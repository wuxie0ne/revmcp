package guard

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/revmcp/revmcp/proto"
	"mvdan.cc/sh/v3/syntax"
)

var (
	// ErrModeDenied indicates the requested RPC method exceeds the agent's startup mode.
	ErrModeDenied = errors.New("guard: operation denied by agent mode")
	// ErrPolicyDenied indicates a command was rejected by the restricted AST allowlist.
	ErrPolicyDenied = errors.New("guard: command denied by restricted policy")
)

// Guard enforces the agent-side hard permission boundary (--mode) and AST command checks.
type Guard struct {
	mode proto.Mode
}

// New creates a Guard for the given mode, failing closed if the mode is unrecognized.
func New(mode proto.Mode) (*Guard, error) {
	parsed, err := proto.ParseMode(string(mode))
	if err != nil {
		return nil, err
	}
	return &Guard{mode: parsed}, nil
}

// Mode returns the active agent mode.
func (g *Guard) Mode() proto.Mode {
	return g.mode
}

// CheckMethod verifies whether the configured agent mode permits the given RPC method.
func (g *Guard) CheckMethod(method string) error {
	switch method {
	case proto.MethodAgentRegister, proto.MethodAgentPing, proto.MethodAgentShutdown:
		return nil
	case proto.MethodSysInfo, proto.MethodProcList, proto.MethodNetSockets, proto.MethodFSRead, proto.MethodFSGrep, proto.MethodFSDownload:
		if !g.mode.Allows(proto.ModeReadOnly) {
			return fmt.Errorf("%w: %s requires %s", ErrModeDenied, method, proto.ModeReadOnly)
		}
		return nil
	case proto.MethodCmdExec:
		if !g.mode.Allows(proto.ModeRestricted) {
			return fmt.Errorf("%w: %s requires %s", ErrModeDenied, method, proto.ModeRestricted)
		}
		return nil
	case proto.MethodFSUpload, proto.MethodSessionOpen, proto.MethodSessionExec, proto.MethodSessionClose:
		if !g.mode.Allows(proto.ModeFull) {
			return fmt.Errorf("%w: %s requires %s", ErrModeDenied, method, proto.ModeFull)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown method %q", ErrModeDenied, method)
	}
}

// CheckCommand validates a command against the agent's mode.
// In readonly mode all commands are denied; in restricted mode the command must pass
// strict shell AST parsing and allowlist validation; in full mode non-empty commands pass.
func (g *Guard) CheckCommand(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: empty command", ErrPolicyDenied)
	}
	switch g.mode {
	case proto.ModeReadOnly:
		return fmt.Errorf("%w: command execution disabled in readonly mode", ErrModeDenied)
	case proto.ModeRestricted:
		return CheckRestrictedCommand(raw)
	case proto.ModeFull:
		return nil
	default:
		return fmt.Errorf("%w: invalid mode %q", ErrModeDenied, g.mode)
	}
}

var allowedCommands = map[string]bool{
	"cat":        true,
	"date":       true,
	"df":         true,
	"dmesg":      true,
	"docker":     true,
	"du":         true,
	"env":        true,
	"find":       true,
	"free":       true,
	"grep":       true,
	"head":       true,
	"hostname":   true,
	"id":         true,
	"ip":         true,
	"journalctl": true,
	"kubectl":    true,
	"ls":         true,
	"netstat":    true,
	"printenv":   true,
	"ps":         true,
	"ss":         true,
	"stat":       true,
	"tail":       true,
	"uname":      true,
	"uptime":     true,
	"wc":         true,
	"whoami":     true,
}

var allowedDockerSubcommands = map[string]bool{
	"images":  true,
	"info":    true,
	"inspect": true,
	"logs":    true,
	"ps":      true,
	"stats":   true,
	"version": true,
}

var allowedKubectlSubcommands = map[string]bool{
	"describe": true,
	"get":      true,
	"logs":     true,
	"top":      true,
	"version":  true,
}

var allowedIPSubcommands = map[string]bool{
	"a":     true,
	"addr":  true,
	"l":     true,
	"link":  true,
	"n":     true,
	"neigh": true,
	"r":     true,
	"route": true,
}

// CheckRestrictedCommand parses raw using mvdan.cc/sh/v3/syntax and enforces a strict
// single-command read-only allowlist. Any parse failure, chaining, redirection, command
// substitution, variable expansion, or disallowed command/flag fails closed.
func CheckRestrictedCommand(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: empty command", ErrPolicyDenied)
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(trimmed), "cmd")
	if err != nil {
		return fmt.Errorf("%w: shell parse failed: %v", ErrPolicyDenied, err)
	}

	if len(file.Stmts) != 1 {
		return fmt.Errorf("%w: multiple statements are not allowed in restricted mode", ErrPolicyDenied)
	}

	stmt := file.Stmts[0]
	if stmt.Background || stmt.Coprocess || stmt.Negated || len(stmt.Redirs) > 0 {
		return fmt.Errorf("%w: redirections, backgrounding, or modifiers are not allowed", ErrPolicyDenied)
	}

	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return fmt.Errorf("%w: only simple commands are allowed (got %T)", ErrPolicyDenied, stmt.Cmd)
	}
	if len(call.Assigns) > 0 || len(call.Args) == 0 {
		return fmt.Errorf("%w: variable assignments or empty call expressions are not allowed", ErrPolicyDenied)
	}

	var walkErr error
	syntax.Walk(file, func(node syntax.Node) bool {
		if walkErr != nil || node == nil {
			return false
		}
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ParamExp,
			*syntax.BinaryCmd, *syntax.Redirect, *syntax.Subshell, *syntax.Block,
			*syntax.FuncDecl, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause,
			*syntax.CaseClause, *syntax.CoprocClause, *syntax.TestClause, *syntax.DeclClause,
			*syntax.TimeClause, *syntax.ExtGlob:
			walkErr = fmt.Errorf("%w: forbidden shell syntax %T", ErrPolicyDenied, node)
			return false
		}
		return true
	})
	if walkErr != nil {
		return walkErr
	}

	args := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		lit, err := wordToLiteral(w)
		if err != nil {
			return err
		}
		args = append(args, lit)
	}

	cmdName := path.Base(args[0])
	if !allowedCommands[cmdName] {
		return fmt.Errorf("%w: command %q is not in restricted allowlist", ErrPolicyDenied, cmdName)
	}

	return checkCommandArgs(cmdName, args[1:])
}

func wordToLiteral(w *syntax.Word) (string, error) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", fmt.Errorf("%w: dynamic expansion %T inside quotes is not allowed", ErrPolicyDenied, dp)
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", fmt.Errorf("%w: unsupported word part %T", ErrPolicyDenied, part)
		}
	}
	return b.String(), nil
}

func checkCommandArgs(cmd string, args []string) error {
	switch cmd {
	case "find":
		for _, a := range args {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls":
				return fmt.Errorf("%w: dangerous find flag %q", ErrPolicyDenied, a)
			}
		}
	case "dmesg":
		for _, a := range args {
			if a == "-c" || a == "-C" || a == "--clear" || a == "--read-clear" {
				return fmt.Errorf("%w: destructive dmesg flag %q", ErrPolicyDenied, a)
			}
		}
	case "docker":
		sub := firstNonFlagArg(args)
		if !allowedDockerSubcommands[sub] {
			return fmt.Errorf("%w: docker subcommand %q is not allowed", ErrPolicyDenied, sub)
		}
	case "kubectl":
		sub := firstNonFlagArg(args)
		if !allowedKubectlSubcommands[sub] {
			return fmt.Errorf("%w: kubectl subcommand %q is not allowed", ErrPolicyDenied, sub)
		}
	case "ip":
		sub := firstNonFlagArg(args)
		if !allowedIPSubcommands[sub] {
			return fmt.Errorf("%w: ip subcommand %q is not allowed", ErrPolicyDenied, sub)
		}
	}
	return nil
}

func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}
