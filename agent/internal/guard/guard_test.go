package guard

import (
	"errors"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

func TestGuardModesFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := New(proto.Mode("bogus")); err == nil {
		t.Fatal("expected error for unrecognized mode")
	}

	ro, err := New(proto.ModeReadOnly)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ro.CheckMethod(proto.MethodSysInfo); err != nil {
		t.Fatalf("readonly should allow sys.info: %v", err)
	}
	if err := ro.CheckMethod(proto.MethodCmdExec); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("readonly must deny cmd.exec, got: %v", err)
	}
	if err := ro.CheckMethod(proto.MethodSessionOpen); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("readonly must deny session.open, got: %v", err)
	}
	if err := ro.CheckMethod(proto.MethodFSDownload); err != nil {
		t.Fatalf("readonly should allow fs.download: %v", err)
	}
	if err := ro.CheckMethod(proto.MethodFSUpload); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("readonly must deny fs.upload: %v", err)
	}

	if err := ro.CheckMethod("unknown.method"); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("unknown method must fail closed, got: %v", err)
	}

	restricted, err := New(proto.ModeRestricted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := restricted.CheckMethod(proto.MethodCmdExec); err != nil {
		t.Fatalf("restricted should allow cmd.exec method gate: %v", err)
	}
	if err := restricted.CheckMethod(proto.MethodSessionOpen); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("restricted must deny session.open, got: %v", err)
	}
	if err := restricted.CheckMethod(proto.MethodFSUpload); !errors.Is(err, ErrModeDenied) {
		t.Fatalf("restricted must deny fs.upload: %v", err)
	}

}

func TestRestrictedASTAllowedCommands(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"ps aux",
		"df -h",
		"free -m",
		"ls -la /var/log",
		"cat /etc/os-release",
		"tail -n 50 /var/log/messages",
		"grep -i 'error' /var/log/app.log",
		"docker ps -a",
		"kubectl get pods -n default",
		"ip addr show",
		"find /var/log -maxdepth 2 -name '*.log'",
	}

	for _, cmd := range allowed {
		if err := CheckRestrictedCommand(cmd); err != nil {
			t.Errorf("expected command %q to be allowed, got error: %v", cmd, err)
		}
	}
}

func TestRestrictedASTBypassAttemptsRejected(t *testing.T) {
	t.Parallel()

	bypassCases := []struct {
		name string
		cmd  string
	}{
		{name: "semicolon chaining", cmd: "ls; rm -rf /tmp/x"},
		{name: "and chaining", cmd: "ls && id"},
		{name: "or chaining", cmd: "ls || id"},
		{name: "pipe chaining", cmd: "ps aux | grep sshd"},
		{name: "command substitution dollar", cmd: "ls $(id)"},
		{name: "command substitution inside double quotes", cmd: `grep "$(id)" /etc/hosts`},
		{name: "backtick substitution", cmd: "ls `id`"},
		{name: "output redirect", cmd: "cat /etc/hosts > /tmp/out"},
		{name: "append redirect", cmd: "cat /etc/hosts >> /tmp/out"},
		{name: "input redirect", cmd: "cat < /etc/shadow"},
		{name: "process substitution", cmd: "cat <(id)"},
		{name: "newline chaining", cmd: "ls\nrm -rf /tmp/x"},
		{name: "parameter expansion", cmd: "ls $HOME"},
		{name: "subshell", cmd: "(ls)"},
		{name: "background execution", cmd: "ls &"},
		{name: "disallowed binary", cmd: "rm -rf /tmp/x"},
		{name: "disallowed shell", cmd: "sh -c 'ls'"},
		{name: "find -exec", cmd: "find /tmp -exec rm -f {} +"},
		{name: "find -delete", cmd: "find /tmp -delete"},
		{name: "docker destructive subcommand", cmd: "docker rm -f mycontainer"},
		{name: "kubectl destructive subcommand", cmd: "kubectl delete pod web-1"},
		{name: "dmesg clear", cmd: "dmesg -C"},
		{name: "invalid syntax", cmd: "ls 'unterminated"},
		{name: "empty command", cmd: "   "},
	}

	for _, tc := range bypassCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckRestrictedCommand(tc.cmd)
			if !errors.Is(err, ErrPolicyDenied) {
				t.Fatalf("expected ErrPolicyDenied for %q, got: %v", tc.cmd, err)
			}
		})
	}
}
