package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/revmcp/revmcp/hub/internal/admin"
	"github.com/revmcp/revmcp/hub/internal/channel"
	"github.com/revmcp/revmcp/hub/internal/config"
	"github.com/revmcp/revmcp/proto"
)

const channelsEndpoint = "/admin/channels"

func channelEndpoint(name string) string { return channelsEndpoint + "/" + url.PathEscape(name) }

func channelRequest(configPath, method, endpoint string, payload any) ([]byte, error) {
	if configPath == "" {
		return nil, errors.New("--config is required")
	}
	token := os.Getenv("REVMCP_ADMIN_TOKEN")
	if token == "" {
		return nil, errors.New("REVMCP_ADMIN_TOKEN is required")
	}
	base, err := config.LoadManagementURL(configPath)
	if err != nil {
		return nil, err
	}
	return doAdminJSON(method, base+endpoint, token, payload)
}

func printChannelResponse(configPath, method, endpoint string, payload any) error {
	body, err := channelRequest(configPath, method, endpoint, payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, strings.TrimSpace(string(body)))
	return err
}

func runTokenIssue(args []string) error {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	var configPath, mode string
	var issue admin.IssueChannel
	fs.StringVar(&configPath, "config", "", "Hub management configuration")
	fs.StringVar(&issue.Name, "name", "", "Unique channel name")
	fs.StringVar(&issue.Profile, "profile", "", "Issuance profile defined on the Hub")
	fs.StringVar(&issue.Policy.Target, "allowed-target", "", "Exact target name or glob")
	fs.StringVar(&mode, "mode", "", "Maximum Agent mode")
	fs.DurationVar(&issue.Policy.AgentTTL, "agent-ttl", 0, "Agent credential validity")
	fs.DurationVar(&issue.Policy.MCPTTL, "ttl", 0, "MCP Bearer validity")
	fs.Func("scope", "MCP scope (repeatable)", func(scope string) error {
		issue.Policy.MCPScopes = append(issue.Policy.MCPScopes, scope)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !channel.ValidName(issue.Name) {
		return errors.New("valid --name is required")
	}
	var invalidDuration bool
	fs.Visit(func(arg *flag.Flag) {
		if (arg.Name == "ttl" && issue.Policy.MCPTTL < time.Second) ||
			(arg.Name == "agent-ttl" && issue.Policy.AgentTTL < time.Second) {
			invalidDuration = true
		}
	})
	if invalidDuration {
		return errors.New("credential validity must be at least one second")
	}
	issue.Policy.Mode = proto.Mode(mode)
	return printChannelResponse(configPath, http.MethodPost, channelsEndpoint, issue)
}

func runTokenList(args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	var configPath, name string
	var details, showSecrets bool
	fs.StringVar(&configPath, "config", "", "Hub management configuration")
	fs.StringVar(&name, "channel", "", "Limit to this channel")
	fs.BoolVar(&details, "details", false, "List active credential metadata")
	fs.BoolVar(&showSecrets, "show-secrets", false, "Reveal active credential values for the selected channel")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (name != "" || showSecrets) && !channel.ValidName(name) {
		return errors.New("provide a valid --channel to select a channel or reveal credentials")
	}
	endpoint := channelsEndpoint
	if name != "" {
		endpoint = channelEndpoint(name)
	}
	if showSecrets {
		return printChannelResponse(configPath, http.MethodPost, endpoint+"/reveal", nil)
	}

	body, err := channelRequest(configPath, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if name != "" {
		var item channel.Detail
		if err := json.Unmarshal(body, &item); err != nil {
			return err
		}
		return printChannelList([]channel.Detail{item}, details)
	}
	var channels []channel.Detail
	if err := json.Unmarshal(body, &channels); err != nil {
		return err
	}
	return printChannelList(channels, details)
}

func printChannelList(channels []channel.Detail, details bool) error {
	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if details {
		_, _ = fmt.Fprintln(table, "CHANNEL\tKIND\tTARGET RULE\tACCESS / SCOPES\tEXPIRES AT")
		for _, item := range channels {
			if item.AgentActive {
				_, _ = fmt.Fprintf(table, "%s\tagent\t%s\t%s\t%s\n", item.Name, item.Target, item.Mode,
					item.AgentExpires.Local().Format("2006-01-02 15:04 MST"))
			}
			if item.MCPActive {
				_, _ = fmt.Fprintf(table, "%s\tmcp\t%s\t%s\t%s\n", item.Name, item.Target,
					strings.Join(item.MCPScopes, ","), item.MCPExpires.Local().Format("2006-01-02 15:04 MST"))
			}
		}
		return table.Flush()
	}
	_, _ = fmt.Fprintln(table, "CHANNEL\tTARGET RULE\tACCESS\tAGENT TOKEN EXPIRES\tCONNECTED TARGETS")
	for _, item := range channels {
		targets := strings.Join(item.Targets, ",")
		if targets == "" {
			targets = "—"
		}
		expiry := item.AgentExpires.Local().Format("2006-01-02 15:04 MST")
		if !item.AgentActive {
			expiry += " (inactive)"
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", item.Name, item.Target, item.Mode, expiry, targets)
	}
	return table.Flush()
}

func changeChannelCredential(configPath, name, kind, operation string) error {
	if !channel.ValidName(name) || !slices.Contains([]string{channel.Agent, channel.MCP}, kind) {
		return errors.New("valid --channel and --kind agent|mcp are required")
	}
	return printChannelResponse(configPath, http.MethodPost, channelEndpoint(name)+"/"+operation+"/"+kind, nil)
}

func runTokenRotate(args []string) error {
	fs := flag.NewFlagSet("token rotate", flag.ContinueOnError)
	var configPath, name, kind string
	fs.StringVar(&configPath, "config", "", "Hub management configuration")
	fs.StringVar(&name, "channel", "", "Channel name")
	fs.StringVar(&kind, "kind", "", "Credential kind (agent or mcp)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return changeChannelCredential(configPath, name, kind, "rotate")
}

func runChannel(args []string) error {
	if len(args) == 0 || args[0] != "delete" {
		return errors.New("expected subcommand: channel delete")
	}
	fs := flag.NewFlagSet("channel delete", flag.ContinueOnError)
	var configPath, name string
	fs.StringVar(&configPath, "config", "", "Hub management configuration")
	fs.StringVar(&name, "name", "", "Channel name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if !channel.ValidName(name) {
		return errors.New("valid --name is required")
	}
	return printChannelResponse(configPath, http.MethodDelete, channelEndpoint(name), nil)
}
