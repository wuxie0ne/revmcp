module github.com/revmcp/revmcp/agent

go 1.23

require (
	github.com/coder/websocket v1.8.15
	github.com/hashicorp/yamux v0.1.2
	github.com/revmcp/revmcp/proto v0.0.0
	mvdan.cc/sh/v3 v3.11.0
)

replace github.com/revmcp/revmcp/proto => ../proto
