package sysinfo

import (
	"os"
	"testing"

	"github.com/revmcp/revmcp/proto"
)

func TestCollectSysInfoAndProcesses(t *testing.T) {
	t.Parallel()

	info, err := CollectSysInfo()
	if err != nil {
		t.Fatalf("CollectSysInfo failed: %v", err)
	}
	if info.CPUCores <= 0 || info.Arch == "" {
		t.Fatalf("unexpected SysInfoResult: %+v", info)
	}

	procs, err := ListProcesses(proto.ProcListRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListProcesses failed: %v", err)
	}
	if procs.Total == 0 || len(procs.Processes) == 0 {
		t.Fatalf("expected at least one process from /proc, got %+v", procs)
	}

	if _, err := os.Stat("/proc/net/tcp"); err == nil {
		if _, err := ListSockets(); err != nil {
			t.Fatalf("ListSockets failed: %v", err)
		}
	}
}
