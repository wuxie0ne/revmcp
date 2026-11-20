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
	if len(info.Mounts) == 0 {
		t.Fatalf("expected non-empty Mounts from /proc/mounts, got empty")
	}
	foundRoot := false
	for _, m := range info.Mounts {
		if m.MountPoint == "/" && m.TotalBytes > 0 {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Fatalf("expected root mount '/' with TotalBytes > 0, got %+v", info.Mounts)
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
