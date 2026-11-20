package sysinfo

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/revmcp/revmcp/proto"
)

const defaultProcLimit = 50

// CollectSysInfo collects host/container system info directly from /proc without shelling out.
func CollectSysInfo() (*proto.SysInfoResult, error) {
	hostname, _ := os.Hostname()
	res := &proto.SysInfoResult{
		Hostname:    hostname,
		Kernel:      readKernelVersion(),
		Arch:        runtime.GOARCH,
		InContainer: detectContainer(),
		CPUCores:    runtime.NumCPU(),
	}

	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			res.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		for i := 0; i < 3 && i < len(fields); i++ {
			res.LoadAvg[i], _ = strconv.ParseFloat(fields[i], 64)
		}
	}

	res.MemTotalBytes, res.MemAvailBytes = readMemInfo()
	res.Mounts = readMounts()
	return res, nil
}

// ListProcesses enumerates processes directly from /proc/[pid] without shelling out to ps.
func ListProcesses(req proto.ProcListRequest) (*proto.ProcListResult, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = defaultProcLimit
	}
	if limit > 500 {
		limit = 500
	}
	filterLower := strings.ToLower(strings.TrimSpace(req.Filter))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("sysinfo: read /proc: %w", err)
	}

	var procs []proto.ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, ok := readProcess(pid)
		if !ok {
			continue
		}
		if filterLower != "" {
			if !strings.Contains(strings.ToLower(p.Name), filterLower) &&
				!strings.Contains(strings.ToLower(p.Cmdline), filterLower) {
				continue
			}
		}
		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool {
		if procs[i].RSSBytes != procs[j].RSSBytes {
			return procs[i].RSSBytes > procs[j].RSSBytes
		}
		return procs[i].PID < procs[j].PID
	})

	total := len(procs)
	truncated := false
	if len(procs) > limit {
		procs = procs[:limit]
		truncated = true
	}

	return &proto.ProcListResult{
		Total:     total,
		Truncated: truncated,
		Processes: procs,
	}, nil
}

// ListSockets parses /proc/net/{tcp,tcp6,udp,udp6} directly without shelling out to ss/netstat.
func ListSockets() (*proto.NetSocketsResult, error) {
	res := &proto.NetSocketsResult{
		StateCounts: make(map[string]int),
	}

	files := []struct {
		proto string
		path  string
		ipv6  bool
	}{
		{"tcp", "/proc/net/tcp", false},
		{"tcp6", "/proc/net/tcp6", true},
		{"udp", "/proc/net/udp", false},
		{"udp6", "/proc/net/udp6", true},
	}

	for _, f := range files {
		sockets, err := parseProcNetFile(f.path, f.proto, f.ipv6)
		if err != nil {
			continue
		}
		for _, s := range sockets {
			res.StateCounts[s.State]++
			if s.State == "LISTEN" || (strings.HasPrefix(s.Proto, "udp") && s.LocalPort > 0) {
				res.Listening = append(res.Listening, s)
			}
		}
	}

	return res, nil
}

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func detectContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") ||
		strings.Contains(content, "kubepods") ||
		strings.Contains(content, "containerd")
}

func readMemInfo() (totalBytes, availBytes uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		valKB, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalBytes = valKB * 1024
		case "MemAvailable:":
			availBytes = valKB * 1024
		}
	}
	return totalBytes, availBytes
}

var ignoredFSTypes = map[string]bool{
	"autofs":      true,
	"binfmt_misc": true,
	"bpf":         true,
	"cgroup":      true,
	"cgroup2":     true,
	"configfs":    true,
	"debugfs":     true,
	"devpts":      true,
	"devtmpfs":    true,
	"fusectl":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"nsfs":        true,
	"proc":        true,
	"pstore":      true,
	"rpc_pipefs":  true,
	"securityfs":  true,
	"sysfs":       true,
	"tracefs":     true,
}

func readMounts() []proto.MountInfo {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	return parseMounts(f, statFS)
}

func statFS(mountPoint string) (totalBytes, freeBytes uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &st); err != nil {
		return 0, 0, false
	}
	if st.Bsize <= 0 {
		return 0, 0, false
	}
	bsize := uint64(st.Bsize)
	return st.Blocks * bsize, st.Bavail * bsize, true
}

func parseMounts(r *os.File, statFn func(string) (uint64, uint64, bool)) []proto.MountInfo {
	seen := make(map[string]bool)
	var mounts []proto.MountInfo

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mountPoint := unescapeMountPath(fields[1])
		fsType := fields[2]
		if ignoredFSTypes[fsType] || seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true

		total, free, ok := statFn(mountPoint)
		if !ok || total == 0 {
			continue
		}
		mounts = append(mounts, proto.MountInfo{
			MountPoint: mountPoint,
			FSType:     fsType,
			TotalBytes: total,
			FreeBytes:  free,
		})
	}
	sort.Slice(mounts, func(i, j int) bool {
		return mounts[i].MountPoint < mounts[j].MountPoint
	})
	return mounts
}

func unescapeMountPath(s string) string {
	r := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return r.Replace(s)
}

func readProcess(pid int) (proto.ProcessInfo, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	statusData, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return proto.ProcessInfo{}, false
	}

	p := proto.ProcessInfo{PID: pid}
	scanner := bufio.NewScanner(bytes.NewReader(statusData))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			p.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "State:"):
			fields := strings.Fields(strings.TrimPrefix(line, "State:"))
			if len(fields) > 0 {
				p.State = fields[0]
			}
		case strings.HasPrefix(line, "PPid:"):
			p.PPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				p.UID, _ = strconv.Atoi(fields[0])
			}
		case strings.HasPrefix(line, "VmRSS:"):
			fields := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
			if len(fields) > 0 {
				if kb, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					p.RSSBytes = kb * 1024
				}
			}
		}
	}

	if rawCmd, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil && len(rawCmd) > 0 {
		parts := bytes.Split(bytes.TrimRight(rawCmd, "\x00"), []byte{0})
		cleaned := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) > 0 {
				cleaned = append(cleaned, string(part))
			}
		}
		p.Cmdline = strings.Join(cleaned, " ")
	}
	if p.Cmdline == "" {
		p.Cmdline = "[" + p.Name + "]"
	}
	return p, true
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func parseProcNetFile(path, protoName string, ipv6 bool) ([]proto.SocketInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var result []proto.SocketInfo
	scanner := bufio.NewScanner(f)
	// Skip header line.
	if !scanner.Scan() {
		return result, nil
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, err := parseHexAddrPort(fields[1], ipv6)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddrPort(fields[2], ipv6)
		if err != nil {
			continue
		}
		state := tcpStates[strings.ToUpper(fields[3])]
		if state == "" {
			state = fields[3]
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		result = append(result, proto.SocketInfo{
			Proto:      protoName,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			Inode:      inode,
		})
	}
	return result, nil
}

func parseHexAddrPort(raw string, ipv6 bool) (string, uint16, error) {
	addrHex, portHex, ok := strings.Cut(raw, ":")
	if !ok {
		return "", 0, fmt.Errorf("invalid addr:port %q", raw)
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, err
	}
	b, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", 0, err
	}

	if !ipv6 {
		if len(b) != 4 {
			return "", 0, fmt.Errorf("unexpected ipv4 length %d", len(b))
		}
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return ip.String(), uint16(port64), nil
	}

	if len(b) != 16 {
		return "", 0, fmt.Errorf("unexpected ipv6 length %d", len(b))
	}
	ip := make(net.IP, 16)
	for i := 0; i < 16; i += 4 {
		ip[i] = b[i+3]
		ip[i+1] = b[i+2]
		ip[i+2] = b[i+1]
		ip[i+3] = b[i]
	}
	return ip.String(), uint16(port64), nil
}
