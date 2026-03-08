package portscan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result represents the scan result for a single port.
type Result struct {
	Port    int
	State   string // "open", "closed", "filtered"
	Service string
}

// ScanOptions configures the port scan behavior.
type ScanOptions struct {
	Target     string
	Ports      []int
	Timeout    time.Duration
	Goroutines int
}

// Common service names mapped by port number.
var wellKnownPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	27017: "mongodb",
}

// ServiceName returns the well-known service name for a port, or empty string.
func ServiceName(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return ""
}

// DefaultPorts returns the list of commonly scanned ports.
func DefaultPorts() []int {
	ports := make([]int, 0, len(wellKnownPorts))
	for p := range wellKnownPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// PortRange generates a slice of ports from start to end (inclusive).
func PortRange(start, end int) []int {
	if start > end {
		start, end = end, start
	}
	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports
}

// Scanner performs TCP connect scans.
type Scanner struct {
	opts ScanOptions
}

// New creates a new Scanner with the given options.
func New(opts ScanOptions) *Scanner {
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Goroutines == 0 {
		opts.Goroutines = 100
	}
	return &Scanner{opts: opts}
}

// scanPort performs a TCP connect scan on a single port.
func (s *Scanner) scanPort(port int) Result {
	addr := fmt.Sprintf("%s:%d", s.opts.Target, port)
	conn, err := net.DialTimeout("tcp", addr, s.opts.Timeout)
	if err != nil {
		return Result{Port: port, State: "closed", Service: ServiceName(port)}
	}
	conn.Close()
	return Result{Port: port, State: "open", Service: ServiceName(port)}
}

// Scan runs the port scan and returns results for all open ports.
func (s *Scanner) Scan() []Result {
	portCh := make(chan int, s.opts.Goroutines)
	resultCh := make(chan Result, len(s.opts.Ports))

	var wg sync.WaitGroup

	// Launch worker goroutines
	for i := 0; i < s.opts.Goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				resultCh <- s.scanPort(port)
			}
		}()
	}

	// Feed ports to workers
	go func() {
		for _, port := range s.opts.Ports {
			portCh <- port
		}
		close(portCh)
	}()

	// Wait for all workers to finish, then close results
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []Result
	for r := range resultCh {
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}
