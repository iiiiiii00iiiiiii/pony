package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pony/scanner/pkg/portscan"
)

func parsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		return portscan.DefaultPorts(), nil
	}

	var ports []int
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range start: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range end: %s", rangeParts[1])
			}
			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range out of bounds: %d-%d", start, end)
			}
			ports = append(ports, portscan.PortRange(start, end)...)
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func main() {
	target := flag.String("target", "", "Target host to scan (IP or hostname)")
	portStr := flag.String("ports", "", "Ports to scan (e.g., 80,443,8080 or 1-1024). Default: common ports")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout per port")
	goroutines := flag.Int("goroutines", 100, "Number of concurrent goroutines")
	openOnly := flag.Bool("open", false, "Show only open ports")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Pony Port Scanner - TCP Connect Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  scanner -target <host> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  scanner -target 192.168.1.1\n")
		fmt.Fprintf(os.Stderr, "  scanner -target example.com -ports 80,443,8080\n")
		fmt.Fprintf(os.Stderr, "  scanner -target 10.0.0.1 -ports 1-1024 -timeout 1s\n")
	}

	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}

	ports, err := parsePorts(*portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Pony Port Scanner ===\n")
	fmt.Printf("Target:     %s\n", *target)
	fmt.Printf("Ports:      %d\n", len(ports))
	fmt.Printf("Timeout:    %s\n", *timeout)
	fmt.Printf("Goroutines: %d\n", *goroutines)
	fmt.Println("========================")
	fmt.Println()

	scanner := portscan.New(portscan.ScanOptions{
		Target:     *target,
		Ports:      ports,
		Timeout:    *timeout,
		Goroutines: *goroutines,
	})

	startTime := time.Now()
	results := scanner.Scan()
	elapsed := time.Since(startTime)

	openCount := 0
	fmt.Printf("%-8s %-12s %s\n", "PORT", "STATE", "SERVICE")
	fmt.Println(strings.Repeat("-", 36))

	for _, r := range results {
		if *openOnly && r.State != "open" {
			continue
		}
		if r.State == "open" {
			openCount++
		}
		service := r.Service
		if service == "" {
			service = "unknown"
		}
		fmt.Printf("%-8d %-12s %s\n", r.Port, r.State, service)
	}

	fmt.Printf("\nScan completed in %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Open ports: %d / %d scanned\n", openCount, len(ports))
}
