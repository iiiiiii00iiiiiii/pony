package portscan

import (
	"testing"
)

func TestPortRange(t *testing.T) {
	ports := PortRange(80, 85)
	expected := []int{80, 81, 82, 83, 84, 85}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestPortRangeSwapped(t *testing.T) {
	ports := PortRange(85, 80)
	if len(ports) != 6 {
		t.Fatalf("expected 6 ports, got %d", len(ports))
	}
	if ports[0] != 80 || ports[5] != 85 {
		t.Errorf("expected range 80-85, got %d-%d", ports[0], ports[5])
	}
}

func TestDefaultPorts(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) == 0 {
		t.Fatal("DefaultPorts returned empty list")
	}
	// Verify sorted
	for i := 1; i < len(ports); i++ {
		if ports[i] <= ports[i-1] {
			t.Errorf("ports not sorted: %d <= %d", ports[i], ports[i-1])
		}
	}
}

func TestServiceName(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{80, "http"},
		{443, "https"},
		{22, "ssh"},
		{12345, ""},
	}
	for _, tt := range tests {
		got := ServiceName(tt.port)
		if got != tt.expected {
			t.Errorf("ServiceName(%d): expected %q, got %q", tt.port, tt.expected, got)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	s := New(ScanOptions{Target: "localhost", Ports: []int{80}})
	if s.opts.Timeout == 0 {
		t.Error("expected default timeout to be set")
	}
	if s.opts.Goroutines == 0 {
		t.Error("expected default goroutines to be set")
	}
}
