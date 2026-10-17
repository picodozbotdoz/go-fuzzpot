package main

// Contract test (B1-8): the fuzzpot JSONL log-line schema is shared with
// fuzz-sec-intel. contract/log_schema.json and contract/sample_v1.jsonl
// are byte-identical in both repos; fuzz-sec-intel's tests/test_contract.py
// validates the same files. Any change here must land as a coordinated
// pair of commits in both repositories.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// schemaRules mirrors contract/log_schema.json using the stdlib only
// (no new dependencies is a hard project rule).
type schemaRules struct {
	required   []string
	allowed    map[string]bool
	protoEnum  []string
	shaPattern func(string) bool
}

func loadRules(t *testing.T) schemaRules {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("contract", "log_schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required             []string `json:"required"`
		AdditionalProperties bool     `json:"additionalProperties"`
		Properties           map[string]struct {
			Type    string   `json:"type"`
			Enum    []string `json:"enum"`
			Minimum *float64 `json:"minimum"`
			Maximum *float64 `json:"maximum"`
			Pattern string   `json:"pattern"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	allowed := make(map[string]bool)
	for name := range schema.Properties {
		allowed[name] = true
	}
	return schemaRules{
		required:   schema.Required,
		allowed:    allowed,
		protoEnum:  schema.Properties["proto"].Enum,
		shaPattern: func(s string) bool { return len(s) == 64 && isLowerHex(s) },
	}
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validateLine checks one decoded JSON object against the schema rules.
func validateLine(t *testing.T, rules schemaRules, line map[string]interface{}) {
	t.Helper()
	for _, key := range rules.required {
		if _, ok := line[key]; !ok {
			t.Errorf("line missing required field %q: %v", key, line)
		}
	}
	for key := range line {
		if !rules.allowed[key] {
			t.Errorf("line has field %q not in schema properties: %v", key, line)
		}
	}
	if v, ok := line["v"].(float64); !ok || int(v) != 1 {
		t.Errorf("v = %v, want integer 1", line["v"])
	}
	if ts, _ := line["ts"].(string); len(ts) < 20 || !strings.Contains(ts, "T") {
		t.Errorf("ts = %q, want RFC3339-ish timestamp", ts)
	}
	if proto, _ := line["proto"].(string); proto != "tcp" && proto != "udp" {
		t.Errorf("proto = %q, want tcp|udp", proto)
	}
	for _, field := range []string{"src_port", "dst_port", "size"} {
		n, ok := line[field].(float64)
		if !ok || n < 0 || n > 65535 {
			t.Errorf("%s = %v, want int in [0,65535]", field, line[field])
		}
	}
	if dst, _ := line["dst_port"].(float64); dst < 1 {
		t.Errorf("dst_port = %v, want >= 1", line["dst_port"])
	}
	if sha, present := line["payload_sha256"].(string); present && !rules.shaPattern(sha) {
		t.Errorf("payload_sha256 = %q, want 64 lowercase hex chars", sha)
	}
}

func TestContractFixtureIsValidV1(t *testing.T) {
	rules := loadRules(t)
	f, err := os.Open(filepath.Join("contract", "sample_v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var line map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("fixture line is not valid JSON: %v", err)
		}
		validateLine(t, rules, line)
		lines++
	}
	if lines != 2 {
		t.Errorf("fixture has %d lines, want 2 (update both repos' fixtures together)", lines)
	}
}

func TestContractLogEntryConformsToV1(t *testing.T) {
	rules := loadRules(t)

	entry := LogEntry{
		V:             logSchemaVersion,
		Timestamp:     "2026-04-17T21:15:03.000+07:00",
		SourceIP:      "185.220.101.42",
		SourcePort:    54321,
		DestPort:      3389,
		Proto:         "tcp",
		Size:          48,
		Printable:     "Cookie: mstshash=test",
		PayloadSHA256: strings.Repeat("ab", 32),
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var line map[string]interface{}
	if err := json.Unmarshal(raw, &line); err != nil {
		t.Fatal(err)
	}
	validateLine(t, rules, line)

	// Old-format lines (no `v`) must stay field-compatible with v1 minus
	// the version: same required set minus v.
	delete(line, "v")
	for _, key := range rules.required {
		if key == "v" {
			continue
		}
		if _, ok := line[key]; !ok {
			t.Errorf("legacy-compat line missing %q", key)
		}
	}
}

func TestContractSchemaVersionConstant(t *testing.T) {
	if logSchemaVersion != 1 {
		t.Errorf("logSchemaVersion = %d; bumping it requires coordinated schema + fixture updates in BOTH repos", logSchemaVersion)
	}
}
