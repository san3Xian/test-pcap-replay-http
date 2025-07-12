package analyzer

import "testing"

func TestAnalyze(t *testing.T) {
	results, count, err := Analyze("../../packet1.pcap")
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 request, got %d", count)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].DecodedLen != results[0].ContentLen {
		t.Errorf("decoded length mismatch: %d vs %d", results[0].DecodedLen, results[0].ContentLen)
	}
	if len(results[0].Body) != results[0].ContentLen {
		t.Errorf("body length mismatch: %d vs %d", len(results[0].Body), results[0].ContentLen)
	}
}
