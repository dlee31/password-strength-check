package pwscore

import (
	"strings"
	"testing"
)

// These cases exist because naive entropy math gets every one of them
// wrong: raw length-times-pool-size math scores "aaaaaaaaaa" and
// "abcdefgh" as stronger than they are, and misses that "Password1" is
// one of the first guesses any cracker tries.
func TestEvaluateAwkwardCases(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		wantScore int
	}{
		{"empty string", "", 0},
		{"single character", "a", 0},
		{"long run of one repeated character", "aaaaaaaaaa", 0},
		{"ascending sequential letters", "abcdefgh", 0},
		{"ascending sequential digits, also a common password", "12345678", 0},
		{"keyboard walk", "qwertyui", 0},
		{"exact common password", "password", 0},
		{"common password with digit appended", "Password1", 0},
		{"common word embedded in a longer password", "myDragon99", 1},
		{"whitespace only", "     ", 0},
		{"long high entropy password", "xQ7!mK9$zP2&vL5#wN8@", 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.password)
			if got.Score != tt.wantScore {
				t.Errorf("Evaluate(%q).Score = %d, want %d (entropy=%.1f, warnings=%v)",
					tt.password, got.Score, tt.wantScore, got.Entropy, got.Warnings)
			}
		})
	}
}

func TestEvaluateEmptyPasswordWarns(t *testing.T) {
	got := Evaluate("")
	if len(got.Warnings) == 0 {
		t.Fatal("Evaluate(\"\") should return a warning explaining why the score is 0")
	}
	if got.Entropy != 0 {
		t.Errorf("Evaluate(\"\").Entropy = %v, want 0", got.Entropy)
	}
}

// Unicode input must never panic and should still produce a usable result,
// even though the per-script entropy estimate is deliberately rough.
func TestEvaluateUnicodeDoesNotPanic(t *testing.T) {
	passwords := []string{
		"пароль123",
		"密码強度測試",
		"emoji🙂🙃🙂🙃password",
		"café-au-lait-42",
	}

	for _, p := range passwords {
		p := p
		t.Run(p, func(t *testing.T) {
			got := Evaluate(p)
			if got.Score < 0 || got.Score > 4 {
				t.Errorf("Evaluate(%q).Score = %d, out of range [0,4]", p, got.Score)
			}
			if got.Entropy < 0 {
				t.Errorf("Evaluate(%q).Entropy = %v, want >= 0", p, got.Entropy)
			}
		})
	}
}

// A password mixing two non-ASCII scripts should get credit for both
// alphabets, not the single flat "other" bump the old pool used for any
// non-ASCII input regardless of how many scripts were actually present.
func TestClassifyPerScriptPool(t *testing.T) {
	cyrillicOnly, _, _, _, _, _ := classify([]rune("привет"))
	mixed, _, _, _, _, _ := classify([]rune("привет日本語"))

	if mixed <= cyrillicOnly {
		t.Errorf("classify pool for Cyrillic+Han (%d) should exceed Cyrillic alone (%d)", mixed, cyrillicOnly)
	}

	lower, _, _, _, _, _ := classify([]rune("привет"))
	upper, _, _, _, _, _ := classify([]rune("ПРИВЕТ"))
	both, _, _, _, _, _ := classify([]rune("Привет"))
	if upper != lower {
		t.Errorf("classify pool for all-uppercase Cyrillic (%d) should equal all-lowercase (%d)", upper, lower)
	}
	if both <= lower {
		t.Errorf("classify pool for mixed-case Cyrillic (%d) should exceed single-case (%d)", both, lower)
	}
}

func TestEvaluateWithWordlist(t *testing.T) {
	extra := []string{"correcthorsebatterystaple", "TrustNo1"}

	// Not in the built-in list, so Evaluate alone won't flag it.
	base := Evaluate("correcthorsebatterystaple99")
	for _, w := range base.Warnings {
		if strings.Contains(w, "common password") {
			t.Fatalf("Evaluate flagged a word that isn't in the built-in list: %v", base.Warnings)
		}
	}

	got := EvaluateWithWordlist("correcthorsebatterystaple99", extra)
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "common password") {
			found = true
		}
	}
	if !found {
		t.Errorf("EvaluateWithWordlist(%q, %v).Warnings = %v, want a common-password warning",
			"correcthorsebatterystaple99", extra, got.Warnings)
	}

	// Matching should be case-insensitive regardless of the case in extra.
	got = EvaluateWithWordlist("mytrustno1word", extra)
	found = false
	for _, w := range got.Warnings {
		if strings.Contains(w, "common password") {
			found = true
		}
	}
	if !found {
		t.Errorf("EvaluateWithWordlist should match extra words case-insensitively, got warnings %v", got.Warnings)
	}
}

func TestLoadWordlist(t *testing.T) {
	input := "# comment\nHunter2\n\n  qwerty12345  \n# another comment\ntrustno1\n"
	words, err := LoadWordlist(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadWordlist returned error: %v", err)
	}
	want := []string{"hunter2", "qwerty12345", "trustno1"}
	if len(words) != len(want) {
		t.Fatalf("LoadWordlist returned %v, want %v", words, want)
	}
	for i, w := range want {
		if words[i] != w {
			t.Errorf("LoadWordlist()[%d] = %q, want %q", i, words[i], w)
		}
	}
}

func TestLongestRepeatRun(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 1},
		{"a", 1},
		{"aabaaa", 3},
		{"abcabc", 1},
	}
	for _, tt := range tests {
		runes := []rune(tt.in)
		if len(runes) == 0 {
			continue // longestRepeatRun assumes at least one rune, same as its caller.
		}
		if got := longestRepeatRun(runes); got != tt.want {
			t.Errorf("longestRepeatRun(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestLongestSequentialRun(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"a", 1},
		{"abcd", 4},
		{"dcba", 4},
		{"az19", 1},
	}
	for _, tt := range tests {
		got := longestSequentialRun([]rune(tt.in))
		if got != tt.want {
			t.Errorf("longestSequentialRun(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
