// Package pwscore estimates password strength without a bundled dictionary.
//
// Length-only checks let "aaaaaaaaaa" pass as "strong" and full dictionary
// based checkers (zxcvbn and friends) drag in tens of thousands of words.
// This is the middle ground: an entropy estimate from the character classes
// actually used, with penalties for the patterns people fall back to when
// they're told to "add a number and a symbol" - repeated characters,
// keyboard walks, sequential runs, and a short list of passwords that show
// up on every breach dump.
package pwscore

import (
	"bufio"
	"io"
	"math"
	"strings"
	"unicode"
)

// Result is the outcome of scoring a single password.
type Result struct {
	// Score is a bucket from 0 (very weak) to 4 (very strong).
	Score int
	// Entropy is the estimated strength in bits after pattern penalties.
	Entropy float64
	// Warnings explains what pulled the score down, if anything.
	Warnings []string
}

// commonPasswords is intentionally short. It exists to catch the handful of
// words and strings that appear in nearly every breach corpus, not to
// replace a real dictionary check.
var commonPasswords = []string{
	"password", "password1", "123456", "12345678", "1234567890",
	"qwerty", "letmein", "admin", "welcome", "iloveyou",
	"monkey", "dragon", "football", "abc123", "111111", "123123",
}

// keyboardRuns are rows (and partial rows) on a standard QWERTY layout.
// Substrings of these catch keyboard walks like "qwertyui" or "asdfgh".
var keyboardRuns = []string{
	"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
}

// LoadWordlist reads newline-separated passwords from r for use as extra
// common-password matches alongside the built-in list. Blank lines and
// lines starting with "#" are skipped so a wordlist file can carry
// comments. Entries are lowercased since matching is case-insensitive.
func LoadWordlist(r io.Reader) ([]string, error) {
	var words []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return words, nil
}

// Evaluate scores a password and explains the score.
func Evaluate(password string) Result {
	return evaluate(password, nil)
}

// EvaluateWithWordlist scores a password the same way Evaluate does, but
// also matches it against extra common passwords (typically loaded with
// LoadWordlist) in addition to the small built-in list. Use this when
// you have a real breach-corpus wordlist and want it checked without
// replacing the built-in patterns and penalties.
func EvaluateWithWordlist(password string, extra []string) Result {
	return evaluate(password, extra)
}

func evaluate(password string, extra []string) Result {
	runes := []rune(password)
	if len(runes) == 0 {
		return Result{Warnings: []string{"password is empty"}}
	}

	pool, hasLower, hasUpper, hasDigit, hasSymbol, hasOther := classify(runes)
	bitsPerChar := log2(float64(pool))
	entropy := float64(len(runes)) * bitsPerChar

	var warnings []string

	if run := longestRepeatRun(runes); run >= 4 {
		entropy -= float64(run-1) * bitsPerChar
		warnings = append(warnings, "contains a long run of the same character")
	}

	if run := longestSequentialRun(runes); run >= 4 {
		entropy -= float64(run-1) * bitsPerChar
		warnings = append(warnings, "contains a sequential run of characters")
	}

	lower := strings.ToLower(string(runes))

	if containsKeyboardPattern(lower) {
		entropy -= 20
		warnings = append(warnings, "contains a keyboard walk")
	}

	if containsCommonPassword(lower, extra) {
		entropy -= 30
		warnings = append(warnings, "contains a common password or word")
	}

	classCount := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol, hasOther} {
		if present {
			classCount++
		}
	}
	if classCount <= 1 {
		warnings = append(warnings, "uses only one type of character")
	}

	if entropy < 0 {
		entropy = 0
	}

	return Result{
		Score:    scoreFromEntropy(entropy),
		Entropy:  entropy,
		Warnings: warnings,
	}
}

// scriptClass is a rough distinct-symbol estimate for one non-ASCII Unicode
// script, used to size the entropy pool when a password draws on it. These
// are conservative round numbers for the letters (and, for Han/Hangul, the
// characters or syllables) actually in common use - not the full size of
// the underlying Unicode block, which would overstate the entropy of a
// password made from a handful of everyday characters. lowerPool is added
// whenever the script is present at all; upperPool is added on top of that
// for scripts that distinguish case (Cyrillic, Greek) when an uppercase
// letter also appears. It stays 0 for scripts without case (Hebrew, Arabic,
// Devanagari, Thai, Han, Hangul, Hiragana, Katakana).
type scriptClass struct {
	name      string
	table     *unicode.RangeTable
	lowerPool int
	upperPool int
}

var otherScripts = []scriptClass{
	{"Cyrillic", unicode.Cyrillic, 33, 33},
	{"Greek", unicode.Greek, 24, 24},
	{"Hebrew", unicode.Hebrew, 27, 0},
	{"Arabic", unicode.Arabic, 36, 0},
	{"Devanagari", unicode.Devanagari, 128, 0},
	{"Thai", unicode.Thai, 70, 0},
	{"Hangul", unicode.Hangul, 2350, 0},
	{"Han", unicode.Han, 3500, 0},
	{"Hiragana", unicode.Hiragana, 86, 0},
	{"Katakana", unicode.Katakana, 90, 0},
}

// classify walks the password once and reports which character classes are
// present, along with the resulting pool size used for the entropy estimate.
// ASCII characters are bucketed the way they always were; anything outside
// ASCII is matched against otherScripts so a password mixing, say, Cyrillic
// and Han gets credit for both alphabets instead of one flat "other" bump.
func classify(runes []rune) (pool int, hasLower, hasUpper, hasDigit, hasSymbol, hasOther bool) {
	seenLower := make([]bool, len(otherScripts))
	seenUpper := make([]bool, len(otherScripts))
	otherFallback := false

	for _, r := range runes {
		if r <= unicode.MaxASCII {
			switch {
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPrint(r):
				hasSymbol = true
			default:
				hasOther = true
				otherFallback = true
			}
			continue
		}

		matched := false
		for i, s := range otherScripts {
			if !unicode.Is(s.table, r) {
				continue
			}
			matched = true
			hasOther = true
			if s.upperPool > 0 && unicode.IsUpper(r) {
				seenUpper[i] = true
			} else {
				seenLower[i] = true
			}
			break
		}
		if !matched {
			// Some script or symbol block not in otherScripts (emoji, rare
			// scripts, etc). Give it the same rough floor the old flat
			// pool used for all non-ASCII input.
			hasOther = true
			otherFallback = true
		}
	}

	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 33
	}
	for i, s := range otherScripts {
		if seenLower[i] {
			pool += s.lowerPool
		}
		if seenUpper[i] {
			pool += s.upperPool
		}
	}
	if otherFallback {
		pool += 100
	}
	return pool, hasLower, hasUpper, hasDigit, hasSymbol, hasOther
}

// longestRepeatRun returns the length of the longest run of one repeated
// rune, e.g. 5 for "aaaaa".
func longestRepeatRun(runes []rune) int {
	longest, current := 1, 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 1
		}
	}
	return longest
}

// longestSequentialRun returns the length of the longest run of
// consecutive-by-code-point runes, ascending or descending, e.g. 5 for
// "abcde" or "54321".
func longestSequentialRun(runes []rune) int {
	longest, current := 1, 1
	for i := 1; i < len(runes); i++ {
		delta := runes[i] - runes[i-1]
		if delta == 1 || delta == -1 {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 1
		}
	}
	return longest
}

func containsKeyboardPattern(lower string) bool {
	const window = 4
	for _, row := range keyboardRuns {
		for i := 0; i+window <= len(row); i++ {
			if strings.Contains(lower, row[i:i+window]) {
				return true
			}
		}
	}
	return false
}

func containsCommonPassword(lower string, extra []string) bool {
	for _, p := range commonPasswords {
		if strings.Contains(lower, p) {
			return true
		}
	}
	for _, p := range extra {
		if p == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log2(x)
}

func scoreFromEntropy(bits float64) int {
	switch {
	case bits < 28:
		return 0
	case bits < 36:
		return 1
	case bits < 60:
		return 2
	case bits < 80:
		return 3
	default:
		return 4
	}
}
