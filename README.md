# password-strength-check

A small Go library for estimating password strength without shipping a
dictionary.

Most strength checks fall into one of two camps: length-only rules that
score "aaaaaaaaaa" as strong because it's ten characters, or full
dictionary-based checkers that bundle in tens of thousands of known
passwords. This is the middle ground - an entropy estimate built from the
character classes actually present in the password, with penalties for the
handful of patterns people fall back on when a form tells them to "add a
number and a symbol": repeated characters, keyboard walks, sequential runs,
and a short list of passwords that show up in every breach dump.

It's a library, not a CLI. Standard library only, no dependencies.

## Usage

```go
package main

import (
	"fmt"

	"github.com/dlee31/password-strength-check"
)

func main() {
	result := pwscore.Evaluate("Tr0ub4dor&3")

	fmt.Println(result.Score)    // 0 (very weak) through 4 (very strong)
	fmt.Println(result.Entropy)  // estimated bits of entropy after penalties
	fmt.Println(result.Warnings) // reasons the score was reduced, if any
}
```

```go
pwscore.Evaluate("aaaaaaaaaa")
// Score: 0
// Warnings: ["contains a long run of the same character", "uses only one type of character"]

pwscore.Evaluate("qwertyui")
// Score: 0
// Warnings: ["contains a keyboard walk", "uses only one type of character"]

pwscore.Evaluate("Password1")
// Score: 0
// Warnings: ["contains a common password or word"]
```

## How scoring works

1. Figure out which character classes are present (lowercase, uppercase,
   digit, ASCII symbol, other/unicode) and derive a pool size from that.
2. Estimate raw entropy as `length * log2(pool size)`.
3. Subtract entropy for patterns that make the password more guessable than
   its raw character-class math suggests: long repeated runs, sequential
   runs (`abcd`, `4321`), keyboard walks, and known common passwords.
4. Bucket the result into a score from 0 to 4.

The unicode entropy estimate is intentionally rough - it buckets "some
other script or symbol" into a single pool size rather than modeling each
script's actual alphabet size. Good enough for a strength meter, not a
substitute for actual cryptographic randomness.

## Status

Early. The common-password list and keyboard-walk detection are both
deliberately small right now - see the roadmap for what's planned next.
