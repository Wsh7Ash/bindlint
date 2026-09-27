package zone

import (
	"strings"
	"testing"
)

func TestLexStripsCommentsAndBlanks(t *testing.T) {
	src := "; leading comment\n\n  ; indented comment\nexample.com. 3600 IN A 192.0.2.1 ; trailing comment\n"
	entries, err := Lex("t.zone", src)
	if err != nil {
		t.Fatalf("Lex: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Line != 4 {
		t.Errorf("Line = %d, want 4", entries[0].Line)
	}
	if entries[0].Text != "example.com. 3600 IN A 192.0.2.1" {
		t.Errorf("Text = %q", entries[0].Text)
	}
	if entries[0].LeadingSpace {
		t.Error("LeadingSpace = true, want false")
	}
}

func TestLexDetectsLeadingSpace(t *testing.T) {
	src := "www IN A 192.0.2.1\n\tIN A 192.0.2.2\n IN A 192.0.2.3\n"
	entries, err := Lex("t.zone", src)
	if err != nil {
		t.Fatalf("Lex: %v", err)
	}
	want := []bool{false, true, true}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, w := range want {
		if entries[i].LeadingSpace != w {
			t.Errorf("entry %d LeadingSpace = %v, want %v", i, entries[i].LeadingSpace, w)
		}
	}
}

func TestLexParenContinuation(t *testing.T) {
	src := "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. (\n 2026092701 ; serial\n 1h 15m 1w 5m )\nnext IN A 192.0.2.1\n"
	entries, err := Lex("t.zone", src)
	if err != nil {
		t.Fatalf("Lex: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Line != 1 {
		t.Errorf("entry 0 Line = %d, want 1", entries[0].Line)
	}
	if strings.Contains(entries[0].Text, "(") || strings.Contains(entries[0].Text, ")") {
		t.Errorf("parentheses not stripped: %q", entries[0].Text)
	}
	if !strings.Contains(entries[0].Text, "2026092701 1h 15m 1w 5m") {
		t.Errorf("continuation not joined: %q", entries[0].Text)
	}
	if entries[1].Text != "next IN A 192.0.2.1" {
		t.Errorf("entry 1 Text = %q", entries[1].Text)
	}
}

func TestLexPreservesQuotedSemicolon(t *testing.T) {
	src := `example.com. IN TXT "hello ; world" ; real comment` + "\n"
	entries, err := Lex("t.zone", src)
	if err != nil {
		t.Fatalf("Lex: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Text != `example.com. IN TXT "hello ; world"` {
		t.Errorf("Text = %q", entries[0].Text)
	}
}

func TestLexErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		msg  string
	}{
		{"unterminated quote", "www IN TXT \"abc\n", "unterminated quoted string"},
		{"open paren", "www IN A (\n", "unbalanced opening parenthesis"},
		{"close paren", "www IN A 192.0.2.1 )\n", "unbalanced closing parenthesis"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Lex("t.zone", tc.src)
			if err == nil {
				t.Fatal("expected error")
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type %T, want *ParseError", err)
			}
			if !strings.Contains(pe.Msg, tc.msg) {
				t.Errorf("Msg = %q, want it to contain %q", pe.Msg, tc.msg)
			}
		})
	}
}

func TestTokenize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "a b c", []string{"a", "b", "c"}},
		{"quoted spaces", `TXT "hello world"`, []string{"TXT", "hello world"}},
		{"escaped quote", `TXT "say \"hi\""`, []string{"TXT", `say "hi"`}},
		{"escaped backslash", `TXT "a\\b"`, []string{"TXT", `a\b`}},
		{"mixed token", `abc"def"ghi`, []string{"abcdefghi"}},
		{"extra whitespace", "  a   b  ", []string{"a", "b"}},
		{"quote glued to text", `10 "mail.example.com."`, []string{"10", "mail.example.com."}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tokenize(tc.in)
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("token %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestTokenizeUnterminated(t *testing.T) {
	if _, err := tokenize(`TXT "abc`); err == nil {
		t.Fatal("expected error for unterminated quote")
	}
}
