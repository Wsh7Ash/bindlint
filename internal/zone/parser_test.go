package zone

import (
	"strings"
	"testing"
)

func parseSrc(t *testing.T, src string, opts Options) *Zone {
	t.Helper()
	z, err := Parse("test.zone", src, opts)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return z
}

func findingCodes(z *Zone) []string {
	out := make([]string, len(z.Findings))
	for i, f := range z.Findings {
		out[i] = f.Code
	}
	return out
}

func hasFinding(z *Zone, code string) (Finding, bool) {
	for _, f := range z.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return Finding{}, false
}

func TestParseRecordForms(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want struct {
			owner  string
			ttl    uint32
			ttlSet bool
			class  string
			typ    string
			rdata  string
		}
	}{
		{
			name: "absolute owner with ttl and class",
			src:  "$TTL 7200\n$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 3600, true, "IN", "A", "192.0.2.1"},
		},
		{
			name: "default ttl from directive",
			src:  "$TTL 7200\n$ORIGIN example.com.\nexample.com. A 192.0.2.2\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 7200, false, "IN", "A", "192.0.2.2"},
		},
		{
			name: "class without ttl",
			src:  "$TTL 7200\n$ORIGIN example.com.\nexample.com. IN MX 10 mail.example.com.\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 7200, false, "IN", "MX", "10 mail.example.com."},
		},
		{
			name: "class before ttl",
			src:  "$TTL 7200\n$ORIGIN example.com.\nexample.com. IN 300 NS ns.example.com.\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 300, true, "IN", "NS", "ns.example.com."},
		},
		{
			name: "lowercase class and type",
			src:  "$TTL 7200\n$ORIGIN example.com.\nexample.com. in a 192.0.2.3\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 7200, false, "IN", "A", "192.0.2.3"},
		},
		{
			name: "ttl with unit combo",
			src:  "$ORIGIN example.com.\nexample.com. 1h30m IN A 192.0.2.4\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 5400, true, "IN", "A", "192.0.2.4"},
		},
		{
			name: "at owner resolves to origin",
			src:  "$TTL 60\n$ORIGIN example.com.\n@ IN A 192.0.2.5\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"example.com.", 60, false, "IN", "A", "192.0.2.5"},
		},
		{
			name: "relative owner gets origin",
			src:  "$TTL 60\n$ORIGIN example.com.\nwww IN A 192.0.2.6\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"www.example.com.", 60, false, "IN", "A", "192.0.2.6"},
		},
		{
			name: "wildcard owner",
			src:  "$TTL 60\n$ORIGIN example.com.\n*.api IN A 192.0.2.7\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"*.api.example.com.", 60, false, "IN", "A", "192.0.2.7"},
		},
		{
			name: "bare wildcard owner",
			src:  "$TTL 60\n$ORIGIN example.com.\n* IN A 192.0.2.8\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"*.example.com.", 60, false, "IN", "A", "192.0.2.8"},
		},
		{
			name: "multi-label relative owner",
			src:  "$TTL 60\n$ORIGIN example.com.\na.b IN A 192.0.2.9\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"a.b.example.com.", 60, false, "IN", "A", "192.0.2.9"},
		},
		{
			name: "numeric-looking owner is not a ttl",
			src:  "$TTL 60\n$ORIGIN example.com.\n3600.example.com. IN A 192.0.2.10\n",
			want: struct {
				owner  string
				ttl    uint32
				ttlSet bool
				class  string
				typ    string
				rdata  string
			}{"3600.example.com.", 60, false, "IN", "A", "192.0.2.10"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := parseSrc(t, tc.src, Options{})
			if len(z.Records) != 1 {
				t.Fatalf("got %d records, want 1: %v", len(z.Records), findingCodes(z))
			}
			r := z.Records[0]
			if r.Owner != tc.want.owner {
				t.Errorf("Owner = %q, want %q", r.Owner, tc.want.owner)
			}
			if r.TTL != tc.want.ttl || r.TTLSet != tc.want.ttlSet {
				t.Errorf("TTL = %d (set=%v), want %d (set=%v)", r.TTL, r.TTLSet, tc.want.ttl, tc.want.ttlSet)
			}
			if r.Class != tc.want.class {
				t.Errorf("Class = %q, want %q", r.Class, tc.want.class)
			}
			if r.Type != tc.want.typ {
				t.Errorf("Type = %q, want %q", r.Type, tc.want.typ)
			}
			if r.RDataText != tc.want.rdata {
				t.Errorf("RData = %q, want %q", r.RDataText, tc.want.rdata)
			}
			if len(z.Findings) != 0 {
				t.Errorf("unexpected findings: %v", z.Findings)
			}
		})
	}
}

func TestOwnerInheritance(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantOwn []string
	}{
		{
			name:    "leading whitespace inherits",
			src:     "$TTL 60\n$ORIGIN example.com.\nwww IN A 192.0.2.1\n\tIN A 192.0.2.2\n IN AAAA 2001:db8::2\n",
			wantOwn: []string{"www.example.com.", "www.example.com.", "www.example.com."},
		},
		{
			name:    "type token first inherits",
			src:     "$TTL 60\n$ORIGIN example.com.\nwww IN A 192.0.2.1\nA 192.0.2.2\n",
			wantOwn: []string{"www.example.com.", "www.example.com."},
		},
		{
			name:    "ttl first inherits without leading space",
			src:     "$TTL 60\n$ORIGIN example.com.\nwww IN A 192.0.2.1\n300 IN A 192.0.2.2\n",
			wantOwn: []string{"www.example.com.", "www.example.com."},
		},
		{
			name:    "paren continuation inherits via leading space",
			src:     "$TTL 60\n$ORIGIN example.com.\nwww IN MX (\n 10 mail.example.com. )\n",
			wantOwn: []string{"www.example.com."},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := parseSrc(t, tc.src, Options{})
			if len(z.Records) != len(tc.wantOwn) {
				t.Fatalf("got %d records, want %d (%v)", len(z.Records), len(tc.wantOwn), findingCodes(z))
			}
			for i, w := range tc.wantOwn {
				if z.Records[i].Owner != w {
					t.Errorf("record %d owner = %q, want %q", i, z.Records[i].Owner, w)
				}
			}
		})
	}
}

func TestBlankOwnerWithoutPreviousIsFinding(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n IN A 192.0.2.1\n", Options{})
	if len(z.Records) != 0 {
		t.Fatalf("got %d records, want 0", len(z.Records))
	}
	f, ok := hasFinding(z, "ZS007")
	if !ok {
		t.Fatal("expected ZS007 finding")
	}
	if f.Line != 3 {
		t.Errorf("Line = %d, want 3", f.Line)
	}
}

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in    string
		want  uint32
		isErr bool
	}{
		{"30", 30, false},
		{"0", 0, false},
		{"30s", 30, false},
		{"5m", 300, false},
		{"2h", 7200, false},
		{"1d", 86400, false},
		{"1w", 604800, false},
		{"1h30m", 5400, false},
		{"1h15m30s", 4530, false},
		{"604800", 604800, false},
		{"1D", 86400, false},
		{"", 0, true},
		{"30x", 0, true},
		{"5q", 0, true},
		{"-5", 0, true},
		{"1.5h", 0, true},
		{"ms", 0, true},
		{"99999999999999999999999", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTTL(tc.in)
			if tc.isErr {
				if err == nil {
					t.Fatalf("ParseTTL(%q) = %d, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTTL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseTTL(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestTTLShapedRejectsHostNames(t *testing.T) {
	cases := map[string]bool{
		"3600":         true,
		"1h30m":        true,
		"30x":          true,
		"3600.example": false,
		"www":          false,
		"":             false,
		"1h-30m":       false,
		"123abc456def": true,
	}
	for in, want := range cases {
		if got := ttlShaped(in); got != want {
			t.Errorf("ttlShaped(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTXTRecords(t *testing.T) {
	cases := []struct {
		name string
		rdat string
		want []string
	}{
		{"multiple strings", `"one" "two"`, []string{"one", "two"}},
		{"three strings", `"a" "b" "c"`, []string{"a", "b", "c"}},
		{"escaped quote", `"say \"hi\""`, []string{`say "hi"`}},
		{"escaped backslash", `"a\\b"`, []string{`a\b`}},
		{"unquoted", `bare-string`, []string{"bare-string"}},
		{"mixed", `"seg1" bare`, []string{"seg1", "bare"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\nt IN TXT "+tc.rdat+"\n", Options{})
			if len(z.Records) != 1 {
				t.Fatalf("got %d records, want 1 (%v)", len(z.Records), findingCodes(z))
			}
			d, ok := z.Records[0].RData.(*TXTData)
			if !ok {
				t.Fatalf("rdata type %T, want *TXTData", z.Records[0].RData)
			}
			if len(d.Segments) != len(tc.want) {
				t.Fatalf("segments = %v, want %v", d.Segments, tc.want)
			}
			for i := range tc.want {
				if d.Segments[i] != tc.want[i] {
					t.Errorf("segment %d = %q, want %q", i, d.Segments[i], tc.want[i])
				}
			}
		})
	}
}

func TestTypedRData(t *testing.T) {
	src := `$TTL 60
$ORIGIN example.com.
@ IN SOA ns1.example.com. hostmaster.example.com. 2026092701 1h 15m 1w 5m
@ IN NS ns1
www IN A 192.0.2.1
www6 IN AAAA 2001:db8::1
mail IN MX 20 mailhost.example.com.
sip IN SRV 10 20 5060 sip.example.com.
www IN CNAME web
ptr IN PTR www.example.com.
txt IN TXT "hello"
_80 IN CAA 0 issue "letsencrypt.org"
`
	z := parseSrc(t, src, Options{})
	if len(z.Findings) != 0 {
		t.Fatalf("unexpected findings: %v", z.Findings)
	}
	if len(z.Records) != 10 {
		t.Fatalf("got %d records, want 10", len(z.Records))
	}

	soa := z.Records[0].RData.(*SOAData)
	if soa.Serial != 2026092701 || soa.Refresh != 3600 || soa.Retry != 900 || soa.Expire != 604800 || soa.Minimum != 300 {
		t.Errorf("SOA = %+v", soa)
	}
	if soa.MName != "ns1.example.com." {
		t.Errorf("SOA MName = %q", soa.MName)
	}
	if ns := z.Records[1].RData.(*NSData); ns.Target != "ns1.example.com." {
		t.Errorf("NS target = %q", ns.Target)
	}
	if mx := z.Records[4].RData.(*MXData); mx.Preference != 20 || mx.Exchange != "mailhost.example.com." {
		t.Errorf("MX = %+v", mx)
	}
	srv := z.Records[5].RData.(*SRVData)
	if srv.Err != "" || srv.Priority != 10 || srv.Weight != 20 || srv.Port != 5060 || srv.Target != "sip.example.com." {
		t.Errorf("SRV = %+v", srv)
	}
	if cn := z.Records[6].RData.(*CNAMEData); cn.Target != "web.example.com." {
		t.Errorf("CNAME target = %q", cn.Target)
	}
	if ptr := z.Records[7].RData.(*PTRData); ptr.Target != "www.example.com." {
		t.Errorf("PTR target = %q", ptr.Target)
	}
	if caa := z.Records[9].RData.(*CAAData); caa.Flags != 0 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Errorf("CAA = %+v", caa)
	}
}

func TestOriginHandling(t *testing.T) {
	t.Run("relative rdata resolves", func(t *testing.T) {
		z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n@ IN NS ns1\n", Options{})
		if got := z.Records[0].RData.(*NSData).Target; got != "ns1.example.com." {
			t.Errorf("target = %q", got)
		}
	})

	t.Run("origin flag seeds origin", func(t *testing.T) {
		z := parseSrc(t, "$TTL 60\nwww IN A 192.0.2.1\n", Options{Origin: "example.com"})
		if z.Records[0].Owner != "www.example.com." {
			t.Errorf("owner = %q", z.Records[0].Owner)
		}
		if z.Apex != "example.com." {
			t.Errorf("apex = %q", z.Apex)
		}
		if _, ok := hasFinding(z, "ZS017"); ok {
			t.Error("unexpected ZS017 with --origin")
		}
	})

	t.Run("origin redefinition applies from its position", func(t *testing.T) {
		src := "$TTL 60\n$ORIGIN example.com.\na IN A 192.0.2.1\n$ORIGIN sub.example.com.\nb IN A 192.0.2.2\n"
		z := parseSrc(t, src, Options{})
		if z.Records[0].Owner != "a.example.com." {
			t.Errorf("owner1 = %q", z.Records[0].Owner)
		}
		if z.Records[1].Owner != "b.sub.example.com." {
			t.Errorf("owner2 = %q", z.Records[1].Owner)
		}
		if z.Apex != "example.com." {
			t.Errorf("apex = %q, want the first origin", z.Apex)
		}
		if z.Origin != "sub.example.com." {
			t.Errorf("origin = %q, want the current origin", z.Origin)
		}
	})

	t.Run("first relative origin is absolutised", func(t *testing.T) {
		z := parseSrc(t, "$TTL 60\n$ORIGIN example.com\nwww IN A 192.0.2.1\n", Options{})
		if z.Origin != "example.com." {
			t.Errorf("origin = %q", z.Origin)
		}
		if _, ok := hasFinding(z, "ZS017"); ok {
			t.Error("unexpected ZS017 for $ORIGIN")
		}
	})

	t.Run("relative origin under known origin", func(t *testing.T) {
		z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n$ORIGIN sub\nwww IN A 192.0.2.1\n", Options{})
		if z.Origin != "sub.example.com." {
			t.Errorf("origin = %q", z.Origin)
		}
	})
}

func TestRelativeWithoutOriginEmitsZS017(t *testing.T) {
	z := parseSrc(t, "$TTL 60\nwww IN A 192.0.2.1\n@ IN NS ns1\n", Options{})
	var lines []int
	for _, f := range z.Findings {
		if f.Code == "ZS017" {
			lines = append(lines, f.Line)
		}
	}
	if len(lines) < 3 {
		t.Fatalf("expected ZS017 for owner, @ and rdata; got findings: %v", z.Findings)
	}
	if lines[0] != 2 {
		t.Errorf("first ZS017 line = %d, want 2", lines[0])
	}
	if z.Records[0].Owner != "www" {
		t.Errorf("owner = %q, want unresolved %q", z.Records[0].Owner, "www")
	}
}

func TestIncludeIsSkippedWithFinding(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n$INCLUDE sub.zone\n@ IN A 192.0.2.1\n", Options{})
	if len(z.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(z.Records))
	}
	f, ok := hasFinding(z, "ZS019")
	if !ok {
		t.Fatal("expected ZS019 finding")
	}
	if f.Line != 3 {
		t.Errorf("Line = %d, want 3", f.Line)
	}
	if !strings.Contains(f.Message, "sub.zone") {
		t.Errorf("Message = %q, want it to mention sub.zone", f.Message)
	}
}

func TestBadRecordsBecomeZS007(t *testing.T) {
	cases := []struct {
		name string
		line string // the record line (after the two-line preamble)
	}{
		{"bad ttl unit", "bad 30x IN A 192.0.2.1"},
		{"missing type", "bad 300"},
		{"no rdata", "bad IN A"},
		{"bad ip fields", "bad IN A 1.2.3.4 5.6.7.8"},
		{"bad soa serial", "bad IN SOA ns host 2026092701x 1h 15m 1w 5m"},
		{"soa too few fields", "bad IN SOA ns host 1"},
		{"mx preference not numeric", "bad IN MX high mail.example.com."},
		{"caa flags not numeric", "bad IN CAA yes issue x"},
		{"unknown directive", "$GENERATE 1-10 host$ IN A 192.0.2.$1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "$TTL 60\n$ORIGIN example.com.\n" + tc.line + "\ngood IN A 192.0.2.9\n"
			z := parseSrc(t, src, Options{})
			f, ok := hasFinding(z, "ZS007")
			if !ok {
				t.Fatalf("expected ZS007, got findings %v", findingCodes(z))
			}
			if f.Line != 3 {
				t.Errorf("Line = %d, want 3", f.Line)
			}
			// Recovery: the following record must still be parsed.
			last := z.Records[len(z.Records)-1]
			if last.Owner != "good.example.com." {
				t.Errorf("recovery failed, last record = %+v", last)
			}
		})
	}
}

func TestBadTTLKeepsRecordWithDefault(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\nbad 30x IN A 192.0.2.1\n", Options{})
	if len(z.Records) != 1 {
		t.Fatalf("got %d records, want 1 (%v)", len(z.Records), findingCodes(z))
	}
	if z.Records[0].TTL != 60 {
		t.Errorf("TTL = %d, want default 60", z.Records[0].TTL)
	}
	if z.Records[0].TTLSet {
		t.Error("TTLSet = true, want false after bad TTL")
	}
}

func TestMalformedSRVIsKept(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n_sip._tcp IN SRV 10 5 0\n", Options{})
	if len(z.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(z.Records))
	}
	d := z.Records[0].RData.(*SRVData)
	if d.Err == "" {
		t.Error("expected SRVData.Err to describe the problem")
	}
}

func TestSRVDotTargetIsValid(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\n_x IN SRV 10 5 5060 .\n", Options{})
	d := z.Records[0].RData.(*SRVData)
	if d.Err != "" {
		t.Errorf("Err = %q, want empty for target \".\"", d.Err)
	}
	if d.Target != "." {
		t.Errorf("Target = %q, want \".\"", d.Target)
	}
}

func TestLineNumbersPreserved(t *testing.T) {
	src := "$TTL 60\n" + // line 1
		"$ORIGIN example.com.\n" + // line 2
		"; comment\n" + // line 3
		"www IN A 192.0.2.1\n" + // line 4
		"\n" + // line 5
		"long IN TXT (\n" + // line 6
		"\"part one\" \"part two\" )\n" + // line 7
		"bad 30x IN A 192.0.2.2\n" // line 8
	z := parseSrc(t, src, Options{})
	if len(z.Records) != 3 {
		t.Fatalf("got %d records, want 3 (%v)", len(z.Records), findingCodes(z))
	}
	if z.Records[0].Line != 4 {
		t.Errorf("record 0 Line = %d, want 4", z.Records[0].Line)
	}
	if z.Records[1].Line != 6 {
		t.Errorf("record 1 Line = %d, want 6 (entry start of parenthesised record)", z.Records[1].Line)
	}
	if z.Records[2].Line != 8 {
		t.Errorf("record 2 Line = %d, want 8 (bad-TTL record is kept with the default TTL)", z.Records[2].Line)
	}
	f, ok := hasFinding(z, "ZS007")
	if !ok {
		t.Fatal("expected ZS007")
	}
	if f.Line != 8 {
		t.Errorf("ZS007 Line = %d, want 8", f.Line)
	}
}

func TestNoTTLDirectiveBackfillsSoaMinimum(t *testing.T) {
	src := "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 2026092701 1h 15m 1w 5m\nbare IN A 192.0.2.1\nexplicit 7200 IN A 192.0.2.2\n"
	z := parseSrc(t, src, Options{})
	if z.HasTTLDirective {
		t.Error("HasTTLDirective = true, want false")
	}
	if z.Records[1].TTL != 300 {
		t.Errorf("bare record TTL = %d, want SOA minimum 300", z.Records[1].TTL)
	}
	if z.Records[2].TTL != 7200 {
		t.Errorf("explicit record TTL = %d, want 7200", z.Records[2].TTL)
	}
}

func TestTTLDirectiveBadValue(t *testing.T) {
	z := parseSrc(t, "$TTL 5q\n$ORIGIN example.com.\n@ IN A 192.0.2.1\n", Options{})
	if z.HasTTLDirective {
		t.Error("HasTTLDirective = true for a bad $TTL value")
	}
	f, ok := hasFinding(z, "ZS007")
	if !ok {
		t.Fatal("expected ZS007 for bad $TTL")
	}
	if f.Line != 1 {
		t.Errorf("Line = %d, want 1", f.Line)
	}
}

func TestParseFatalError(t *testing.T) {
	if _, err := Parse("t.zone", "www IN TXT \"unterminated\n", Options{}); err == nil {
		t.Fatal("expected fatal parse error")
	} else if _, ok := err.(*ParseError); !ok {
		t.Fatalf("error type %T, want *ParseError", err)
	}
}

func TestOpaqueRecordTypeIsPreserved(t *testing.T) {
	z := parseSrc(t, "$TTL 60\n$ORIGIN example.com.\ndnskey IN DNSKEY 256 3 1 AwEAA\n", Options{})
	if len(z.Records) != 1 {
		t.Fatalf("got %d records, want 1 (%v)", len(z.Records), findingCodes(z))
	}
	if z.Records[0].Type != "DNSKEY" {
		t.Errorf("Type = %q", z.Records[0].Type)
	}
	if z.Records[0].RDataText != "256 3 1 AwEAA" {
		t.Errorf("RData = %q", z.Records[0].RDataText)
	}
}
