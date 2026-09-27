package zone

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Options controls parsing.
type Options struct {
	// Origin seeds the zone origin (from the --origin flag) before any
	// $ORIGIN directive is applied. Empty means "no origin known".
	Origin string
}

// Supported record types.
var supportedTypes = map[string]bool{
	"SOA": true, "NS": true, "A": true, "AAAA": true, "CNAME": true,
	"MX": true, "TXT": true, "PTR": true, "SRV": true, "CAA": true,
}

var classTokens = map[string]bool{"IN": true, "CH": true, "HS": true, "CS": true}

// ParseFile reads and parses a master file.
func ParseFile(path string, opts Options) (*Zone, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, string(src), opts)
}

// Parse parses master-file source into a Zone. Unrecoverable syntax errors
// (returned as *ParseError) mean the file could not be parsed at all;
// individual bad records are recovered from and reported as ZS007 findings.
func Parse(file, src string, opts Options) (*Zone, error) {
	entries, err := Lex(file, src)
	if err != nil {
		return nil, err
	}

	z := &Zone{File: file}
	if seed := normalizeOrigin(opts.Origin); seed != "" {
		z.Origin = seed
		z.OriginKnown = true
		z.Apex = seed
	}

	lastOwner := ""
	for _, e := range entries {
		toks, terr := tokenize(e.Text)
		if terr != nil {
			z.addFinding("ZS007", SeverityError, e.Line, "", "cannot tokenize record: "+terr.Error())
			continue
		}
		if len(toks) == 0 {
			continue
		}
		if strings.HasPrefix(toks[0], "$") {
			z.parseDirective(e, toks)
			continue
		}
		owner, ok := z.parseOwner(e, toks, lastOwner)
		if !ok {
			continue
		}
		lastOwner = owner
		z.parseRecord(e, toks, owner, attrStart(e, toks))
	}

	z.backfillTTL()
	return z, nil
}

// backfillTTL applies the historical fallback: without a $TTL directive,
// records with no explicit TTL inherit the SOA minimum.
func (z *Zone) backfillTTL() {
	if z.HasTTLDirective {
		return
	}
	for _, r := range z.Records {
		if r.Type == "SOA" {
			if d, ok := r.RData.(*SOAData); ok && !r.TTLSet {
				for _, rr := range z.Records {
					if !rr.TTLSet {
						rr.TTL = d.Minimum
					}
				}
			}
			return
		}
	}
}

// parseDirective handles $ORIGIN, $TTL, $INCLUDE and reports unknown ones.
func (z *Zone) parseDirective(e Entry, toks []string) {
	dir := strings.ToUpper(toks[0])
	switch dir {
	case "$ORIGIN":
		if len(toks) != 2 {
			z.addFinding("ZS007", SeverityError, e.Line, "", "$ORIGIN requires exactly one name")
			return
		}
		name := toks[1]
		switch {
		case name == "@":
			if !z.OriginKnown {
				z.addFinding("ZS007", SeverityError, e.Line, "", `$ORIGIN "@" used before any origin is known`)
				return
			}
			name = z.Origin
		case strings.HasSuffix(name, "."):
			// Absolute: used as written.
		case z.OriginKnown:
			// Relative to the current origin.
			name = name + "." + z.Origin
		default:
			// First origin in the file: taken as absolute.
			name += "."
		}
		z.Origin = name
		z.OriginKnown = true
		if z.Apex == "" {
			z.Apex = name
		}
	case "$TTL":
		if len(toks) != 2 {
			z.addFinding("ZS007", SeverityError, e.Line, "", "$TTL requires exactly one value")
			return
		}
		v, err := ParseTTL(toks[1])
		if err != nil {
			z.addFinding("ZS007", SeverityError, e.Line, "", fmt.Sprintf("bad $TTL value %q: %s", toks[1], err))
			return
		}
		z.DefaultTTL = v
		z.HasTTLDirective = true
	case "$INCLUDE":
		z.addFinding("ZS019", SeverityInfo, e.Line, "",
			fmt.Sprintf("$INCLUDE %s is not supported and was skipped; its records were not loaded", strings.Join(toks[1:], " ")))
	default:
		z.addFinding("ZS007", SeverityError, e.Line, "", fmt.Sprintf("unsupported directive %s", toks[0]))
	}
}

// attrStart returns the index of the first attribute (TTL/class) or type
// token. Index 0 means the owner name was omitted and is inherited.
func attrStart(e Entry, toks []string) int {
	switch {
	case e.LeadingSpace:
		// RFC 1035: a blank owner is expressed by leading whitespace.
		return 0
	case isTypeToken(toks[0]) && len(toks) > 1 &&
		!isClassToken(toks[1]) && !isTypeToken(toks[1]):
		// A bare type token begins a blank-owner record only when what
		// follows cannot continue an owner line, e.g. "A 192.0.2.2".
		// When a class follows ("a IN A ..."), the type-shaped token is
		// really an owner named "a" or "ptr".
		return 0
	case (ttlShaped(toks[0]) || isClassToken(toks[0])) && typeWithin(toks[1:], 3):
		return 0
	default:
		return 1
	}
}

// parseOwner resolves the owner name of a record, applying owner inheritance.
// It returns the resolved owner and whether parsing should continue.
func (z *Zone) parseOwner(e Entry, toks []string, lastOwner string) (string, bool) {
	if attrStart(e, toks) == 0 {
		if lastOwner == "" {
			z.addFinding("ZS007", SeverityError, e.Line, "",
				"blank owner name but no previous record to inherit from")
			return "", false
		}
		return lastOwner, true
	}
	return z.resolveName(toks[0], e.Line), true
}

// parseRecord parses TTL/class/type/rdata and appends the record, emitting
// ZS007 findings for malformed records and skipping them (line-oriented
// recovery).
func (z *Zone) parseRecord(e Entry, toks []string, owner string, idx int) {
	ttl := z.DefaultTTL
	ttlSet := false
	class := "IN"
	for idx < len(toks) && (isClassToken(toks[idx]) || ttlShaped(toks[idx])) {
		t := toks[idx]
		idx++
		if isClassToken(t) {
			class = strings.ToUpper(t)
			continue
		}
		v, err := ParseTTL(t)
		if err != nil {
			z.addFinding("ZS007", SeverityError, e.Line, owner, fmt.Sprintf("bad TTL %q: %s", t, err))
			continue
		}
		ttl = v
		ttlSet = true
	}

	if idx >= len(toks) {
		z.addFinding("ZS007", SeverityError, e.Line, owner, "record is missing a type")
		return
	}
	recType := strings.ToUpper(toks[idx])
	idx++

	rdata := toks[idx:]
	rd, ok := z.buildRData(e, owner, recType, rdata)
	if !ok {
		return
	}

	z.Records = append(z.Records, &Record{
		Line:      e.Line,
		Owner:     owner,
		TTL:       ttl,
		TTLSet:    ttlSet,
		Class:     class,
		Type:      recType,
		RData:     rd,
		RDataText: rd.String(),
	})
}

// buildRData parses and validates the rdata of a record. On failure it emits
// a ZS007 finding and returns false so the caller skips the record.
func (z *Zone) buildRData(e Entry, owner, recType string, toks []string) (RData, bool) {
	bad := func(format string, args ...any) (RData, bool) {
		z.addFinding("ZS007", SeverityError, e.Line, owner, fmt.Sprintf(format, args...))
		return nil, false
	}
	need := func(n int) bool { return len(toks) == n }

	switch recType {
	case "SOA":
		if !need(7) {
			return bad("SOA record needs 7 fields (mname rname serial refresh retry expire minimum), got %d", len(toks))
		}
		serial, err := strconv.ParseUint(toks[2], 10, 32)
		if err != nil {
			return bad("SOA serial %q is not a 32-bit unsigned integer", toks[2])
		}
		var times [4]uint32
		for i := 0; i < 4; i++ {
			v, err := ParseTTL(toks[3+i])
			if err != nil {
				return bad("SOA %s value %q: %s", []string{"refresh", "retry", "expire", "minimum"}[i], toks[3+i], err)
			}
			times[i] = v
		}
		return &SOAData{
			MName: z.resolveName(toks[0], e.Line), RName: z.resolveName(toks[1], e.Line),
			Serial: uint32(serial), Refresh: times[0], Retry: times[1], Expire: times[2], Minimum: times[3],
		}, true

	case "NS":
		if !need(1) {
			return bad("NS record needs exactly 1 field (target), got %d", len(toks))
		}
		return &NSData{Target: z.resolveName(toks[0], e.Line)}, true

	case "A":
		if !need(1) {
			return bad("A record needs exactly 1 field (IPv4 address), got %d", len(toks))
		}
		return &AData{Address: toks[0]}, true

	case "AAAA":
		if !need(1) {
			return bad("AAAA record needs exactly 1 field (IPv6 address), got %d", len(toks))
		}
		return &AAAAData{Address: toks[0]}, true

	case "CNAME":
		if !need(1) {
			return bad("CNAME record needs exactly 1 field (target), got %d", len(toks))
		}
		return &CNAMEData{Target: z.resolveName(toks[0], e.Line)}, true

	case "PTR":
		if !need(1) {
			return bad("PTR record needs exactly 1 field (target), got %d", len(toks))
		}
		return &PTRData{Target: z.resolveName(toks[0], e.Line)}, true

	case "MX":
		if !need(2) {
			return bad("MX record needs exactly 2 fields (preference exchange), got %d", len(toks))
		}
		pref, err := strconv.ParseUint(toks[0], 10, 16)
		if err != nil {
			return bad("MX preference %q is not a 16-bit unsigned integer", toks[0])
		}
		return &MXData{Preference: uint16(pref), Exchange: z.resolveName(toks[1], e.Line)}, true

	case "TXT":
		if len(toks) == 0 {
			return bad("TXT record needs at least 1 string")
		}
		return &TXTData{Segments: append([]string(nil), toks...)}, true

	case "SRV":
		return z.buildSRV(e, owner, toks), true

	case "CAA":
		if !need(3) {
			return bad("CAA record needs exactly 3 fields (flags tag value), got %d", len(toks))
		}
		flags, err := strconv.ParseUint(toks[0], 10, 8)
		if err != nil {
			return bad("CAA flags %q is not an 8-bit unsigned integer", toks[0])
		}
		return &CAAData{Flags: uint8(flags), Tag: toks[1], Value: toks[2]}, true

	default:
		return &OpaqueData{TypeName: recType, Raw: strings.Join(toks, " ")}, true
	}
}

// buildSRV parses SRV rdata tolerantly: malformed records are kept so that
// lint rule ZS009 can report them with a precise line.
func (z *Zone) buildSRV(e Entry, owner string, toks []string) *SRVData {
	d := &SRVData{}
	if len(toks) != 4 {
		d.Err = fmt.Sprintf("SRV record needs 4 fields (priority weight port target), got %d", len(toks))
	} else {
		var err error
		if d.Priority, err = parseUint16(toks[0]); err != nil {
			d.Err = fmt.Sprintf("SRV priority %q is not a 16-bit unsigned integer", toks[0])
		} else if d.Weight, err = parseUint16(toks[1]); err != nil {
			d.Err = fmt.Sprintf("SRV weight %q is not a 16-bit unsigned integer", toks[1])
		} else if d.Port, err = parseUint16(toks[2]); err != nil {
			d.Err = fmt.Sprintf("SRV port %q is not a 16-bit unsigned integer", toks[2])
		}
	}
	if len(toks) > 3 {
		d.Target = z.resolveName(toks[3], e.Line)
	}
	return d
}

func parseUint16(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	return uint16(v), err
}

// resolveName canonicalises a domain name relative to the current origin.
// Names ending in "." are absolute; "@" is the origin; other names are
// relative and get the origin appended. When no origin is known, relative
// names are kept as written and a ZS017 warning is emitted.
func (z *Zone) resolveName(name string, line int) string {
	if name == "@" {
		if z.OriginKnown {
			return z.Origin
		}
		z.addFinding("ZS017", SeverityWarning, line, "", `name "@" used but no origin is set (no $ORIGIN and no --origin)`)
		return name
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	if z.OriginKnown {
		return name + "." + z.Origin
	}
	z.addFinding("ZS017", SeverityWarning, line, "",
		fmt.Sprintf("relative name %q has no origin to resolve against (no $ORIGIN and no --origin)", name))
	return name
}

// addFinding appends a parser-level finding.
func (z *Zone) addFinding(code string, sev Severity, line int, owner, msg string) {
	z.Findings = append(z.Findings, Finding{
		Code:     code,
		Severity: sev,
		Line:     line,
		Owner:    owner,
		Message:  msg,
	})
}

// normalizeOrigin canonicalises an origin from --origin: non-empty values
// gain a trailing dot.
func normalizeOrigin(o string) string {
	o = strings.TrimSpace(o)
	if o == "" {
		return ""
	}
	if o == "@" {
		return ""
	}
	if !strings.HasSuffix(o, ".") {
		o += "."
	}
	return o
}

// isTypeToken reports whether s is one of the record types bindlint models.
func isTypeToken(s string) bool {
	return supportedTypes[strings.ToUpper(s)]
}

func isClassToken(s string) bool {
	return classTokens[strings.ToUpper(s)]
}

// typeWithin reports whether one of the first n tokens is a record type.
func typeWithin(toks []string, n int) bool {
	if n > len(toks) {
		n = len(toks)
	}
	for i := 0; i < n; i++ {
		if isTypeToken(toks[i]) {
			return true
		}
	}
	return false
}

// ttlShaped reports whether s has the lexical shape of a TTL (digits grouped
// with letter units, e.g. "30", "1h30m", "30x"). It rejects anything
// containing dots so that host names such as "3600.example.com" are never
// mistaken for TTLs. ParseTTL performs the actual validation.
func ttlShaped(s string) bool {
	i := 0
	if i >= len(s) {
		return false
	}
	for i < len(s) {
		if !isDigit(s[i]) {
			return false
		}
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i == len(s) {
			return true
		}
		if !isLetter(s[i]) {
			return false
		}
		for i < len(s) && isLetter(s[i]) {
			i++
		}
		if i < len(s) && !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// ParseTTL parses a TTL such as "30", "30s", "5m", "2h", "1d", "1w" or
// combinations like "1h30m" into seconds.
func ParseTTL(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	var total uint64
	i := 0
	sawDigit := false
	for i < len(s) {
		if !isDigit(s[i]) {
			return 0, fmt.Errorf("expected digit at position %d", i+1)
		}
		start := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		sawDigit = true
		n, err := strconv.ParseUint(s[start:i], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("number out of range")
		}
		var mult uint64 = 1
		if i < len(s) {
			if !isLetter(s[i]) {
				return 0, fmt.Errorf("bad time unit %q", string(s[i]))
			}
			unit := s[i]
			if i+1 < len(s) && isLetter(s[i+1]) {
				// Consume multi-letter attempts so the error names them.
				j := i
				for j < len(s) && isLetter(s[j]) {
					j++
				}
				return 0, fmt.Errorf("unknown time unit %q", s[i:j])
			}
			i++
			switch unit {
			case 's', 'S':
				mult = 1
			case 'm', 'M':
				mult = 60
			case 'h', 'H':
				mult = 3600
			case 'd', 'D':
				mult = 86400
			case 'w', 'W':
				mult = 604800
			default:
				return 0, fmt.Errorf("unknown time unit %q", string(unit))
			}
		}
		total += n * mult
		if total > uint64(^uint32(0)) {
			return 0, fmt.Errorf("TTL out of range")
		}
	}
	if !sawDigit {
		return 0, fmt.Errorf("no digits")
	}
	return uint32(total), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
