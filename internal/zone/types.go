// Package zone implements an offline parser for BIND-style DNS master files.
//
// The parser produces typed records and parser-level findings without any
// network access and without requiring BIND to be installed.
package zone

import (
	"fmt"
	"strings"
)

// Severity classifies a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// String returns the lowercase display name of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// MarshalJSON encodes the severity as a lowercase string.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON decodes a lowercase severity string.
func (s *Severity) UnmarshalJSON(b []byte) error {
	v := strings.Trim(string(b), `"`)
	switch v {
	case "error":
		*s = SeverityError
	case "warning":
		*s = SeverityWarning
	case "info":
		*s = SeverityInfo
	default:
		return fmt.Errorf("unknown severity %q", v)
	}
	return nil
}

// ParseSeverity maps a string to a Severity.
func ParseSeverity(v string) (Severity, error) {
	switch v {
	case "error":
		return SeverityError, nil
	case "warning":
		return SeverityWarning, nil
	case "info":
		return SeverityInfo, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q", v)
}

// Finding is a single lint/parser observation about a zone file.
type Finding struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Line        int      `json:"line"`
	Owner       string   `json:"owner,omitempty"`
	Message     string   `json:"message"`
	Explanation string   `json:"explanation,omitempty"`
	Suggestion  string   `json:"suggestion,omitempty"`
}

// RData is the typed rdata of a record.
type RData interface {
	// Kind is the RR type name, e.g. "A".
	Kind() string
	// String renders the rdata in zone-file syntax.
	String() string
}

// SOAData is the rdata of an SOA record.
type SOAData struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

func (d *SOAData) Kind() string { return "SOA" }
func (d *SOAData) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", d.MName, d.RName, d.Serial, d.Refresh, d.Retry, d.Expire, d.Minimum)
}

// NSData is the rdata of an NS record.
type NSData struct {
	Target string `json:"target"`
}

func (d *NSData) Kind() string   { return "NS" }
func (d *NSData) String() string { return d.Target }

// AData is the rdata of an A record. The address is kept as written; it is
// validated by lint rule ZS008.
type AData struct {
	Address string `json:"address"`
}

func (d *AData) Kind() string   { return "A" }
func (d *AData) String() string { return d.Address }

// AAAAData is the rdata of an AAAA record. Validated by ZS008.
type AAAAData struct {
	Address string `json:"address"`
}

func (d *AAAAData) Kind() string   { return "AAAA" }
func (d *AAAAData) String() string { return d.Address }

// CNAMEData is the rdata of a CNAME record.
type CNAMEData struct {
	Target string `json:"target"`
}

func (d *CNAMEData) Kind() string   { return "CNAME" }
func (d *CNAMEData) String() string { return d.Target }

// PTRData is the rdata of a PTR record.
type PTRData struct {
	Target string `json:"target"`
}

func (d *PTRData) Kind() string   { return "PTR" }
func (d *PTRData) String() string { return d.Target }

// MXData is the rdata of an MX record.
type MXData struct {
	Preference uint16 `json:"preference"`
	Exchange   string `json:"exchange"`
}

func (d *MXData) Kind() string { return "MX" }
func (d *MXData) String() string {
	return fmt.Sprintf("%d %s", d.Preference, d.Exchange)
}

// TXTData is the rdata of a TXT record. Each segment is at most 255 octets
// (checked by ZS014).
type TXTData struct {
	Segments []string `json:"segments"`
}

func (d *TXTData) Kind() string { return "TXT" }
func (d *TXTData) String() string {
	parts := make([]string, len(d.Segments))
	for i, s := range d.Segments {
		parts[i] = quoteTXT(s)
	}
	return strings.Join(parts, " ")
}

// SRVData is the rdata of an SRV record. Err is non-empty when the record is
// malformed (checked by ZS009); whatever could be parsed is retained.
type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
	Err      string `json:"error,omitempty"`
}

func (d *SRVData) Kind() string { return "SRV" }
func (d *SRVData) String() string {
	if d.Err != "" {
		return strings.TrimSpace(fmt.Sprintf("%d %d %d %s", d.Priority, d.Weight, d.Port, d.Target))
	}
	return fmt.Sprintf("%d %d %d %s", d.Priority, d.Weight, d.Port, d.Target)
}

// CAAData is the rdata of a CAA record.
type CAAData struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

func (d *CAAData) Kind() string { return "CAA" }
func (d *CAAData) String() string {
	return fmt.Sprintf("%d %s %s", d.Flags, d.Tag, quoteTXT(d.Value))
}

// OpaqueData holds the rdata of a record type bindlint does not model
// (for example DNSKEY). It is carried through without validation.
type OpaqueData struct {
	TypeName string `json:"type_name"`
	Raw      string `json:"raw"`
}

func (d *OpaqueData) Kind() string   { return d.TypeName }
func (d *OpaqueData) String() string { return d.Raw }

// quoteTXT renders a TXT/CAA value as a quoted zone-file string, escaping
// backslashes and double quotes.
func quoteTXT(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Record is one parsed resource record.
type Record struct {
	Line  int    `json:"line"`
	Owner string `json:"owner"`
	TTL   uint32 `json:"ttl"`
	// TTLSet reports whether the TTL was written explicitly on the record
	// (as opposed to inherited from $TTL or the SOA minimum).
	TTLSet bool   `json:"ttl_set"`
	Class  string `json:"class"`
	Type   string `json:"type"`
	RData  RData  `json:"-"`
	// RDataText is the rendered rdata used by the JSON dump.
	RDataText string `json:"rdata"`
}

// Zone is the result of parsing one master file.
type Zone struct {
	File string `json:"file"`
	// Origin is the zone origin after applying $ORIGIN/--origin. Empty when
	// no origin is known.
	Origin string `json:"origin"`
	// OriginKnown reports whether Origin was ever set.
	OriginKnown bool `json:"origin_known"`
	// Apex is the first known origin (from --origin or the first $ORIGIN).
	// It identifies the zone itself even when $ORIGIN is redefined later.
	Apex string `json:"apex,omitempty"`
	// HasTTLDirective reports whether a valid $TTL directive was seen.
	HasTTLDirective bool `json:"has_ttl_directive"`
	// DefaultTTL is the value from $TTL (0 when unset).
	DefaultTTL uint32    `json:"default_ttl"`
	Records    []*Record `json:"records"`
	// Findings holds parser-level findings (ZS007, ZS017, ZS019, ...).
	Findings []Finding `json:"findings"`
}
