// Package lint implements the RFC-aware rule checks over a parsed zone and
// turns parser findings plus rule findings into a report.
package lint

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Wsh7Ash/bindlint/internal/zone"
)

// DefaultMaxTTL is the default ceiling for ZS016: 68400 seconds (19 hours),
// a common SOA-maximum TTL in published zones.
const DefaultMaxTTL = 68400

// Config controls lint behaviour.
type Config struct {
	// MaxTTL is the TTL ceiling used by ZS016. Zero means DefaultMaxTTL.
	MaxTTL uint32
}

// EffectiveMaxTTL returns the configured TTL ceiling.
func (c Config) EffectiveMaxTTL() uint32 {
	if c.MaxTTL == 0 {
		return DefaultMaxTTL
	}
	return c.MaxTTL
}

// Rule is the static description of one lint rule.
type Rule struct {
	Code        string
	Severity    zone.Severity
	Description string
	Explanation string
	Suggestion  string
}

// Rules is the stable rule catalogue, in code order. `bindlint rules` lists
// these entries and findings are enriched from them.
var Rules = []Rule{
	{
		Code: "ZS001", Severity: zone.SeverityError,
		Description: "no SOA record at the zone apex",
		Explanation: "Every zone must contain exactly one SOA record at its apex (RFC 1035 section 3.3.13). Secondaries and resolvers read it for the zone's serial and timing parameters; without it the zone cannot be transferred and many servers refuse to answer authoritatively.",
		Suggestion:  "Add an SOA at the origin, for example: `@ IN SOA ns1.<zone>. hostmaster.<zone>. ( <serial> <refresh> <retry> <expire> <minimum> )`.",
	},
	{
		Code: "ZS002", Severity: zone.SeverityError,
		Description: "no NS record at the zone apex",
		Explanation: "Delegation is expressed by NS records at the zone apex (RFC 1035 section 3.3.13). Without them the parent has nothing to delegate to and resolvers will not treat the servers as authoritative for the zone.",
		Suggestion:  "Add at least one apex NS record, for example: `@ IN NS ns1.<zone>.`",
	},
	{
		Code: "ZS003", Severity: zone.SeverityError,
		Description: "CNAME coexists with other data at the same owner",
		Explanation: "RFC 2181 section 10.1 states that a CNAME record is incompatible with every other record type at the same owner name. Configurations such as CNAME plus A at the same name make resolver behaviour undefined and are rejected by BIND at load time.",
		Suggestion:  "Either drop the CNAME and keep the address records, or keep the CNAME and move the other data (for example the MX or TXT records) to a different name.",
	},
	{
		Code: "ZS004", Severity: zone.SeverityError,
		Description: "CNAME target chain forms a loop",
		Explanation: "A CNAME must point to a name that eventually resolves to a different record type (RFC 1034 section 3.6.6). A cycle such as a -> b -> a can never terminate, so every query for the names in the loop fails, often with a server-side loop error that is hard to trace back to the zone file.",
		Suggestion:  "Break the chain: make the last CNAME in the loop point at the real final name (an A, AAAA or other record), not back at an earlier name.",
	},
	{
		Code: "ZS005", Severity: zone.SeverityError,
		Description: "CNAME target inside the zone has no records",
		Explanation: "When a CNAME target is a name inside this zone and no record exists for that target, every lookup of the alias fails with NXDOMAIN after the delegation is live. The reference is dangling inside the authoritative data.",
		Suggestion:  "Create the target name in this zone (typically an A/AAAA record), or point the CNAME at a name that exists here or at an out-of-zone name you control.",
	},
	{
		Code: "ZS006", Severity: zone.SeverityError,
		Description: "duplicate identical record",
		Explanation: "The same record twice (same owner, class, type, rdata and TTL) is redundant data that usually indicates a copy/paste error. It bloats transfers and can mask the intended edit.",
		Suggestion:  "Delete one of the duplicate lines and keep a single copy of the record.",
	},
	{
		Code: "ZS007", Severity: zone.SeverityError,
		Description: "malformed record: bad TTL, bad time unit or unparseable fields",
		Explanation: "The parser could not make sense of the line (for example a TTL with an unknown unit, a missing type, or a field with the wrong syntax). bindlint recovers line by line: the bad line is skipped and parsing continues, so later problems are still reported.",
		Suggestion:  "Fix the reported line: use TTL units s, m, h, d or w (for example `5m` or `1h30m`), and check that the record has a type and the right number of rdata fields.",
	},
	{
		Code: "ZS008", Severity: zone.SeverityError,
		Description: "invalid IP address literal in A or AAAA record",
		Explanation: "An A record must contain a dotted-quad IPv4 address and an AAAA record an IPv6 address (RFC 1035 section 3.3.14, RFC 3596). An unparseable or wrong-family literal makes the record unusable and BIND will refuse the zone.",
		Suggestion:  "Replace the value with a valid address of the right family, for example `192.0.2.10` for A or `2001:db8::10` for AAAA.",
	},
	{
		Code: "ZS009", Severity: zone.SeverityError,
		Description: "malformed SRV record",
		Explanation: "SRV rdata must be four fields: priority, weight, port and target (RFC 2782). Missing fields or non-numeric numbers make the record unusable; the target `.` (root) is legal and means 'no service'.",
		Suggestion:  "Write the record as `_<service>._<proto>. IN SRV <priority> <weight> <port> <target>` with 16-bit unsigned numbers.",
	},
	{
		Code: "ZS010", Severity: zone.SeverityWarning,
		Description: "no $TTL directive in the zone file",
		Explanation: "Without $TTL, records with no explicit TTL fall back to the SOA minimum field (RFC 2308). That fallback is silent, so the effective TTL of a record may not be what the operator expects.",
		Suggestion:  "Add a `$TTL <value>` directive near the top of the file, for example `$TTL 3600`.",
	},
	{
		Code: "ZS011", Severity: zone.SeverityWarning,
		Description: "inconsistent TTLs across records at the same owner",
		Explanation: "Records at one name carrying different TTLs make caching behaviour unpredictable and are usually a sign that one of the values was edited by mistake (RFC 2181 section 8).",
		Suggestion:  "Pick one TTL for the name and apply it to all of its records (or rely on a single $TTL).",
	},
	{
		Code: "ZS012", Severity: zone.SeverityWarning,
		Description: "zone apex has no A or AAAA record",
		Explanation: "The origin name itself almost always needs an address record: the zone apex is where the domain is resolved from, and its absence usually means the main website or mail front-end will not resolve.",
		Suggestion:  "Add an apex address record such as `@ IN A 192.0.2.10` (and/or `@ IN AAAA 2001:db8::10`).",
	},
	{
		Code: "ZS013", Severity: zone.SeverityWarning,
		Description: "MX exchange inside the zone has no A/AAAA record",
		Explanation: "Mail is delivered to the host named in the MX exchange. When that host is inside this zone but has no address record here, delivery fails after the zone goes live. The check only applies to exchanges inside the zone origin; out-of-zone exchanges are not visible offline.",
		Suggestion:  "Add an A/AAAA record for the exchange host in this zone, or point the MX at a name that has one.",
	},
	{
		Code: "ZS014", Severity: zone.SeverityWarning,
		Description: "TXT string longer than 255 octets",
		Explanation: "A single TXT character-string is limited to 255 octets (RFC 1035 section 3.3). Longer strings are rejected by strict servers; long values such as SPF or DKIM records must be split into multiple quoted strings inside one TXT record.",
		Suggestion:  "Split the value into quoted chunks of at most 255 octets: `TXT \"part1\" \"part2\"` (the chunks are concatenated by the resolver).",
	},
	{
		Code: "ZS015", Severity: zone.SeverityWarning,
		Description: "wildcard coexists with an explicit record under the same parent",
		Explanation: "A wildcard `*.example.com` never applies to names that have their own records (RFC 4592 section 2.2.1). When an explicit name such as `www.example.com` exists alongside the wildcard, the wildcard is shadowed for that name, which surprises operators who expect the wildcard to cover it.",
		Suggestion:  "If the explicit record is intended, keep it and remember the wildcard does not cover that name; otherwise remove one of the two.",
	},
	{
		Code: "ZS016", Severity: zone.SeverityWarning,
		Description: "TTL above the configured maximum",
		Explanation: "Very long TTLs (above 68400 seconds by default) pin stale answers in caches for a long time and make emergency changes slow to take effect. bindlint flags any effective TTL above the configurable maximum.",
		Suggestion:  "Lower the TTL, or raise the ceiling explicitly with `--max-ttl` if the long TTL is intentional.",
	},
	{
		Code: "ZS017", Severity: zone.SeverityWarning,
		Description: "relative name used but no origin is set",
		Explanation: "Relative names (and `@`) are only meaningful relative to the zone origin. Without $ORIGIN or --origin bindlint cannot resolve them, so the name is kept as written and other checks that depend on the origin are skipped.",
		Suggestion:  "Add a `$ORIGIN example.com.` directive at the top of the file, pass `--origin example.com.`, or write absolute names with a trailing dot.",
	},
	{
		Code: "ZS018", Severity: zone.SeverityInfo,
		Description: "apex has no SPF or DMARC TXT records",
		Explanation: "Modern sending domains publish an SPF record (`v=spf1`) at the apex and a DMARC policy at `_dmarc.<zone>`. Their absence is not an outage, but mail receivers will treat the domain more strictly.",
		Suggestion:  "Publish `@ IN TXT \"v=spf1 ...\"` and `_dmarc.<zone>. IN TXT \"v=DMARC1; p=none\"` if you send mail from this domain.",
	},
	{
		Code: "ZS019", Severity: zone.SeverityInfo,
		Description: "$INCLUDE encountered and skipped",
		Explanation: "bindlint is an offline linter and deliberately does not follow $INCLUDE: included files are not read, so records inside them are not linted. The directive is reported for awareness.",
		Suggestion:  "Lint each included file separately, or inline the included content before running bindlint.",
	},
}

var rulesByCode = func() map[string]Rule {
	m := make(map[string]Rule, len(Rules))
	for _, r := range Rules {
		m[r.Code] = r
	}
	return m
}()

// Lookup returns the catalogue entry for a rule code.
func Lookup(code string) (Rule, bool) {
	r, ok := rulesByCode[code]
	return r, ok
}

// Enrich fills severity, explanation and suggestion on a finding from the
// catalogue. Existing values are kept so parser-provided messages win.
func Enrich(f *zone.Finding) {
	if r, ok := rulesByCode[f.Code]; ok {
		f.Severity = r.Severity
		if f.Explanation == "" {
			f.Explanation = r.Explanation
		}
		if f.Suggestion == "" {
			f.Suggestion = r.Suggestion
		}
	}
}

// Lint runs every rule over a parsed zone and returns all findings,
// including the parser-level findings the zone already carries.
func Lint(z *zone.Zone, cfg Config) []zone.Finding {
	out := make([]zone.Finding, len(z.Findings))
	copy(out, z.Findings)

	l := &linter{z: z, cfg: cfg, records: z.Records}
	l.index()
	l.ruleSOA()
	l.ruleNS()
	l.ruleCNAMECoexist()
	l.ruleCNAMELoop()
	l.ruleCNAMEDangling()
	l.ruleDuplicates()
	l.ruleBadIP()
	l.ruleSRV()
	l.ruleMissingTTL()
	l.ruleTTLInconsistent()
	l.ruleNoApexAddress()
	l.ruleMXExchange()
	l.ruleTXTLong()
	l.ruleWildcardShadow()
	l.ruleTTLMax()
	l.ruleNoSPF()

	for i := range out {
		Enrich(&out[i])
	}
	for i := range l.findings {
		Enrich(&l.findings[i])
	}
	out = append(out, l.findings...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Code < out[j].Code
	})
	return out
}

type linter struct {
	z       *zone.Zone
	cfg     Config
	records []*zone.Record

	byOwner  map[string][]*zone.Record
	apex     string
	apexSet  []string
	findings []zone.Finding
}

func (l *linter) index() {
	l.byOwner = make(map[string][]*zone.Record)
	for _, r := range l.records {
		key := strings.ToLower(r.Owner)
		l.byOwner[key] = append(l.byOwner[key], r)
	}

	// The apex is the first known origin ($ORIGIN or --origin). When no
	// origin is known the SOA owner (or "@") stands in for it.
	if l.z.Apex != "" {
		l.apex = l.z.Apex
		l.apexSet = []string{l.z.Apex}
		return
	}
	for _, r := range l.records {
		if r.Type == "SOA" {
			l.apex = r.Owner
			l.apexSet = []string{r.Owner, "@"}
			return
		}
	}
	l.apex = "@"
	l.apexSet = []string{"@"}
}

// isApex reports whether owner names the zone apex.
func (l *linter) isApex(owner string) bool {
	for _, a := range l.apexSet {
		if strings.EqualFold(owner, a) {
			return true
		}
	}
	return false
}

// insideApex reports whether name lies within the zone origin (used by ZS005
// and ZS013 so that only in-zone targets are flagged).
func (l *linter) insideApex(name string) bool {
	if l.z.Apex == "" {
		return false
	}
	n := strings.ToLower(name)
	a := strings.ToLower(l.z.Apex)
	return n == a || strings.HasSuffix(n, "."+a)
}

// hasRecordsAt reports whether any record exists for the given name.
func (l *linter) hasRecordsAt(name string) bool {
	return len(l.byOwner[strings.ToLower(name)]) > 0
}

// hasAddressAt reports whether an A or AAAA record exists for the name.
func (l *linter) hasAddressAt(name string) bool {
	for _, r := range l.byOwner[strings.ToLower(name)] {
		if r.Type == "A" || r.Type == "AAAA" {
			return true
		}
	}
	return false
}

func (l *linter) add(code string, line int, owner, format string, args ...any) {
	l.findings = append(l.findings, zone.Finding{
		Code:    code,
		Line:    line,
		Owner:   owner,
		Message: fmt.Sprintf(format, args...),
	})
}

// ruleSOA implements ZS001.
func (l *linter) ruleSOA() {
	for _, r := range l.records {
		if r.Type == "SOA" && l.isApex(r.Owner) {
			return
		}
	}
	l.add("ZS001", 1, l.apex, "no SOA record found at the zone apex %q", l.apex)
}

// ruleNS implements ZS002.
func (l *linter) ruleNS() {
	for _, r := range l.records {
		if r.Type == "NS" && l.isApex(r.Owner) {
			return
		}
	}
	l.add("ZS002", 1, l.apex, "no NS record found at the zone apex %q", l.apex)
}

// ruleCNAMECoexist implements ZS003.
func (l *linter) ruleCNAMECoexist() {
	for _, recs := range l.byOwner {
		var cnames, others []*zone.Record
		distinctCNAME := false
		seenTarget := map[string]bool{}
		for _, r := range recs {
			if r.Type == "CNAME" {
				cnames = append(cnames, r)
				t := strings.ToLower(r.RDataText)
				if seenTarget[t] {
					distinctCNAME = true
				}
				seenTarget[t] = true
			} else {
				others = append(others, r)
			}
		}
		if len(cnames) == 0 {
			continue
		}
		first := cnames[0]
		if len(others) > 0 {
			kinds := map[string]bool{}
			for _, o := range others {
				kinds[o.Type] = true
			}
			var list []string
			for k := range kinds {
				list = append(list, k)
			}
			sort.Strings(list)
			l.add("ZS003", first.Line, first.Owner,
				"CNAME at %q coexists with %s record(s) (RFC 2181 section 10.1)",
				first.Owner, strings.Join(list, ", "))
			continue
		}
		if len(cnames) > 1 && distinctCNAME {
			l.add("ZS003", first.Line, first.Owner,
				"multiple different CNAME records at %q (RFC 2181 section 10.1)", first.Owner)
		}
	}
}

// ruleCNAMELoop implements ZS004.
func (l *linter) ruleCNAMELoop() {
	// First CNAME record per owner, in file order.
	type node struct {
		owner  string
		target string
		line   int
		orig   string
	}
	var nodes []*node
	targetOf := map[string]*node{}
	for _, r := range l.records {
		if r.Type != "CNAME" {
			continue
		}
		key := strings.ToLower(r.Owner)
		if _, dup := targetOf[key]; dup {
			continue
		}
		n := &node{owner: key, target: strings.ToLower(r.RData.(*zone.CNAMEData).Target), line: r.Line, orig: r.Owner}
		targetOf[key] = n
		nodes = append(nodes, n)
	}

	reported := map[string]bool{}
	cycleKey := func(members []*node) string {
		var names []string
		for _, n := range members {
			names = append(names, n.owner)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	for _, start := range nodes {
		seen := map[string]*node{}
		var path []*node
		cur := start
		for cur != nil {
			if at, ok := seen[cur.owner]; ok {
				// Cycle found. Cycle members start at `at` in path.
				idx := 0
				for i, n := range path {
					if n == at {
						idx = i
						break
					}
				}
				members := path[idx:]
				key := cycleKey(members)
				if !reported[key] {
					reported[key] = true
					var b strings.Builder
					for i, n := range members {
						if i > 0 {
							b.WriteString(" -> ")
						}
						b.WriteString(n.orig)
					}
					b.WriteString(" -> ")
					b.WriteString(members[0].orig)
					l.add("ZS004", at.line, at.orig, "CNAME loop detected: %s", b.String())
				}
				break
			}
			seen[cur.owner] = cur
			path = append(path, cur)
			cur = targetOf[cur.target]
		}
	}
}

// ruleCNAMEDangling implements ZS005.
func (l *linter) ruleCNAMEDangling() {
	for _, r := range l.records {
		if r.Type != "CNAME" {
			continue
		}
		target := r.RData.(*zone.CNAMEData).Target
		if !l.insideApex(target) {
			continue
		}
		if !l.hasRecordsAt(target) {
			l.add("ZS005", r.Line, r.Owner,
				"CNAME target %q is inside the zone but has no records", target)
		}
	}
}

// ruleDuplicates implements ZS006.
func (l *linter) ruleDuplicates() {
	seen := map[string]int{}
	for _, r := range l.records {
		key := strings.ToLower(r.Owner) + "|" + r.Class + "|" + r.Type + "|" + strings.ToLower(r.RDataText) + "|" + fmt.Sprint(r.TTL)
		if first, ok := seen[key]; ok {
			l.add("ZS006", r.Line, r.Owner,
				"duplicate of the identical record on line %d (%s %s %s)", first, r.Owner, r.Type, r.RDataText)
			continue
		}
		seen[key] = r.Line
	}
}

// ruleBadIP implements ZS008.
func (l *linter) ruleBadIP() {
	for _, r := range l.records {
		switch r.Type {
		case "A":
			addr, err := netip.ParseAddr(r.RData.(*zone.AData).Address)
			if err != nil || !addr.Is4() {
				l.add("ZS008", r.Line, r.Owner, "A record %q is not a valid IPv4 address literal", r.RData.(*zone.AData).Address)
			}
		case "AAAA":
			addr, err := netip.ParseAddr(r.RData.(*zone.AAAAData).Address)
			if err != nil || addr.Is4() {
				l.add("ZS008", r.Line, r.Owner, "AAAA record %q is not a valid IPv6 address literal", r.RData.(*zone.AAAAData).Address)
			}
		}
	}
}

// ruleSRV implements ZS009.
func (l *linter) ruleSRV() {
	for _, r := range l.records {
		if r.Type != "SRV" {
			continue
		}
		d := r.RData.(*zone.SRVData)
		if d.Err != "" {
			l.add("ZS009", r.Line, r.Owner, "%s", d.Err)
		}
	}
}

// ruleMissingTTL implements ZS010.
func (l *linter) ruleMissingTTL() {
	if l.z.HasTTLDirective {
		return
	}
	fallback := uint32(0)
	for _, r := range l.records {
		if r.Type == "SOA" {
			fallback = r.RData.(*zone.SOAData).Minimum
			break
		}
	}
	l.add("ZS010", 1, l.apex,
		"no $TTL directive; records without an explicit TTL fall back to the SOA minimum (%d seconds)", fallback)
}

// ruleTTLInconsistent implements ZS011.
func (l *linter) ruleTTLInconsistent() {
	for _, recs := range l.byOwner {
		if len(recs) < 2 {
			continue
		}
		first := recs[0]
		var offender *zone.Record
		ttls := map[uint32]bool{first.TTL: true}
		for _, r := range recs[1:] {
			ttls[r.TTL] = true
			if offender == nil && r.TTL != first.TTL {
				offender = r
			}
		}
		if len(ttls) < 2 {
			continue
		}
		var vals []uint32
		for v := range ttls {
			vals = append(vals, v)
		}
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		var s []string
		for _, v := range vals {
			s = append(s, fmt.Sprint(v))
		}
		line := first.Line
		if offender != nil {
			line = offender.Line
		}
		l.add("ZS011", line, first.Owner,
			"inconsistent TTLs at %q: %s seconds", first.Owner, strings.Join(s, ", "))
	}
}

// ruleNoApexAddress implements ZS012.
func (l *linter) ruleNoApexAddress() {
	for _, r := range l.records {
		if (r.Type == "A" || r.Type == "AAAA") && l.isApex(r.Owner) {
			return
		}
	}
	l.add("ZS012", 1, l.apex, "zone apex %q has no A or AAAA record", l.apex)
}

// ruleMXExchange implements ZS013.
func (l *linter) ruleMXExchange() {
	for _, r := range l.records {
		if r.Type != "MX" {
			continue
		}
		ex := r.RData.(*zone.MXData).Exchange
		if !l.insideApex(ex) {
			continue
		}
		if !l.hasAddressAt(ex) {
			l.add("ZS013", r.Line, r.Owner, "MX exchange %q is inside the zone but has no A or AAAA record", ex)
		}
	}
}

// ruleTXTLong implements ZS014.
func (l *linter) ruleTXTLong() {
	for _, r := range l.records {
		if r.Type != "TXT" {
			continue
		}
		d := r.RData.(*zone.TXTData)
		for i, seg := range d.Segments {
			if len(seg) > 255 {
				l.add("ZS014", r.Line, r.Owner,
					"TXT segment %d is %d octets (limit 255)", i+1, len(seg))
				break
			}
		}
	}
}

// ruleWildcardShadow implements ZS015.
func (l *linter) ruleWildcardShadow() {
	// Group explicit children by their parent domain.
	children := map[string][]string{} // parent -> explicit owners (file order, unique)
	seenChild := map[string]bool{}
	for _, r := range l.records {
		o := strings.ToLower(r.Owner)
		if strings.HasPrefix(o, "*.") || o == "*" {
			continue
		}
		dot := strings.Index(o, ".")
		if dot < 0 {
			continue
		}
		parent := o[dot+1:]
		if seenChild[parent+"|"+o] {
			continue
		}
		seenChild[parent+"|"+o] = true
		children[parent] = append(children[parent], r.Owner)
	}

	seen := map[string]bool{}
	for _, r := range l.records {
		o := strings.ToLower(r.Owner)
		if o == "*" {
			continue
		}
		if !strings.HasPrefix(o, "*.") {
			continue
		}
		parent := o[2:]
		if seen[parent] {
			continue
		}
		kids := children[parent]
		if len(kids) == 0 {
			continue
		}
		seen[parent] = true
		shown := kids
		extra := ""
		if len(kids) > 3 {
			shown = kids[:3]
			extra = fmt.Sprintf(" (+%d more)", len(kids)-3)
		}
		l.add("ZS015", r.Line, r.Owner,
			"wildcard %q is shadowed for explicit name(s) under %q: %s%s", r.Owner, parent, strings.Join(shown, ", "), extra)
	}
}

// ruleTTLMax implements ZS016.
func (l *linter) ruleTTLMax() {
	max := l.cfg.EffectiveMaxTTL()
	for _, r := range l.records {
		if r.TTL > max {
			l.add("ZS016", r.Line, r.Owner, "TTL %d at %q exceeds the maximum %d", r.TTL, r.Owner, max)
		}
	}
}

// ruleNoSPF implements ZS018.
func (l *linter) ruleNoSPF() {
	spf := false
	for _, r := range l.byOwner[strings.ToLower(l.apex)] {
		if r.Type != "TXT" {
			continue
		}
		for _, seg := range r.RData.(*zone.TXTData).Segments {
			if strings.HasPrefix(strings.ToLower(seg), "v=spf1") {
				spf = true
			}
		}
	}
	dmarcOwner := "_dmarc." + l.apex
	dmarc := false
	for _, r := range l.byOwner[strings.ToLower(dmarcOwner)] {
		if r.Type == "TXT" {
			dmarc = true
		}
	}
	if spf && dmarc {
		return
	}
	var missing []string
	if !spf {
		missing = append(missing, "SPF TXT at the apex (v=spf1)")
	}
	if !dmarc {
		missing = append(missing, "DMARC TXT at "+dmarcOwner)
	}
	l.add("ZS018", 1, l.apex, "zone has no %s", strings.Join(missing, " and no "))
}
