// Package redact replaces personal details with stable placeholders, so a
// timeline can be pasted into an issue and related rows still line up:
// the home folder becomes ~, the user USER, host names HOST-1, UUIDs
// UUID-1, IP addresses IP-1, e-mail addresses EMAIL-1, and URLs keep only
// their domain.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Identity is what to look for.
type Identity struct {
	Home     string
	User     string
	FullName string
	Hosts    []string // host, computer and local host names
	Serial   string
}

// Redactor is safe for concurrent use. A nil *Redactor leaves text alone.
type Redactor struct {
	id      Identity
	words   []string // exact strings to replace, longest first
	mu      sync.Mutex
	seen    map[string]string
	counter map[string]int
}

var (
	uuidRe  = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	ipv4Re  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re  = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b`)
	emailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	macRe   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b`)
	urlRe   = regexp.MustCompile(`\b(https?)://([^/\s'"]+)(/[^\s'"]*)?`)
	usersRe = regexp.MustCompile(`/Users/[^/\s'"]+`)
)

// New builds a redactor.
func New(id Identity) *Redactor {
	r := &Redactor{id: id, seen: map[string]string{}, counter: map[string]int{}}
	for _, w := range append([]string{id.FullName, id.Serial}, id.Hosts...) {
		if len(w) >= 3 {
			r.words = append(r.words, w)
		}
	}
	sort.Slice(r.words, func(i, j int) bool { return len(r.words[i]) > len(r.words[j]) })
	return r
}

// String redacts one string.
func (r *Redactor) String(s string) string {
	if r == nil || s == "" {
		return s
	}
	if r.id.Home != "" && r.id.Home != "/" {
		s = strings.ReplaceAll(s, r.id.Home, "~")
	}
	s = usersRe.ReplaceAllStringFunc(s, func(m string) string {
		if m == "/Users/Shared" {
			return m
		}
		return "/Users/USER"
	})
	for _, w := range r.words {
		label := "HOST"
		switch w {
		case r.id.Serial:
			label = "SERIAL"
		case r.id.FullName:
			label = "NAME"
		}
		if strings.Contains(s, w) {
			s = strings.ReplaceAll(s, w, r.token(label, w))
		}
	}
	if len(r.id.User) >= 3 {
		s = wordRe(r.id.User).ReplaceAllString(s, "USER")
	}
	s = urlRe.ReplaceAllStringFunc(s, func(m string) string {
		p := urlRe.FindStringSubmatch(m)
		if p[3] == "" || p[3] == "/" {
			return m
		}
		return p[1] + "://" + p[2] + "/…"
	})
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string { return r.token("EMAIL", m) })
	s = uuidRe.ReplaceAllStringFunc(s, func(m string) string { return r.token("UUID", strings.ToUpper(m)) })
	s = macRe.ReplaceAllStringFunc(s, func(m string) string { return r.token("MAC", strings.ToLower(m)) })
	s = r.ipv4(s)
	s = ipv6Re.ReplaceAllStringFunc(s, func(m string) string {
		if !strings.Contains(m, "::") && strings.Count(m, ":") < 4 {
			return m // times such as 12:04:05 are not addresses
		}
		return r.token("IP", strings.ToLower(m))
	})
	return s
}

var wordCache sync.Map

func wordRe(w string) *regexp.Regexp {
	if v, ok := wordCache.Load(w); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(w) + `\b`)
	wordCache.Store(w, re)
	return re
}

func (r *Redactor) token(label, value string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := label + "\x00" + value
	if t, ok := r.seen[k]; ok {
		return t
	}
	r.counter[label]++
	t := fmt.Sprintf("%s-%d", label, r.counter[label])
	r.seen[k] = t
	return t
}

// Map redacts every value of a map in place.
func (r *Redactor) Map(m map[string]string) {
	if r == nil {
		return
	}
	for k, v := range m {
		m[k] = r.String(v)
	}
}

// ipv4 replaces dotted quads that stand alone, so version strings such as
// 1.0.0.0.17 survive.
func (r *Redactor) ipv4(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range ipv4Re.FindAllStringIndex(s, -1) {
		i, j := loc[0], loc[1]
		m := s[i:j]
		if (i > 0 && s[i-1] == '.') || (j < len(s) && s[j] == '.' && j+1 < len(s) && s[j+1] >= '0' && s[j+1] <= '9') ||
			m == "127.0.0.1" || m == "0.0.0.0" || !octets(m) {
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(r.token("IP", m))
		last = j
	}
	b.WriteString(s[last:])
	return b.String()
}

func octets(ip string) bool {
	for _, p := range strings.Split(ip, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
