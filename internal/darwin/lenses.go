package darwin

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

// --- RunningBoard: "Now tracking process: [app<application.com.foo.12.34(501)>:4242]"

var (
	rbApp    = regexp.MustCompile(`^app<application\.(.+?)\.\d+\.\d+\(\d+\)>`)
	rbAnon   = regexp.MustCompile(`^anon<(.+?)>\(\d+\)`)
	rbNamed  = regexp.MustCompile(`^(xpcservice|osservice|extension|daemon)<([^(\[<>]+)`)
	rbHost   = regexp.MustCompile(`app<application\.(.+?)\.\d+\.\d+\(\d+\)>`)
	rbPIDEnd = regexp.MustCompile(`:(\d+)\]$`)
)

func parseLaunch(r Record, emit func(event.Event)) {
	msg := strings.TrimPrefix(r.EventMessage, "Now tracking process: ")
	if msg == r.EventMessage || !strings.HasPrefix(msg, "[") {
		return
	}
	e, ok := newEvent(r, event.KindLaunch)
	if !ok {
		return
	}
	ident := msg[1:]
	if m := rbPIDEnd.FindStringSubmatch(msg); m != nil {
		e.Subject.PID, _ = strconv.Atoi(m[1])
	}
	switch {
	case rbApp.MatchString(ident):
		e.Subject.BundleID = rbApp.FindStringSubmatch(ident)[1]
		e.Set("identity", "app")
	case rbAnon.MatchString(ident):
		e.Subject.Name = rbAnon.FindStringSubmatch(ident)[1]
		e.Set("identity", "anon")
	case rbNamed.MatchString(ident):
		m := rbNamed.FindStringSubmatch(ident)
		e.Subject.BundleID = m[2]
		e.Set("identity", m[1])
		if h := rbHost.FindStringSubmatch(ident[len(m[0]):]); h != nil {
			e.Subject.Responsible = h[1]
		}
	default:
		e.Set("identity", "unknown")
		e.Subject.Name = ident
	}
	emit(e)
}

// --- TCC: one decision is spread over AUTHREQ_CTX, _ATTRIBUTION and _RESULT
// lines that share a msgID.

var (
	tccMsgID   = regexp.MustCompile(`msgID=([^,\s]+)`)
	tccService = regexp.MustCompile(`service=(kTCCService\w+)`)
	tccReqID   = regexp.MustCompile(`requesting=\{TCCDProcess: identifier=([^,]+), pid=(\d+)[^}]*?binary_path=([^}]+)\}`)
	tccRespID  = regexp.MustCompile(`responsible=\{TCCDProcess: identifier=([^,]+),`)
	tccResult  = regexp.MustCompile(`authValue=(\d+), authReason=(\d+)`)
)

// TCCServices maps service names to what System Settings calls them.
var TCCServices = map[string]string{
	"kTCCServiceAccessibility":                "Accessibility",
	"kTCCServiceScreenCapture":                "Screen Recording",
	"kTCCServiceSystemPolicyAllFiles":         "Full Disk Access",
	"kTCCServiceListenEvent":                  "Input Monitoring",
	"kTCCServicePostEvent":                    "Accessibility (send keystrokes)",
	"kTCCServiceDeveloperTool":                "Developer Tools",
	"kTCCServiceEndpointSecurityClient":       "Endpoint Security",
	"kTCCServiceMicrophone":                   "Microphone",
	"kTCCServiceCamera":                       "Camera",
	"kTCCServiceAppleEvents":                  "Automation",
	"kTCCServiceAddressBook":                  "Contacts",
	"kTCCServiceCalendar":                     "Calendars",
	"kTCCServiceReminders":                    "Reminders",
	"kTCCServicePhotos":                       "Photos",
	"kTCCServiceSystemPolicyDesktopFolder":    "Desktop folder",
	"kTCCServiceSystemPolicyDocumentsFolder":  "Documents folder",
	"kTCCServiceSystemPolicyDownloadsFolder":  "Downloads folder",
	"kTCCServiceSystemPolicyNetworkVolumes":   "Network volumes",
	"kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
	"kTCCServiceBluetoothAlways":              "Bluetooth",
	"kTCCServiceLocation":                     "Location",
}

// powerfulTCC are the grants that let an app watch or control the Mac.
var powerfulTCC = map[string]bool{
	"kTCCServiceAccessibility": true, "kTCCServiceScreenCapture": true,
	"kTCCServiceSystemPolicyAllFiles": true, "kTCCServiceListenEvent": true,
	"kTCCServicePostEvent": true, "kTCCServiceEndpointSecurityClient": true,
}

// Auth reasons that mean a person decided (answered a prompt or flipped a
// switch). Entitlement, policy and preflight checks are thousands a day and
// carry no news.
var tccUserReasons = map[string]string{"2": "answered a prompt", "3": "set in System Settings"}

var tccValues = map[string]string{"0": "denied", "1": "unknown", "2": "allowed", "3": "limited"}

type tccReq struct {
	service, client, pid, path, responsible string
}

func newTCCParser() parser {
	reqs := map[string]*tccReq{}
	return func(r Record, emit func(event.Event)) {
		m := tccMsgID.FindStringSubmatch(r.EventMessage)
		if m == nil {
			return
		}
		id := m[1]
		q := reqs[id]
		if q == nil {
			q = &tccReq{}
			reqs[id] = q
		}
		msg := r.EventMessage
		switch {
		case strings.HasPrefix(msg, "AUTHREQ_CTX"):
			if s := tccService.FindStringSubmatch(msg); s != nil {
				q.service = s[1]
			}
		case strings.HasPrefix(msg, "AUTHREQ_ATTRIBUTION"):
			if s := tccReqID.FindStringSubmatch(msg); s != nil {
				q.client, q.pid, q.path = s[1], s[2], strings.TrimSpace(s[3])
			}
			if s := tccRespID.FindStringSubmatch(msg); s != nil {
				q.responsible = s[1]
			}
		case strings.HasPrefix(msg, "AUTHREQ_RESULT"):
			delete(reqs, id)
			s := tccResult.FindStringSubmatch(msg)
			if s == nil {
				return
			}
			why, ok := tccUserReasons[s[2]]
			if !ok {
				return
			}
			e, ok := newEvent(r, event.KindPermit)
			if !ok {
				return
			}
			e.Subject = event.Subject{BundleID: q.client, Path: q.path, Responsible: q.responsible}
			e.Subject.PID, _ = strconv.Atoi(q.pid)
			e.Set("service", q.service)
			e.Set("service_name", tccName(q.service))
			e.Set("decision", tccValues[s[1]])
			e.Set("how", why)
			if powerfulTCC[q.service] {
				e.Set("powerful", "yes")
			}
			emit(e)
		}
	}
}

func tccName(s string) string {
	if n, ok := TCCServices[s]; ok {
		return n
	}
	if s == "" {
		return "an unknown permission"
	}
	return strings.TrimPrefix(s, "kTCCService")
}

// --- Gatekeeper: "GK evaluateScanResult: 2, PST: (path: …), (team: X), (id: Y), (bundle_id: Z), …"

var gkScan = regexp.MustCompile(`^GK evaluateScanResult: (\d+), PST: \(path: [^)]*\), \(team: ([^)]*)\), \(id: ([^)]*)\), \(bundle_id: ([^)]*)\)`)

func parseGatekeeper(r Record, emit func(event.Event)) {
	m := gkScan.FindStringSubmatch(r.EventMessage)
	if m == nil {
		return
	}
	team, id, bundle := nullable(m[2]), nullable(m[3]), nullable(m[4])
	if id == "" && bundle == "" {
		return // anonymous scans carry nothing a person could act on
	}
	e, ok := newEvent(r, event.KindGatekeeper)
	if !ok {
		return
	}
	if bundle == "NOT_A_BUNDLE" {
		bundle = ""
	}
	e.Subject = event.Subject{Name: id, BundleID: bundle, TeamID: team}
	if team == "" {
		e.Set("unsigned_team", "yes")
	}
	e.Set("scan_result", m[1])
	emit(e)
}

func nullable(s string) string {
	if s == "(null)" {
		return ""
	}
	return s
}

// --- XProtect Remediator: structured JSON per plugin run.

type xpEvent struct {
	StatusMessage string `json:"status_message"`
	StatusCode    *int   `json:"status_code"`
}

var xpQuiet = map[string]bool{"Success": true, "NoThreatDetected": true}

func parseXProtect(r Record, emit func(event.Event)) {
	var x xpEvent
	if err := json.Unmarshal([]byte(r.EventMessage), &x); err != nil || x.StatusMessage == "" {
		e, ok := newEvent(r, event.KindMalware)
		if !ok {
			return
		}
		e.Set("status", "unreadable")
		emit(e) // unknown format: surface it, never drop it
		return
	}
	if xpQuiet[x.StatusMessage] {
		return
	}
	e, ok := newEvent(r, event.KindMalware)
	if !ok {
		return
	}
	e.Subject = event.Subject{Name: "XProtect Remediator", Signer: event.SignerApple}
	e.Set("status", x.StatusMessage)
	lower := strings.ToLower(x.StatusMessage)
	if !strings.Contains(lower, "nothreat") && (strings.Contains(lower, "threat") || strings.Contains(lower, "detect") || strings.Contains(lower, "remediat")) {
		e.Set("threat", "yes")
	}
	emit(e)
}

// --- Background Task Management: registration lines that name the item.

var btmItem = regexp.MustCompile(`name=([^,]*), type=([^,]*), disposition=\[([^\]]*)\], identifier=([^,]*), url=(.*)$`)

func parseBTM(r Record, emit func(event.Event)) {
	msg := r.EventMessage
	m := btmItem.FindStringSubmatch(msg)
	if m == nil {
		return // the request lines before it only carry <private> URLs
	}
	if strings.Contains(msg, "checking for an updated legacy") {
		return // repeats the "found existing" line
	}
	e, ok := newEvent(r, event.KindPersist)
	if !ok {
		return
	}
	id := m[4]
	if i := strings.IndexByte(id, '.'); i > 0 && isDigits(id[:i]) {
		id = id[i+1:] // BTM prefixes identifiers with a numeric type
	}
	e.Subject = event.Subject{Name: m[1], BundleID: id, Path: btmPath(m[5])}
	e.Set("persist", "login_item")
	e.Set("btm_type", m[2])
	e.Set("disposition", m[3])
	switch {
	case strings.HasPrefix(msg, "unregister"):
		e.Set("change", "removed")
	case strings.Contains(msg, "found existing"):
		e.Set("change", "existing")
	default:
		e.Set("change", "added")
	}
	emit(e)
}

// btmPath turns "file:///Users/x/Library/LaunchAgents/a.plist" or
// "Contents/PlugIns/X.plugin -- file:///Applications/X.app/" into a path.
func btmPath(u string) string {
	if i := strings.Index(u, " -- "); i >= 0 {
		rel, base := u[:i], strings.TrimPrefix(u[i+4:], "file://")
		return strings.TrimSuffix(base, "/") + "/" + rel
	}
	return strings.TrimSuffix(strings.TrimPrefix(u, "file://"), "/")
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// --- DumpPanic and the pre-OS log. DumpPanic runs after every boot and
// says what it found. Only unambiguous wording counts: "paniclog" alone
// also appears in "No paniclog data found".

var (
	breadcrumbWrite = regexp.MustCompile(`= "([^"]*)";\s*\} to /var/db/com\.apple\.DumpPanic\.panicLogPathBreadcrumb`)
	bootFaults      = regexp.MustCompile(`(?s)boot faults: \((.*?)\)`)
)

func parsePanicLog(r Record, emit func(event.Event)) {
	msg := r.EventMessage
	evidence, detail := "", ""
	switch {
	case breadcrumbWrite.MatchString(msg):
		if p := breadcrumbWrite.FindStringSubmatch(msg)[1]; p != "" {
			evidence, detail = "panic", "panic log saved to "+p
		} else {
			evidence = "no_panic"
		}
	case strings.Contains(msg, "No paniclog data found") || strings.Contains(msg, "did not contain any paniclog data"):
		evidence = "no_panic"
	case strings.Contains(msg, "panic(cpu") || strings.Contains(msg, "Kernel panic"):
		evidence, detail = "panic", shorten(msg, 120)
	case bootFaults.MatchString(msg) && strings.Contains(bootFaults.FindStringSubmatch(msg)[1], "wdog"):
		evidence, detail = "watchdog", "boot fault data records a watchdog reset (wdog)"
	default:
		return // DumpPanic narrating its checks
	}
	e, ok := newEvent(r, event.KindPanic)
	if !ok {
		return
	}
	e.Subject = event.Subject{Name: "kernel", Signer: event.SignerApple}
	e.Set("evidence", evidence)
	e.Set("detail", detail)
	emit(e)
}

// --- Kernel: jetsam kills and (Intel only) the previous shutdown cause.

var shutdownCause = regexp.MustCompile(`[Pp]revious shutdown cause: (-?\d+)`)

func parseKernel(r Record, emit func(event.Event)) {
	msg := r.EventMessage
	if m := shutdownCause.FindStringSubmatch(msg); m != nil {
		e, ok := newEvent(r, event.KindBoot)
		if !ok {
			return
		}
		e.Subject = event.Subject{Name: "kernel", Signer: event.SignerApple}
		e.Set("shutdown_cause", m[1])
		emit(e)
		return
	}
	if strings.Contains(msg, "memorystatus: kill") {
		e, ok := newEvent(r, event.KindCrash)
		if !ok {
			return
		}
		e.Subject = event.Subject{Name: jetsamVictim(msg)}
		e.Set("report_kind", "jetsam")
		emit(e)
	}
}

// jetsamVictim pulls the process name out of a kill line such as
// "memorystatus: killing_specific_process pid 123 [Foo] (vm-pageshortage …)".
func jetsamVictim(msg string) string {
	if i := strings.IndexByte(msg, '['); i >= 0 {
		if j := strings.IndexByte(msg[i:], ']'); j > 0 {
			return msg[i+1 : i+j]
		}
	}
	return "a process"
}

// --- `log` records its own invocations: "log run noninteractively, parent:
// 123 (zsh), args: 'log' 'erase' '--all'".

var (
	logRun = regexp.MustCompile(`^log run \w+, parent: (\d+) \(([^)]*)\), args: (.*)$`)
	// argv[0] can be anything (a copy, exec -a); the subcommand is argv[1].
	logEraseArgs = regexp.MustCompile(`^'[^']*' 'erase'`)
)

func parseLogErase(r Record, emit func(event.Event)) {
	m := logRun.FindStringSubmatch(r.EventMessage)
	if m == nil {
		return
	}
	args := m[3]
	if !logEraseArgs.MatchString(args) {
		return // lately's own queries mention "erase" only inside the predicate
	}
	if m[1] == strconv.Itoa(os.Getpid()) {
		return
	}
	e, ok := newEvent(r, event.KindLog)
	if !ok {
		return
	}
	e.Subject = event.Subject{Name: m[2], PID: atoi(m[1])}
	e.Set("action", "erase")
	e.Set("args", args)
	emit(e)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
