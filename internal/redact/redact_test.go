package redact

import "testing"

func TestString(t *testing.T) {
	r := New(Identity{Home: "/Users/alice", User: "alice", FullName: "Alice Liddell", Hosts: []string{"Alices-MBP.local", "Alices-MBP"}, Serial: "C02ABC123"})
	cases := map[string]string{
		"/Users/alice/Library/LaunchAgents/x.plist": "~/Library/LaunchAgents/x.plist",
		"file:///Users/bob/x":                       "file:///Users/USER/x",
		"/Users/Shared/x":                           "/Users/Shared/x",
		"2026-10-27 Alices-MBP Safari[1]: by alice": "2026-10-27 HOST-1 Safari[1]: by USER",
		"serial C02ABC123, Alice Liddell":           "serial SERIAL-1, NAME-1",
		"uuid=1B4E28BA-2FA1-11D2-883F-0016D3CCA427 again 1b4e28ba-2fa1-11d2-883f-0016d3cca427": "uuid=UUID-1 again UUID-1",
		"10.0.0.2:5000->1.2.3.4:443 and 10.0.0.2":                                              "IP-1:5000->IP-2:443 and IP-1",
		"version=1.0.0.0.1775460258 at 12:04:05":                                               "version=1.0.0.0.1775460258 at 12:04:05",
		"get https://example.com/a/b?c=d now":                                                  "get https://example.com/… now",
		"mail someone@example.org":                                                             "mail EMAIL-1",
		"aliceberg stays":                                                                      "aliceberg stays",
	}
	for in, want := range cases {
		if got := r.String(in); got != want {
			t.Errorf("%q\n got %q\nwant %q", in, got, want)
		}
	}
	var nilR *Redactor
	if nilR.String("/Users/alice") != "/Users/alice" {
		t.Error("nil redactor must pass text through")
	}
}
