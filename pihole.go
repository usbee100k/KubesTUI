package main

// Pi-hole (v6 API) for the SOC console's DNS page: what every device on
// the network looks up, what gets blocked, and detections in the lookups
// (random-looking domains, DNS tunnels, crypto-mining pools, tunnel and
// remote-access services, encrypted DNS that bypasses the Pi-hole).
//
// The address and password (an app password is best: it can't change
// settings unless app_sudo is on, and it can be revoked) are kept in
// ~/.kubestui/network/pihole.json, readable only by this user. The Pi-hole's
// own certificate is self-signed, so its fingerprint is remembered on the
// first connect; if it ever changes the password isn't sent.
//
// One login session is kept and reused, and logged out when the SOC
// console closes (Pi-hole allows only a few sessions at a time).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type piholeConf struct {
	URL      string `json:"url"`
	Password string `json:"password"`
	CertSHA  string `json:"certSHA256,omitempty"` // pinned on the first connect (https)
}

type phCount struct {
	Name  string
	Count int
}

type phQuery struct {
	ID     int64   `json:"id"`
	Time   float64 `json:"time"`
	Type   string  `json:"type"`
	Domain string  `json:"domain"`
	Status string  `json:"status"`
	Client struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	} `json:"client"`
	Reply struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
	Upstream string `json:"upstream"`
}

func (q phQuery) at() time.Time {
	s, f := math.Modf(q.Time)
	return time.Unix(int64(s), int64(f*1e9))
}

// phBlocked: the statuses that mean the Pi-hole (or its upstream) blocked it.
func phBlocked(status string) bool {
	switch status {
	case "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN",
		"EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE", "DBBUSY":
		return true
	}
	return false
}

// phClient: one device as the Pi-hole sees it.
type phClient struct {
	IP, Name, MAC, Vendor string
	Total, Blocked        int // last 24 hours (Pi-hole's top clients)
	Hour, HourBlocked     int // last hour (the query log)
	NX                    int // NXDOMAIN answers in the last hour
	Last                  time.Time
	Domains               []phCount // most looked up, last hour
	BlockedDomains        []phCount
}

// phDetection: something suspicious in the lookups.
type phDetection struct {
	Kind     string // dga, tunnel, mining, tunnelsvc, remote, doh
	Client   string // IP
	Name     string // client name
	Domain   string // the domains (watch list), the base domain (tunnel)
	Count    int
	Blocked  int // of Count, blocked by the Pi-hole
	Examples []string
	Last     time.Time
}

type phHost struct {
	Host, Want, Got string // Pi-hole's answer for an ingress host vs the ingress IP
	Record          string // the local record behind the answer ("" = forwarded)
	Err             string
}

type phView struct {
	Configured bool
	Found      string // a Pi-hole on one of this computer's DNS servers (not configured yet)
	URL        string
	OK         bool
	Err        string
	At         time.Time
	Version    string
	Update     string // newer version available

	Blocking                       string
	Total, Blocked                 int
	Percent                        float64
	Cached, Forwarded, Unique      int
	Freq                           float64
	ClientsActive, ClientsTotal    int
	Gravity                        int
	GravityAt                      time.Time
	TopDomains, TopBlocked         []phCount
	Upstreams                      []phCount
	Clients                        []*phClient
	Recent                         []phQuery // newest first
	Detections                     []phDetection
	Messages                       []string
	LocalRecords                   []string // "ip host" and "host,target" (CNAME)
	Hosts                          []phHost
	NoDNS                          []string // LAN devices that never asked the Pi-hole (IP)
	CertChanged                    bool
	HourQueries, HourBlocked       int
	HourStart                      time.Time
	QPM                            ccRing // queries per minute (from the query log)
	sudo                           bool   // the session can change settings
	devicesAt, configAt, versionAt time.Time
}

type piholeClient struct {
	mu     sync.Mutex
	v      phView
	conf   piholeConf
	sid    string
	hc     *http.Client
	window map[int64]phQuery // the last hour of the query log
	lastQ  float64
	devs   map[string]phDevice // IP -> network table entry
	path   string
	demo   bool
	stop   chan struct{}
	kick   chan struct{}
	redraw func()
	dnsIPs func() []string // this computer's DNS servers (for discovery)
	sites  func() []ccIngress
	lan    func() []string // online LAN device IPs (for "never asked")
}

type phDevice struct {
	MAC, Vendor, Name string
	NumQueries        int
	LastQuery         time.Time
}

func newPiholeClient(demo bool, redraw func()) *piholeClient {
	p := &piholeClient{demo: demo, redraw: redraw, stop: make(chan struct{}), kick: make(chan struct{}, 1),
		window: map[int64]phQuery{}, devs: map[string]phDevice{}}
	if !demo {
		p.path = filepath.Join(kubestuiDir(), "network", "pihole.json")
		if data, err := os.ReadFile(p.path); err == nil {
			_ = json.Unmarshal(data, &p.conf)
		}
	}
	p.v.Configured = p.conf.URL != ""
	p.v.URL = p.conf.URL
	p.hc = p.httpClient()
	return p
}

// httpClient checks the Pi-hole's certificate against the pinned one.
func (p *piholeClient) httpClient() *http.Client {
	pin := p.conf.CertSHA
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if pin == "" || len(cs.PeerCertificates) == 0 {
				return nil
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != pin {
				return errPinChanged
			}
			return nil
		}},
		Proxy:               nil,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

var errPinChanged = errors.New("the Pi-hole's certificate changed")

func (p *piholeClient) saveConf() error {
	if p.path == "" {
		return nil
	}
	data, _ := json.MarshalIndent(p.conf, "", "  ")
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.path, data, 0o600)
}

func (p *piholeClient) view() phView {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.v
	v.Clients = nil
	for _, c := range p.v.Clients {
		cp := *c
		v.Clients = append(v.Clients, &cp)
	}
	v.Recent = append([]phQuery(nil), p.v.Recent...)
	v.Detections = append([]phDetection(nil), p.v.Detections...)
	v.Hosts = append([]phHost(nil), p.v.Hosts...)
	v.QPM = ccRing{v: append([]float64(nil), p.v.QPM.v...)}
	return v
}

func (p *piholeClient) client(ip string) *phClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.v.Clients {
		if c.IP == ip {
			cp := *c
			return &cp
		}
	}
	return nil
}

// queriesFor: the last hour's lookups of one client, newest first.
func (p *piholeClient) queriesFor(ip string, n int) []phQuery {
	p.mu.Lock()
	var out []phQuery
	for _, q := range p.window {
		if q.Client.IP == ip {
			out = append(out, q)
		}
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Time > out[j].Time })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (p *piholeClient) Start() {
	if p.demo {
		go p.runDemo()
		return
	}
	go p.loop()
}

func (p *piholeClient) Stop() {
	select {
	case <-p.stop:
		return
	default:
		close(p.stop)
	}
	if !p.demo {
		go p.logout()
	}
}

func (p *piholeClient) Kick() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *piholeClient) loop() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for n := 0; ; n++ {
		p.mu.Lock()
		configured := p.conf.URL != ""
		p.mu.Unlock()
		if configured {
			p.poll()
		} else if n%6 == 0 {
			p.discover()
		}
		if p.redraw != nil {
			p.redraw()
		}
		select {
		case <-p.stop:
			return
		case <-p.kick:
		case <-tick.C:
		}
	}
}

// discover looks for a Pi-hole on this computer's DNS servers.
func (p *piholeClient) discover() {
	if p.dnsIPs == nil {
		return
	}
	for _, ip := range p.dnsIPs() {
		if u := probePihole(p.hc, ip); u != "" {
			p.mu.Lock()
			p.v.Found = u
			p.mu.Unlock()
			return
		}
	}
}

// probePihole: the API base of a Pi-hole v6 at host, or "".
func probePihole(hc *http.Client, host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	for _, base := range []string{"https://" + host, "http://" + host} {
		resp, err := hc.Get(base + "/api/info/login")
		if err != nil {
			continue
		}
		var r struct {
			DNS *bool `json:"dns"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
		resp.Body.Close()
		if err == nil && r.DNS != nil {
			return base
		}
	}
	return ""
}

// Connect logs in with a new address and password and remembers them. The
// certificate seen now is pinned.
func (p *piholeClient) Connect(base, password string) error {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	base = strings.TrimSuffix(base, "/admin")
	base = strings.TrimSuffix(base, "/api")
	if !strings.Contains(base, "://") {
		if u := probePihole(p.httpClient(), base); u != "" {
			base = u
		} else {
			base = "https://" + base
		}
	}
	if _, err := url.Parse(base); err != nil {
		return err
	}
	pin := ""
	if strings.HasPrefix(base, "https://") {
		u, _ := url.Parse(base)
		addr := u.Host
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "443")
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return fmt.Errorf("can't reach %s: %s", addr, shortErr(err))
		}
		if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
			sum := sha256.Sum256(certs[0].Raw)
			pin = hex.EncodeToString(sum[:])
		}
		conn.Close()
	}
	old := p.conf
	p.mu.Lock()
	p.conf = piholeConf{URL: base, Password: password, CertSHA: pin}
	p.hc = p.httpClient()
	p.sid = ""
	p.mu.Unlock()
	if err := p.login(); err != nil {
		p.mu.Lock()
		p.conf = old
		p.hc = p.httpClient()
		p.mu.Unlock()
		return err
	}
	p.mu.Lock()
	p.v = phView{Configured: true, URL: base}
	p.window = map[int64]phQuery{}
	p.lastQ = 0
	err := p.saveConf()
	p.mu.Unlock()
	p.Kick()
	return err
}

// Forget logs out and deletes the saved address and password.
func (p *piholeClient) Forget() {
	p.logout()
	p.mu.Lock()
	p.conf = piholeConf{}
	p.v = phView{}
	p.window = map[int64]phQuery{}
	p.mu.Unlock()
	if p.path != "" {
		_ = os.Remove(p.path)
	}
	p.Kick()
}

func (p *piholeClient) login() error {
	p.mu.Lock()
	base, pw, hc := p.conf.URL, p.conf.Password, p.hc
	p.mu.Unlock()
	body, _ := json.Marshal(map[string]string{"password": pw})
	resp, err := hc.Post(base+"/api/auth", "application/json", bytes.NewReader(body))
	if err != nil {
		if errors.Is(err, errPinChanged) {
			p.mu.Lock()
			p.v.CertChanged = true
			p.mu.Unlock()
			return errPinChanged
		}
		return fmt.Errorf("can't reach the Pi-hole: %s", shortErr(err))
	}
	defer resp.Body.Close()
	var r struct {
		Session struct {
			Valid   bool   `json:"valid"`
			TOTP    bool   `json:"totp"`
			SID     string `json:"sid"`
			Message string `json:"message"`
		} `json:"session"`
		Error struct {
			Key, Message, Hint string
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
	if !r.Session.Valid {
		msg := orDefault(r.Error.Message, r.Session.Message)
		switch {
		case r.Error.Key == "bad_request" && strings.Contains(strings.ToLower(r.Error.Hint+r.Error.Message), "totp"),
			r.Session.TOTP && r.Session.SID == "":
			return errors.New("two-factor login is on: use an app password (Settings → Web interface / API → Configure app password)")
		case resp.StatusCode == http.StatusTooManyRequests:
			return errors.New("too many logins: Pi-hole limits sessions; wait a few minutes")
		case msg == "":
			msg = resp.Status
		}
		return errors.New("login refused: " + msg)
	}
	p.mu.Lock()
	p.sid = r.Session.SID
	p.mu.Unlock()
	return nil
}

func (p *piholeClient) logout() {
	p.mu.Lock()
	base, sid, hc := p.conf.URL, p.sid, p.hc
	p.sid = ""
	p.mu.Unlock()
	if base == "" || sid == "" {
		return
	}
	req, _ := http.NewRequest(http.MethodDelete, base+"/api/auth", nil)
	req.Header.Set("X-FTL-SID", sid)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := hc.Do(req.WithContext(ctx)); err == nil {
		resp.Body.Close()
	}
}

var errForbidden = errors.New("forbidden")

// call does one API request (logging in again once if the session expired).
func (p *piholeClient) call(method, path string, out any) error {
	for try := 0; try < 2; try++ {
		p.mu.Lock()
		base, sid, hc := p.conf.URL, p.sid, p.hc
		p.mu.Unlock()
		if sid == "" && try == 0 {
			if err := p.login(); err != nil {
				return err
			}
			continue
		}
		req, err := http.NewRequest(method, base+"/api"+path, nil)
		if err != nil {
			return err
		}
		if sid != "" {
			req.Header.Set("X-FTL-SID", sid)
		}
		resp, err := hc.Do(req)
		if err != nil {
			if errors.Is(err, errPinChanged) {
				p.mu.Lock()
				p.v.CertChanged = true
				p.mu.Unlock()
				return errPinChanged
			}
			return fmt.Errorf("can't reach the Pi-hole: %s", shortErr(err))
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusUnauthorized && try == 0:
			p.mu.Lock()
			p.sid = ""
			p.mu.Unlock()
			if err := p.login(); err != nil {
				return err
			}
			continue
		case resp.StatusCode == http.StatusForbidden:
			return errForbidden
		case resp.StatusCode >= 300:
			var e struct {
				Error struct{ Message, Hint string } `json:"error"`
			}
			_ = json.Unmarshal(data, &e)
			return fmt.Errorf("%s %s: %s %s", method, path, orDefault(e.Error.Message, resp.Status), e.Error.Hint)
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
	return errors.New("not logged in")
}

func (p *piholeClient) poll() {
	var errs []string
	note := func(err error) {
		if err != nil && !contains(errs, err.Error()) {
			errs = append(errs, err.Error())
		}
	}
	var sum struct {
		Queries struct {
			Total, Blocked, Cached, Forwarded int
			Percent                           float64 `json:"percent_blocked"`
			Unique                            int     `json:"unique_domains"`
			Frequency                         float64
		}
		Clients struct{ Active, Total int }
		Gravity struct {
			Domains    int   `json:"domains_being_blocked"`
			LastUpdate int64 `json:"last_update"`
		}
	}
	if err := p.call("GET", "/stats/summary", &sum); err != nil {
		p.mu.Lock()
		p.v.OK, p.v.Err, p.v.At = false, err.Error(), time.Now()
		p.mu.Unlock()
		return
	}
	var blk struct{ Blocking string }
	note(p.call("GET", "/dns/blocking", &blk))
	var td, tb struct {
		Domains []struct {
			Domain string
			Count  int
		}
	}
	note(p.call("GET", "/stats/top_domains?count=15", &td))
	note(p.call("GET", "/stats/top_domains?blocked=true&count=15", &tb))
	var tc, tcb struct {
		Clients []struct {
			IP, Name string
			Count    int
		}
	}
	note(p.call("GET", "/stats/top_clients?count=200", &tc))
	note(p.call("GET", "/stats/top_clients?blocked=true&count=200", &tcb))
	var ups struct {
		Upstreams []struct {
			IP, Name string
			Port     int
			Count    int
		}
	}
	note(p.call("GET", "/stats/upstreams", &ups))

	// The query log: the last hour on the first poll, then what's new.
	p.mu.Lock()
	from := p.lastQ
	p.mu.Unlock()
	if from == 0 {
		from = float64(time.Now().Add(-time.Hour).Unix())
	}
	var ql struct{ Queries []phQuery }
	note(p.call("GET", fmt.Sprintf("/queries?from=%d&length=20000", int64(from)), &ql))

	now := time.Now()
	slow := func(at time.Time, every time.Duration) bool { return now.Sub(at) >= every }
	p.mu.Lock()
	devDue, cfgDue, verDue := slow(p.v.devicesAt, time.Minute), slow(p.v.configAt, 2*time.Minute), slow(p.v.versionAt, 6*time.Hour)
	p.mu.Unlock()

	var devs map[string]phDevice
	if devDue {
		var nd struct {
			Devices []struct {
				HWAddr     string `json:"hwaddr"`
				MacVendor  string `json:"macVendor"`
				LastQuery  int64  `json:"lastQuery"`
				NumQueries int    `json:"numQueries"`
				IPs        []struct {
					IP   string `json:"ip"`
					Name string `json:"name"`
				} `json:"ips"`
			}
		}
		if err := p.call("GET", "/network/devices?max_devices=500&max_addresses=8", &nd); err == nil {
			devs = map[string]phDevice{}
			for _, d := range nd.Devices {
				for _, ip := range d.IPs {
					cur, ok := devs[ip.IP]
					if ok && cur.LastQuery.Unix() >= d.LastQuery {
						continue
					}
					devs[ip.IP] = phDevice{MAC: d.HWAddr, Vendor: d.MacVendor, Name: ip.Name, NumQueries: d.NumQueries, LastQuery: time.Unix(d.LastQuery, 0)}
				}
			}
		} else {
			note(err)
		}
	}
	var msgs []string
	var records []string
	var cfgOK bool
	if cfgDue {
		var m struct {
			Messages []struct {
				Type, Plain string
				Timestamp   float64
			}
		}
		if err := p.call("GET", "/info/messages", &m); err == nil {
			for _, x := range m.Messages {
				msgs = append(msgs, time.Unix(int64(x.Timestamp), 0).Local().Format("01-02 15:04")+" "+x.Type+": "+x.Plain)
			}
		}
		var hc, cn struct {
			Config struct {
				DNS struct {
					Hosts        []string `json:"hosts"`
					CnameRecords []string `json:"cnameRecords"`
				} `json:"dns"`
			} `json:"config"`
		}
		if err := p.call("GET", "/config/dns/hosts", &hc); err == nil {
			cfgOK = true
			records = append(records, hc.Config.DNS.Hosts...)
			if p.call("GET", "/config/dns/cnameRecords", &cn) == nil {
				records = append(records, cn.Config.DNS.CnameRecords...)
			}
		} else if !errors.Is(err, errForbidden) {
			note(err)
		}
	}
	var version, update string
	if verDue {
		var ver struct {
			Version struct {
				Core struct {
					Local  struct{ Version string } `json:"local"`
					Remote struct{ Version string } `json:"remote"`
				} `json:"core"`
				FTL struct {
					Local  struct{ Version string } `json:"local"`
					Remote struct{ Version string } `json:"remote"`
				} `json:"ftl"`
			} `json:"version"`
		}
		if p.call("GET", "/info/version", &ver) == nil {
			version = ver.Version.Core.Local.Version
			if r := ver.Version.Core.Remote.Version; r != "" && version != "" && r != version {
				update = r
			}
			if r, l := ver.Version.FTL.Remote.Version, ver.Version.FTL.Local.Version; update == "" && r != "" && l != "" && r != l {
				update = "FTL " + r
			}
		}
	}
	var hosts []phHost
	if cfgDue {
		if !cfgOK {
			p.mu.Lock()
			records = append([]string(nil), p.v.LocalRecords...)
			p.mu.Unlock()
		}
		hosts = p.checkHosts(records)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	v := &p.v
	v.OK, v.At, v.Err = true, now, strings.Join(errs, "; ")
	v.CertChanged = false
	v.Blocking = blk.Blocking
	v.Total, v.Blocked, v.Percent = sum.Queries.Total, sum.Queries.Blocked, sum.Queries.Percent
	v.Cached, v.Forwarded, v.Unique, v.Freq = sum.Queries.Cached, sum.Queries.Forwarded, sum.Queries.Unique, sum.Queries.Frequency
	v.ClientsActive, v.ClientsTotal = sum.Clients.Active, sum.Clients.Total
	v.Gravity = sum.Gravity.Domains
	if sum.Gravity.LastUpdate > 0 {
		v.GravityAt = time.Unix(sum.Gravity.LastUpdate, 0)
	}
	v.TopDomains, v.TopBlocked = nil, nil
	for _, d := range td.Domains {
		v.TopDomains = append(v.TopDomains, phCount{d.Domain, d.Count})
	}
	for _, d := range tb.Domains {
		v.TopBlocked = append(v.TopBlocked, phCount{d.Domain, d.Count})
	}
	v.Upstreams = nil
	for _, u := range ups.Upstreams {
		name := orDefault(u.Name, u.IP)
		if u.Port > 0 && u.Port != 53 && u.IP != "" {
			name += "#" + strconv.Itoa(u.Port)
		}
		v.Upstreams = append(v.Upstreams, phCount{name, u.Count})
	}
	if devs != nil {
		p.devs, v.devicesAt = devs, now
	}
	if cfgDue {
		v.configAt = now
		v.Messages = msgs
		if cfgOK {
			v.LocalRecords = records
		}
	}
	if verDue {
		v.versionAt = now
		if version != "" {
			v.Version, v.Update = version, update
		}
	}
	if hosts != nil {
		v.Hosts = hosts
	}
	for _, q := range ql.Queries {
		p.window[q.ID] = q
		p.lastQ = max(p.lastQ, q.Time)
	}
	cut := float64(now.Add(-time.Hour).Unix())
	for id, q := range p.window {
		if q.Time < cut {
			delete(p.window, id)
		}
	}
	p.analyze(tc.Clients, tcb.Clients, now)
}

// analyze turns the stats and the last hour of the query log into clients,
// the live stream and detections. p.mu held.
func (p *piholeClient) analyze(top, topBlocked []struct {
	IP, Name string
	Count    int
}, now time.Time) {
	v := &p.v
	byIP := map[string]*phClient{}
	get := func(ip, name string) *phClient {
		c := byIP[ip]
		if c == nil {
			c = &phClient{IP: ip}
			byIP[ip] = c
		}
		if c.Name == "" && name != "" {
			c.Name = name
		}
		return c
	}
	for _, t := range top {
		get(t.IP, t.Name).Total = t.Count
	}
	for _, t := range topBlocked {
		get(t.IP, t.Name).Blocked = t.Count
	}

	qs := make([]phQuery, 0, len(p.window))
	for _, q := range p.window {
		qs = append(qs, q)
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].Time > qs[j].Time })
	if len(qs) > 400 {
		v.Recent = append([]phQuery(nil), qs[:400]...)
	} else {
		v.Recent = qs
	}

	doms := map[string]map[string]int{}
	bdoms := map[string]map[string]int{}
	type key struct{ ip, d string }
	det := map[key]*phDetection{}
	// group: one detection per client and kind (and base, for tunnels);
	// domain is added to its list.
	addDet := func(kind, ip, name, group, domain, example string, at time.Time, blocked bool) {
		k := key{ip, kind + "|" + group}
		d := det[k]
		if d == nil {
			d = &phDetection{Kind: kind, Client: ip, Name: name}
			det[k] = d
		}
		if domain != "" && !strings.Contains(", "+d.Domain+", ", ", "+domain+", ") {
			if d.Domain != "" {
				d.Domain += ", "
			}
			d.Domain += domain
		}
		d.Count++
		if blocked {
			d.Blocked++
		}
		if len(d.Examples) < 6 && !contains(d.Examples, example) {
			d.Examples = append(d.Examples, example)
		}
		if at.After(d.Last) {
			d.Last = at
		}
	}
	// For tunnels: unique long subdomains per client and base domain.
	subs := map[key]map[string]bool{}
	v.HourQueries, v.HourBlocked = 0, 0
	v.HourStart = now
	minute := map[int64]int{}
	for _, q := range qs {
		at := q.at()
		if at.Before(v.HourStart) {
			v.HourStart = at
		}
		minute[at.Unix()/60]++
		v.HourQueries++
		c := get(q.Client.IP, q.Client.Name)
		c.Hour++
		if at.After(c.Last) {
			c.Last = at
		}
		d := strings.ToLower(strings.TrimSuffix(q.Domain, "."))
		blocked := phBlocked(q.Status)
		if blocked {
			c.HourBlocked++
			v.HourBlocked++
			if bdoms[c.IP] == nil {
				bdoms[c.IP] = map[string]int{}
			}
			bdoms[c.IP][d]++
		} else {
			if doms[c.IP] == nil {
				doms[c.IP] = map[string]int{}
			}
			doms[c.IP][d]++
		}
		if q.Reply.Type == "NXDOMAIN" {
			c.NX++
		}
		if d == "" || strings.HasSuffix(d, ".arpa") || strings.HasSuffix(d, ".local") || !strings.Contains(d, ".") {
			continue
		}
		base := baseDomain(d)
		if kind, suffix, ok := phWatchlist(d); ok {
			addDet(kind, c.IP, c.Name, "", suffix, d, at, blocked)
		}
		if q.Reply.Type == "NXDOMAIN" && looksRandom(d) {
			addDet("dga", c.IP, c.Name, "", "", d, at, blocked)
		}
		if sub := strings.TrimSuffix(d, "."+base); sub != d && len(sub) >= 30 && !phTunnelOK(base) {
			k := key{c.IP, base}
			if subs[k] == nil {
				subs[k] = map[string]bool{}
			}
			subs[k][sub] = true
			if len(subs[k]) >= 40 {
				addDet("tunnel", c.IP, c.Name, base, base, d, at, blocked)
			}
		}
	}
	// Queries per minute over the hour, oldest first.
	v.QPM = ccRing{}
	for m := now.Add(-59*time.Minute).Unix() / 60; m <= now.Unix()/60; m++ {
		v.QPM.push(float64(minute[m]))
	}
	for ip, c := range byIP {
		c.Domains = topCounts(doms[ip], 12)
		c.BlockedDomains = topCounts(bdoms[ip], 12)
		if d, ok := p.devs[ip]; ok {
			c.MAC, c.Vendor = d.MAC, d.Vendor
			if c.Name == "" {
				c.Name = d.Name
			}
			if c.Last.IsZero() && d.LastQuery.Unix() > 0 {
				c.Last = d.LastQuery
			}
		}
	}
	v.Clients = nil
	for _, c := range byIP {
		v.Clients = append(v.Clients, c)
	}
	sort.Slice(v.Clients, func(i, j int) bool {
		a, b := v.Clients[i], v.Clients[j]
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		if a.Hour != b.Hour {
			return a.Hour > b.Hour
		}
		return ipLess(a.IP, b.IP)
	})
	v.Detections = nil
	for _, d := range det {
		if d.Kind == "dga" && d.Count < 4 {
			continue // a typo or two isn't malware
		}
		v.Detections = append(v.Detections, *d)
	}
	sort.Slice(v.Detections, func(i, j int) bool { return v.Detections[i].Last.After(v.Detections[j].Last) })

	// LAN devices the Pi-hole has never heard from (they use another DNS).
	v.NoDNS = nil
	if p.lan != nil && len(p.devs) > 0 && len(v.Clients) > 1 {
		host := ""
		if u, err := url.Parse(p.conf.URL); err == nil {
			host = u.Hostname()
		}
		for _, ip := range p.lan() {
			if ip == host {
				continue
			}
			if _, ok := byIP[ip]; ok {
				continue
			}
			if d, ok := p.devs[ip]; ok && d.NumQueries > 0 && now.Sub(d.LastQuery) < 24*time.Hour {
				continue
			}
			v.NoDNS = append(v.NoDNS, ip)
		}
		sort.Slice(v.NoDNS, func(i, j int) bool { return ipLess(v.NoDNS[i], v.NoDNS[j]) })
	}
}

func topCounts(m map[string]int, n int) []phCount {
	var out []phCount
	for k, c := range m {
		out = append(out, phCount{k, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// checkHosts asks the Pi-hole itself (DNS, port 53) for every ingress host
// and compares with the ingress address.
func (p *piholeClient) checkHosts(records []string) []phHost {
	if p.sites == nil {
		return nil
	}
	ings := p.sites()
	p.mu.Lock()
	base := p.conf.URL
	p.mu.Unlock()
	u, err := url.Parse(base)
	if err != nil || len(ings) == 0 {
		return nil
	}
	server := net.JoinHostPort(u.Hostname(), "53")
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, server)
	}}
	var out []phHost
	seen := map[string]bool{}
	for _, ing := range ings {
		if seen[ing.Host] || ing.Host == "" || ing.Address == "" || strings.HasPrefix(ing.Host, "*") {
			continue
		}
		seen[ing.Host] = true
		h := phHost{Host: ing.Host, Want: ing.Address, Record: phRecordFor(records, ing.Host)}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		addrs, err := r.LookupHost(ctx, ing.Host)
		cancel()
		if err != nil {
			h.Err = shortErr(err)
		} else {
			for _, a := range addrs {
				if net.ParseIP(a).To4() != nil {
					h.Got = a
					break
				}
			}
			if h.Got == "" && len(addrs) > 0 {
				h.Got = addrs[0]
			}
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// phRecordFor: the local record (hosts entry or CNAME) for a host, or "".
func phRecordFor(records []string, host string) string {
	for _, r := range records {
		if strings.Contains(r, ",") { // CNAME: "alias[,alias...],target[,ttl]"
			parts := strings.Split(r, ",")
			for _, a := range parts[:max(1, len(parts)-1)] {
				if strings.EqualFold(strings.TrimSpace(a), host) {
					return r
				}
			}
			continue
		}
		f := strings.Fields(r)
		for _, h := range f[min(1, len(f)):] {
			if strings.EqualFold(h, host) {
				return r
			}
		}
	}
	return ""
}

// FixHosts makes the Pi-hole answer every ingress host with the ingress
// address: wrong local records for those hosts are removed, missing ones
// added. It returns what it changed.
func (p *piholeClient) FixHosts(fix []phHost) ([]string, error) {
	if p.demo {
		return p.demoFixHosts(fix), nil
	}
	var done []string
	for _, h := range fix {
		if h.Record != "" {
			if strings.Contains(h.Record, ",") {
				if err := p.call("DELETE", "/config/dns/cnameRecords/"+url.PathEscape(h.Record), nil); err != nil {
					return done, p.fixErr(err)
				}
				done = append(done, "removed CNAME "+h.Record)
			} else {
				if err := p.call("DELETE", "/config/dns/hosts/"+url.PathEscape(h.Record), nil); err != nil {
					return done, p.fixErr(err)
				}
				done = append(done, "removed "+h.Record)
				// Keep the entry's other names.
				f := strings.Fields(h.Record)
				var rest []string
				for _, n := range f[1:] {
					if !strings.EqualFold(n, h.Host) {
						rest = append(rest, n)
					}
				}
				if len(rest) > 0 {
					keep := f[0] + " " + strings.Join(rest, " ")
					if err := p.call("PUT", "/config/dns/hosts/"+url.PathEscape(keep), nil); err != nil {
						return done, p.fixErr(err)
					}
					done = append(done, "kept "+keep)
				}
			}
		}
		entry := h.Want + " " + h.Host
		if err := p.call("PUT", "/config/dns/hosts/"+url.PathEscape(entry), nil); err != nil && !strings.Contains(err.Error(), "already") {
			return done, p.fixErr(err)
		}
		done = append(done, "added "+entry)
	}
	p.mu.Lock()
	p.v.configAt = time.Time{} // re-read the records
	p.mu.Unlock()
	p.Kick()
	return done, nil
}

func (p *piholeClient) fixErr(err error) error {
	if errors.Is(err, errForbidden) {
		return errors.New("the Pi-hole refused the change: an app password can only read unless 'webserver.api.app_sudo' is on (Settings → All settings → Webserver and API), or add the records in Local DNS → DNS Records")
	}
	return err
}

// ---------------------------------------------------------------------------
// What's suspicious in a lookup
// ---------------------------------------------------------------------------

// Suffixes that are watched (kind per entry).
var phWatch = []struct{ suffix, kind string }{
	// Crypto-mining pools (cryptojacking).
	{"minexmr.com", "mining"}, {"supportxmr.com", "mining"}, {"nanopool.org", "mining"}, {"2miners.com", "mining"},
	{"f2pool.com", "mining"}, {"moneroocean.stream", "mining"}, {"hashvault.pro", "mining"}, {"c3pool.com", "mining"},
	{"herominers.com", "mining"}, {"unmineable.com", "mining"}, {"nicehash.com", "mining"}, {"ethermine.org", "mining"},
	{"xmrpool.eu", "mining"}, {"coinhive.com", "mining"}, {"minergate.com", "mining"}, {"kryptex.network", "mining"},
	{"viabtc.com", "mining"}, {"antpool.com", "mining"}, {"poolin.com", "mining"}, {"zpool.ca", "mining"},
	// Tunnels that expose a device to the internet (or hide traffic).
	{"ngrok.io", "tunnelsvc"}, {"ngrok-free.app", "tunnelsvc"}, {"ngrok.app", "tunnelsvc"}, {"ngrok.dev", "tunnelsvc"},
	{"trycloudflare.com", "tunnelsvc"}, {"serveo.net", "tunnelsvc"}, {"loca.lt", "tunnelsvc"}, {"localtunnel.me", "tunnelsvc"},
	{"pagekite.me", "tunnelsvc"}, {"localhost.run", "tunnelsvc"}, {"bore.pub", "tunnelsvc"}, {"playit.gg", "tunnelsvc"},
	{"pinggy.io", "tunnelsvc"}, {"torproject.org", "tunnelsvc"},
	// Remote-control tools.
	{"anydesk.com", "remote"}, {"teamviewer.com", "remote"}, {"rustdesk.com", "remote"}, {"screenconnect.com", "remote"},
	{"connectwise.com", "remote"}, {"splashtop.com", "remote"}, {"logmein.com", "remote"}, {"remoteutilities.com", "remote"},
	{"atera.com", "remote"}, {"getscreen.me", "remote"}, {"ammyy.com", "remote"}, {"supremocontrol.com", "remote"},
	// Encrypted DNS: a device using it skips the Pi-hole.
	{"dns.google", "doh"}, {"cloudflare-dns.com", "doh"}, {"dns.quad9.net", "doh"}, {"doh.opendns.com", "doh"},
	{"dns.nextdns.io", "doh"}, {"doh.cleanbrowsing.org", "doh"}, {"dns.adguard-dns.com", "doh"}, {"doh.mullvad.net", "doh"},
	{"dns.mullvad.net", "doh"}, {"one.one.one.one", "doh"}, {"use-application-dns.net", "doh"},
}

func phWatchlist(d string) (kind, suffix string, ok bool) {
	for _, w := range phWatch {
		if d == w.suffix || strings.HasSuffix(d, "."+w.suffix) {
			return w.kind, w.suffix, true
		}
	}
	return "", "", false
}

// Bases with long, unique subdomains by design (CDNs, clouds, trackers),
// not tunnels.
var phTunnelAllow = []string{"akamaihd.net", "akamaized.net", "akamaiedge.net", "cloudfront.net", "amazonaws.com", "googlevideo.com",
	"gvt1.com", "googleusercontent.com", "googlesyndication.com", "doubleclick.net", "1e100.net", "azureedge.net", "azurefd.net",
	"trafficmanager.net", "windows.net", "msedge.net", "spotify.com", "scdn.co", "fbcdn.net", "cdninstagram.com", "apple.com",
	"icloud.com", "aaplimg.com", "sophosxl.net", "mcafee.com", "trendmicro.com", "spamhaus.org", "spamcop.net", "barracudacentral.org",
	"duckdns.org", "nflxvideo.net", "ttvnw.net", "steamcontent.com", "xboxlive.com", "plex.direct", "tailscale.com", "ts.net",
	"in-addr.arpa", "ip6.arpa", "dnsbl.sorbs.net", "surbl.org", "uribl.com", "e5.sk", "_dns-sd._udp.local"}

func phTunnelOK(base string) bool {
	for _, a := range phTunnelAllow {
		if base == a || strings.HasSuffix(base, "."+a) {
			return true
		}
	}
	return false
}

// Two-part public suffixes (a short list: good enough to find the base).
var phSuffix2 = map[string]bool{"co.uk": true, "org.uk": true, "ac.uk": true, "com.au": true, "net.au": true, "co.jp": true,
	"com.br": true, "co.nz": true, "co.in": true, "com.mx": true, "com.cn": true, "co.za": true, "com.tr": true, "com.ar": true,
	"duckdns.org": true, "github.io": true, "herokuapp.com": true, "azurewebsites.net": true, "blogspot.com": true, "ngrok.io": true,
	"ngrok-free.app": true, "trycloudflare.com": true, "cloudfront.net": true, "amazonaws.com": true}

// baseDomain: the registered domain (example.co.uk, x.duckdns.org).
func baseDomain(d string) string {
	parts := strings.Split(d, ".")
	if len(parts) <= 2 {
		return d
	}
	n := 2
	if phSuffix2[strings.Join(parts[len(parts)-2:], ".")] {
		n = 3
	}
	if len(parts) <= n {
		return d
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// looksRandom: a domain whose main label looks machine-generated (DGA).
func looksRandom(d string) bool {
	b := baseDomain(d)
	label := b
	if i := strings.IndexByte(b, '.'); i > 0 {
		label = b[:i]
	}
	if len(label) < 12 {
		return false
	}
	freq := map[rune]int{}
	vowels, digits := 0, 0
	for _, r := range label {
		freq[r]++
		switch {
		case strings.ContainsRune("aeiou", r):
			vowels++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	ent := 0.0
	for _, n := range freq {
		pr := float64(n) / float64(len(label))
		ent -= pr * math.Log2(pr)
	}
	vr := float64(vowels) / float64(len(label))
	return ent >= 3.5 && (vr < 0.25 || digits >= 3)
}
