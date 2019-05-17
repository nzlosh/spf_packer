package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

/**************************************************************************************************/
//Power DNS Client
type IPowerDNSClient interface {
	setConfiguration(cfg PdnsConfig)
	zonesList(server_id string) []PowerDNSZone
	zoneCreate(server_id string) PowerDNSZone
	zoneGet(server_id string) PowerDNSZone
	zoneDelete(server_id string, zone_id string) bool
	zoneMetaModify(server_id string, zone_id string) bool
	recordCreate(server_id string, zone_id string, record RRSet) bool
	recordUpdate(server_id string, zone_id string, record RRSet) bool
	recordDelete(server_id string, zone_id string, record RRSet) bool
}

type PowerDNSClient struct {
	cfg        PdnsConfig
	tls_config tls.Config
	transport  *http.Transport
	zone       PowerDNSZone
}

func (c *PowerDNSClient) setConfiguration(cfg PdnsConfig) {
	c.cfg = cfg
	c.tls_config = tls.Config{
		ServerName: "localhost",
	}
	c.transport = &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &c.tls_config,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

func (c *PowerDNSClient) call(verb string, url url.URL, body io.ReadCloser) *http.Response {
	// Set SSL certficate hostname.
	c.transport.TLSClientConfig.ServerName = url.Hostname()
	r := http.Request{
		Method: verb,
		URL:    &url,
		Body:   body,
		Header: make(http.Header),
	}

	// Pass basic authentication
	r.SetBasicAuth(c.cfg.Username, c.cfg.Password)

	// apply configuration settings to the http client.
	client := &http.Client{
		Transport: c.transport,
	}

	// get the previous spf records for the domain.
	resp, err := client.Do(&r)
	if err != nil {
		log.Printf("Error accessing %s.  %s\n", url.String(), err)
		os.Exit(1)
	}
	return resp
}

func (c *PowerDNSClient) zonesList(server_id string) []PowerDNSZone {
	//GET /servers/{server_id}/zones
	if server_id != "" {
		server_id = "servers/" + server_id + "/"
	}
	api_url, err := url.Parse(c.cfg.Api_url + server_id + "zones")
	if err != nil {
		log.Fatal(err)
	}
	resp := c.call("GET", *api_url, nil)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatal("HTTP Error " + api_url.String() + " " + resp.Status)
	}
	// process the server resposne.
	var domain_records []PowerDNSZone
	err = json.Unmarshal([]byte(body), &domain_records)
	if err != nil {
		log.Fatal(err)
	}

	return domain_records
}

func (c *PowerDNSClient) zoneCreate(server_id string) PowerDNSZone {
	// POST /servers/{server_id}/zones
	return PowerDNSZone{}
}

func (c *PowerDNSClient) zoneGet(server_id string, zone_id string) PowerDNSZone {
	// GET /servers/{server_id}/zones/{zone_id}
	if server_id != "" {
		server_id = "servers/" + server_id + "/"
	}

	api_url, err := url.Parse(c.cfg.Api_url + server_id + "zones/" + zone_id)
	if err != nil {
		log.Fatal(err)
	}

	resp := c.call("GET", *api_url, nil)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatal(fmt.Sprintf("HTTP Error %s %s\n", api_url.String(), resp.Status))
	}
	// process the server resposne.
	var zone PowerDNSZone
	err = json.Unmarshal([]byte(body), &zone)
	if err != nil {
		log.Fatal(err)
	}
	return zone
}

func (c *PowerDNSClient) zoneDelete(server_id string) bool {
	// DELETE /servers/{server_id}/zones/{zone_id}
	return false
}

func (c *PowerDNSClient) zoneMetaModify(server_id string) bool {
	// PUT /servers/{server_id}/zones/{zone_id}
	return false
}

func (c *PowerDNSClient) recordCreate(server_id string) bool {
	// PATCH /servers/{server_id}/zones/{zone_id}
	return false
}

func (c *PowerDNSClient) recordUpdate(server_id string, zone_id string, records RRSets) bool {
	// PATCH /servers/{server_id}/zones/{zone_id}

	if server_id != "" {
		server_id = "servers/" + server_id + "/"
	}

	api_url, err := url.Parse(c.cfg.Api_url + server_id + "zones/" + zone_id)
	if err != nil {
		log.Fatal(err)
	}
	/* rather than using the full zone object, a minimalist one is used to construct the JSON sent
	 * as the request body.
	 */
	s := fmt.Sprintf("{\"rrsets\": %s}", rrsetToJson(records))
	fmt.Println(s)
	/* http.Client.Body needs an io.ReadCloser, so bytes pkg converts the []byte to an io.Reader.
	 * Since a []byte doesn't need to be closed it's wrapped in ioutil.NopCloser.
	 * https://stackoverflow.com/questions/52076747/how-do-i-turn-an-io-reader-into-a-io-readcloser
	 */
	send_body := ioutil.NopCloser(bytes.NewReader([]byte(s)))
	defer send_body.Close()

	resp := c.call("PATCH", *api_url, send_body)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 204 {
		log.Fatal(
			fmt.Sprintf(
				"HTTP Error encounter for %s.  %s - %s\n",
				api_url.String(),
				resp.Status,
				string(body),
			),
		)
	}
	return true
}

func (c *PowerDNSClient) recordDelete(server_id string) bool {
	// PATCH /servers/{server_id}/zones/{zone_id}
	return false
}

/***************************************************************************************************/

func usage(script_name string, version Version) {
	fmt.Printf("Usage: %s -c <config.yaml>\n", script_name)
	fmt.Printf("Version: %d.%d.%d\n", version.Major, version.Minor, version.Patch)
	fmt.Println("    -c, --config    Configuration file.")
	fmt.Println("    -h, --help      Display this help.")
	fmt.Printf("    -n, --dryrun    Dry-run mode.  Don't apply changes.\n\n")
	//	fmt.Println("    -v, --verbose   verbose logging.")
}

type Version struct {
	Major int
	Minor int
	Patch int
}

func main() {
	version := Version{1, 0, 0}
	if len(os.Args) < 2 {
		usage(os.Args[0], version)
		os.Exit(1)
	}

	dryrun := false
	verbose := false
	cfg_file := ""
	for i := 0; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dryrun", "--dry-run", "-n", "dryrun", "dry-run":
			dryrun = true
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h":
			usage(os.Args[0], version)
			os.Exit(0)
		case "--config", "-c":
			if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
				fmt.Printf("\nFlag %s requries a filename.\n\n", os.Args[i])
				usage(os.Args[0], version)
				os.Exit(2)
			} else {
				i++
				cfg_file = os.Args[i]
			}
		}

	}
	cfg := LoadConfig(cfg_file)
	cfg.Dryrun = dryrun
	cfg.Verbose = verbose

	// parse configuration
	result := processConfiguration(cfg)

	// resolve dns entries to create a list of address.
	result = resolveSPFFields(result)

	// de-duplicate overlapping address ranges.
	result = deduplicateAddressRanges(result)

	// If PowerDNS configuration is not present, display results to console.
	if (PdnsConfig{}) == cfg.Pdns {
		printSpf(makeSpfFields(result, cfg), cfg.Domain)
	} else {
		log.Println("Comparing with PowerDNS entries")
		// Create SPF entries in the form of PowerDNS Resource Records.
		pdns_result := makeRRSet(result, cfg)

		pdns := PowerDNSClient{}
		pdns.setConfiguration(cfg.Pdns)
		zone := pdns.zoneGet("", cfg.Domain)
		records := filterSPF(zone)

		log.Print(fmt.Sprintf("Dry-run mode enabled = %v", cfg.Dryrun))
		if rrsetEquivalent(pdns_result, records) {
			log.Println("SPF records are the same.")
		} else {
			log.Println("SPF has changed, update DNS records.  Previous entry:")
			log.Println(string(rrsetToJson(records)))
			update := createUpdateRecords(pdns_result, records)
			if cfg.Dryrun == true {
				log.Print("Dry-run mode - no changes applied.")
				os.Exit(0)
			}
			if pdns.recordUpdate("", cfg.Domain, update) {
				log.Println("Updated DNS records successfully.")
			} else {
				log.Println("Failed to update DNS records.")
			}
		}
	}
}

func createUpdateRecords(latest []RRSet, original []RRSet) RRSets {
	// Compare the update RRset with the original RRset to produce a new
	// RRset to used to update PowerDNS.
	update := RRSets{}
	// Find records to be updated.
	for _, rlatest := range latest {
		update = append(update, rlatest)
		idx := len(update) - 1
		for _, roriginal := range original {
			// If there is a match between the records, merge original excluding spf entries.
			if rlatest.Name == roriginal.Name {
				update[idx].Changetype = "REPLACE"
				update[idx].Ttl = roriginal.Ttl
				for _, non_spf := range roriginal.Records {
					ok, _ := regexp.Match(`^"v=spf1`, []byte(non_spf.Content))
					if ok == false {
						update[idx].Records = append(update[idx].Records, non_spf)
					}
				}
				break
			}
		}
	}

	// Find records to be deleted.
	if len(original) > len(update) {
		for _, roriginal := range original {
			match := false
			for _, rupdate := range update {
				if roriginal.Name == rupdate.Name {
					match = true
				}
			}
			// If there was no match, the original record must be deleted.
			if match == false {
				update = append(update,
					RRSet{
						Changetype: "DELETE",
						Comments:   []Comment{},
						Name:       roriginal.Name,
						Records:    []Record{},
						Type:       "TXT",
						Ttl:        0,
					})
			}
		}
	}

	/* Any records that are not already tagged are creates so we add the REPLACE value */
	for i, r := range update {
		if !(r.Changetype == "DELETE" || r.Changetype == "REPLACE") {
			update[i].Changetype = "REPLACE"
		}
	}

	return update
}

func red(s string) string {
	return fmt.Sprintf("%s%s%s", "\033[31m", s, "\033[0m")
}

func green(s string) string {
	return fmt.Sprintf("%s%s%s", "\033[32m", s, "\033[0m")
}

func blue(s string) string {
	return fmt.Sprintf("%s%s%s", "\033[34m", s, "\033[0m")
}

func yellow(s string) string {
	return fmt.Sprintf("%s%s%s", "\033[33m", s, "\033[0m")
}

type PdnsConfig struct {
	Api_key     string
	Api_url     string
	Client_key  string
	Client_cert string
	Ca_cert     string
	Username    string
	Password    string
}

type Config struct {
	Version     string
	Domain      string
	SpfMaxChars int
	Rawtxt      string
	Policy      string
	Ipv4        []string
	Ipv6        []string
	Includes    []string
	A           []string
	Mx          []string
	Redirect    []string
	Ptr         []string
	Pdns        PdnsConfig
	Dryrun      bool
	Verbose     bool
}

type Comment struct {
	Content     string `json:"content"`
	Account     string `json:"account"`
	Modified_at int    `json:"modified_at"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
	Setptr   bool   `json:"set-ptr"`
}

type RRSet struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Ttl        int       `json:"ttl,omitempty"`
	Changetype string    `json:"changetype"`
	Records    []Record  `json:"records"`
	Comments   []Comment `json:"comments"`
}

/* Define RRSets to provide the Sort interface. */
type RRSets []RRSet

func (s RRSets) Len() int {
	return len(s)
}
func (s RRSets) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s RRSets) Less(i, j int) bool {
	return s[i].Name < s[j].Name
}

type Records []Record

func (s Records) Len() int {
	return len(s)
}
func (s Records) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s Records) Less(i, j int) bool {
	return s[i].Content < s[j].Content
}

type PowerDNSZone struct {
	Id                  string   `json:"id"`
	Name                string   `json:"name"`
	Type                string   `json:"type"`
	Url                 string   `json:"url"`
	Kind                string   `json:"kind'`
	Rrsets              []RRSet  `json:"rrsets"`
	Serial              int      `json:"serial"`
	Notified_serial     int      `json:"notified_serial"`
	Masters             []string `json:"master"`
	Dnssec              bool     `json:"dnssec"`
	Nsec3param          string   `json:"nsec3param"`
	Nsec3narrow         bool     `json:"nsec3narrow"`
	Presigned           bool     `json:"presigned"`
	Soa_edit            string   `json:"soa_edit"`
	Soa_edit_api        string   `json:"soa_edit_api"`
	Api_rectify         bool     `json:"api_rectify:`
	Zone                string   `json:"zone"`
	Account             string   `json:"account"`
	Nameservers         []string `json:"nameservers"`
	Tsig_master_key_ids []string `json:"tsig_master_keys_ids"`
	Tsig_slave_key_ids  []string `json:"tsig_slave_key_ids"`
}

func processConfiguration(cfg *Config) []string {
	check_list := []string{"v=" + cfg.Version}
	for _, ipv4 := range cfg.Ipv4 {
		check_list = append(check_list, "ip4:"+ipv4)
	}
	for _, ipv6 := range cfg.Ipv6 {
		check_list = append(check_list, "ip6:"+ipv6)
	}
	for _, include := range cfg.Includes {
		check_list = append(check_list, "include:"+include)
	}
	for _, a := range cfg.A {
		check_list = append(check_list, "a:"+a)
	}
	for _, mx := range cfg.Mx {
		check_list = append(check_list, "mx:"+mx)
	}
	for _, ptr := range cfg.Ptr {
		check_list = append(check_list, "ptr:"+ptr)
	}
	for _, redirect := range cfg.Redirect {
		log.Printf("Redirect not supported.  %s", redirect)
	}
	check_list = append(check_list, cfg.Policy)
	return check_list
}

func deduplicateAddressRanges(all []string) []string {

	// Dedupe records
	seen := make(map[string]struct{})
	for _, item := range all {
		if _, ok := seen[item]; ok {
			log.Printf("Ignoring duplicate %s\n", item)
		} else {
			seen[item] = struct{}{}
		}
	}

	var deduped []string
	for item, _ := range seen {
		deduped = append(deduped, item)
	}

	// Build slice of CIDRs
	var cidrs []*net.IPNet
	for _, item := range deduped {
		network := strings.SplitN(item, ":", 2)
		if len(network) == 2 && strings.HasPrefix(network[0], "ip") {
			_, cidr, err := net.ParseCIDR(network[1])
			if err == nil {
				cidrs = append(cidrs, cidr)
			}
		}
	}

	// Dedupe IP addresses covered by network range
	var result []string
	for _, item := range deduped {
		address := strings.SplitN(item, ":", 2)
		if len(address) == 2 && strings.HasPrefix(address[0], "ip") {
			ip := net.ParseIP(address[1])
			if ip != nil {
				var duplicate bool
				duplicate = false
				for _, cidr := range cidrs {
					if cidr.Contains(ip) {
						duplicate = true
						log.Printf("Ignoring IP address %s already contained in %s\n", item, cidr)
						break
					}
				}
				if !duplicate {
					result = append(result, item)
				}
			} else { // not and address
				result = append(result, item)
			}
		} else { // non IP item, no deduplicatiuon needed
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

func LoadConfig(cfg_file string) *Config {
	file, err := os.Open(cfg_file)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	bs := make([]byte, stat.Size())
	_, err = file.Read(bs)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	return parseYAML(bs)
}

func parseYAML(str_cfg []byte) *Config {
	m := new(Config)
	err := yaml.Unmarshal(str_cfg, m)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	return m
}

func parseSPFText(spf_text string) []string {
	fields := []string{}
	if strings.HasPrefix(spf_text, "v=spf1 ") {
		fields = strings.Fields(spf_text)
	} else {
		log.Printf("Ignoring text, doesn't appear to be an spf1 record. %s\n", spf_text)
	}
	return fields
}

func resolveSPFFields(result []string) []string {
	spf_set := []string{}
	for _, field := range result {
		if field == "v=spf1" {
			continue
		}
		if strings.HasSuffix(field, "all") && strings.ContainsAny(string(field[0]), "+-?~") {
			continue
		}
		p := "a:"
		if strings.HasPrefix(field, p) {
			ips := resolveA(field[len(p):])
			spf_set = append(spf_set, ips...)
			continue
		}
		p = "include:"
		if strings.HasPrefix(field, p) {
			texts := resolveInclude(field[len(p):])
			for _, text := range texts {
				spf_fields := parseSPFText(text)
				if len(spf_fields) > 0 {
					ips := resolveSPFFields(spf_fields)
					spf_set = append(spf_set, ips...)
				}
			}
			continue
		}
		p = "ip4:"
		if strings.HasPrefix(field, p) {
			spf_set = append(spf_set, field)
			continue
		}
		p = "ip6:"
		if strings.HasPrefix(field, p) {
			spf_set = append(spf_set, field)
			continue
		}
		p = "ptr:"
		if strings.HasPrefix(field, p) {
			resolvePtr(field)
			continue
		}
		p = "mx:"
		if strings.HasPrefix(field, p) {
			ips := resolveMx(field[len(p):])
			spf_set = append(spf_set, ips...)
			continue
		}
		log.Printf("Unhandled field '%s'\n", field)
	}
	return spf_set
}

func makeSpfFields(result []string, cfg *Config) map[string]string {
	domain := cfg.Domain
	suffix := "a"
	spf_records := make(map[string]string)
	current_record := "v=" + cfg.Version
	spf_max_chars := cfg.SpfMaxChars
	root_spf := fmt.Sprintf("%s %s include:spf%s.%s", current_record, cfg.Rawtxt, suffix, domain)

	for i, record := range result {
		if len(fmt.Sprintf("\"%s %s %s\"", current_record, record, cfg.Policy)) > spf_max_chars {
			spf_records[fmt.Sprintf("spf%s.%s", suffix, domain)] = current_record + " " + cfg.Policy
			current_record = fmt.Sprintf("v=%s %s", cfg.Version, record)
			suffix = string([]byte(suffix)[0] + 1)
			root_spf += fmt.Sprintf(" include:spf%s.%s", suffix, domain)
		} else {
			current_record = fmt.Sprintf("%s %s", current_record, record)
		}
		if i == len(result)-1 {
			spf_records[fmt.Sprintf("spf%s.%s", suffix, domain)] = current_record + " " + cfg.Policy
		}
	}
	root_spf += " " + cfg.Policy
	// Insert the root spf at the beginning of the array and return the result.
	spf_records[domain] = root_spf
	return spf_records
}

func makeRRSet(result []string, cfg *Config) []RRSet {
	domain := cfg.Domain
	suffix := "a"
	spf_records := []RRSet{}
	current_record := "v=" + cfg.Version
	spf_max_chars := cfg.SpfMaxChars
	root_spf := fmt.Sprintf("%s %s include:spf%s.%s", current_record, cfg.Rawtxt, suffix, domain)

	for i, record := range result {
		if len(fmt.Sprintf("\"%s %s %s\"", current_record, record, cfg.Policy)) > spf_max_chars {
			spf_records = append(spf_records, RRSet{
				Comments: []Comment{},
				Name:     fmt.Sprintf("spf%s.%s.", suffix, domain),
				Records: []Record{
					Record{
						Content:  fmt.Sprintf("\"%s %s\"", current_record, cfg.Policy),
						Disabled: false,
						Setptr:   false,
					},
				},
				Ttl:  43200,
				Type: "TXT",
			})
			current_record = fmt.Sprintf("v=%s %s", cfg.Version, record)
			suffix = string([]byte(suffix)[0] + 1)
			root_spf += fmt.Sprintf(" include:spf%s.%s", suffix, domain)
		} else {
			current_record = fmt.Sprintf("%s %s", current_record, record)
		}
		if i == len(result)-1 {
			spf_records = append(spf_records, RRSet{
				Comments: []Comment{},
				Name:     fmt.Sprintf("spf%s.%s.", suffix, domain),
				Records: []Record{
					Record{
						Content:  fmt.Sprintf("\"%s %s\"", current_record, cfg.Policy),
						Disabled: false,
						Setptr:   false,
					},
				},
				Ttl:  43200,
				Type: "TXT",
			})
		}
	}

	spf_records = append(spf_records, RRSet{
		Comments: []Comment{},
		Name:     fmt.Sprintf("%s.", domain),
		Records: []Record{
			Record{
				Content:  fmt.Sprintf("\"%s %s\"", root_spf, cfg.Policy),
				Disabled: false,
				Setptr:   false,
			},
		},
		Ttl:  43200,
		Type: "TXT",
	})
	return spf_records
}

func printSpf(spf_records map[string]string, domain string) {
	fmt.Printf("\nPacked SPF TXT records for %s.\n", domain)
	var keys []string
	for k := range spf_records {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("\n%s %s\n", k, spf_records[k])
	}
}

func resolveMx(field string) []string {
	ips := []string{}
	mxs, err := net.LookupMX(field)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error looking up MX %s. %s\n", field, err))
	}
	for _, mx := range mxs {
		log.Printf("MX: %s\n", mx.Host)
		addresses := resolveA(mx.Host)
		for _, address := range addresses {
			ips = append(ips, address)
		}
	}
	return ips
}

func ValidateIP(ip string) (string, error) {
	var err error = nil
	spf_ip := net.ParseIP(ip)
	if spf_ip == nil {
		err = errors.New("Invalid IP address " + ip)
	} else {
		if strings.Contains(spf_ip.String(), "::") {
			ip = "ip6:" + spf_ip.String() + "/64"
		} else {
			ip = "ip4:" + spf_ip.String() + "/32"
		}
	}
	return ip, err
}

func resolvePtr(field string) {
	log.Printf("Pointer records aren't supported.  Skipping %s\n", field)
}

func resolveInclude(record string) []string {
	log.Printf("Include: %s\n", record)
	spf_text, err := net.LookupTXT(record)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error looking up '%s'. %s\n", record, err))
	}
	return spf_text
}

func resolveA(record string) []string {
	ips := []string{}
	res, err := net.LookupHost(record)
	log.Printf("A: %s\n", record)
	if err != nil {
		log.Fatal(fmt.Sprintf("A record lookup error. %s\n", err))
	}
	for _, address := range res {
		ip, err := ValidateIP(address)
		if err == nil {
			ips = append(ips, ip)
		} else {
			log.Printf("%s\n", err)
		}
	}
	return ips
}

func rrsetToJson(records []RRSet) []byte {
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		fmt.Println(red(fmt.Sprintf("error: %s", err)))
	}
	return b
}

func rrsetEquivalent(set1 []RRSet, set2 []RRSet) bool {
	// Sort sets to simplify comparing.
	sort.Sort(RRSets(set1))
	sort.Sort(RRSets(set2))
	matched := true
	if len(set1) == len(set2) {
		for i, _ := range set1 {
			if set1[i].Name != set2[i].Name {
				fmt.Println("Records do not match.")
				matched = false
				break
			}
			sort.Sort(Records(set1[i].Records))
			spf1 := "not_spf2"
			for _, r := range set1[i].Records {
				if strings.HasPrefix(r.Content, "\"v=spf1") {
					spf1 = r.Content
					break
				}
			}
			sort.Sort(Records(set2[i].Records))
			spf2 := "not_spf1"
			for _, r := range set2[i].Records {
				if strings.HasPrefix(r.Content, "\"v=spf1") {
					spf2 = r.Content
					break
				}
			}
			// compare records
			if spf1 != spf2 {
				matched = false
				break
			}
		}
	} else {
		matched = false
	}
	return matched
}

func filterSPF(domain_records PowerDNSZone) []RRSet {
	// Return only SPF records for the domain.
	records := []RRSet{}
	name := strings.TrimSuffix(domain_records.Name, ".")
	for _, rr := range domain_records.Rrsets {
		ok, _ := regexp.Match("^(spf[a-z]\\.)?"+name, []byte(rr.Name))
		if ok == true && rr.Type == "TXT" {
			for _, r := range rr.Records {
				if strings.HasPrefix(r.Content, "\"v=spf1") {
					records = append(records, rr)
				}
			}
		}
	}
	return records
}
