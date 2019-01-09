package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
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

func (c *PowerDNSClient) call(verb string, url url.URL) *http.Response {
	// Set SSL certficate hostname.
	c.transport.TLSClientConfig.ServerName = url.Hostname()
	r := http.Request{
		Method: verb,
		URL:    &url,
		Body:   nil,
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
		server_id = "servers/" + server_id
	}
	api_url, err := url.Parse(c.cfg.Api_url + server_id + "/zones")
	if err != nil {
		log.Fatal(err)
	}
	resp := c.call("GET", *api_url)
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
		server_id = "servers/" + server_id
	}

	api_url, err := url.Parse(c.cfg.Api_url + server_id + "/zones/" + zone_id)
	if err != nil {
		log.Fatal(err)
	}

	resp := c.call("GET", *api_url)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatal("HTTP Error " + api_url.String() + " " + resp.Status)
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

func (c *PowerDNSClient) recordUpdate(server_id string, zone_id string, records []RRSet) bool {
	// PATCH /servers/{server_id}/zones/{zone_id}
	/* JSON representation of RRSet entry.  "changetype":
	   * DELETE, all existing RRs matching name and type will be deleted, including all comments.
	   * REPLACE: when records is present, all existing RRs matching name and type will be deleted,
	   * and then new records given in records will be created.
	         {
	          "comments": [],
	          "name": "host.example.com.",
	          "records": [
	            {
	              "content": "a.example.com.",
	              "disabled": false
	            },
	            {
	              "content": "b.example.com.",
	              "disabled": false
	            }
	          ],
	          "ttl": 86400,
	          "type": "NS"
	        },
	*/
	if server_id != "" {
		server_id = "servers/" + server_id
	}

	api_url, err := url.Parse(c.cfg.Api_url + server_id + "/zones/" + zone_id)
	if err != nil {
		log.Fatal(err)
	}

	resp := c.call("PATCH", *api_url)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(body))

	if resp.StatusCode != 204 {
		log.Fatal("HTTP Error " + api_url.String() + " " + resp.Status)
		return false
	}
	return true
}

func (c *PowerDNSClient) recordDelete(server_id string) bool {
	// PATCH /servers/{server_id}/zones/{zone_id}
	return false
}

/***************************************************************************************************/

func main() {
	cfg := LoadConfig(os.Args[0] + ".yaml")
	// parse configuration
	result := processConfiguration(cfg)

	// resolve dns entries to create a list of address.
	result = expandFields(result)

	// de-duplicate overlapping address ranges.
	result = deduplicateAddressRanges(result)

	// If PowerDNS configuration is not present, display results to console.
	if (PdnsConfig{}) == cfg.Pdns {
		// Create SPF TXT entries for list of addresses.
		result = makeSpfFields(result, cfg)
		printSpf(result, cfg.Domain)
	} else {
		fmt.Printf("%s\n", red("Updating PowerDNS entries"))
		// Create SPF entries in the form of PowerDNS Resource Records.
		pdns_result := makeRRSet(result, cfg)

		// Display for debug
		//convertRRSetToString(pdns_result)
		pdns := PowerDNSClient{}
		pdns.setConfiguration(cfg.Pdns)
		zone := pdns.zoneGet("", cfg.Domain)
		fmt.Println(green(zone.Name), len(zone.Rrsets))
		updatePdns(pdns_result, cfg)
	}
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
}

type Comment struct {
	Content     string
	Account     string
	Modified_at int
}

type Record struct {
	Content  string
	Disabled bool
	Setptr   bool `json: "set-ptr"`
}

type RRSet struct {
	Name       string
	Type       string
	Ttl        int
	Changetype string
	Records    []Record
	Comments   []Comment
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
	Id                  string
	Name                string
	Type                string
	Url                 string
	Kind                string
	Rrsets              []RRSet
	Serial              int
	Notified_serial     int
	Masters             []string
	Dnssec              bool
	Nsec3param          string
	Nsec3narrow         bool
	Presigned           bool
	Soa_edit            string
	Soa_edit_api        string
	Api_rectify         bool
	Zone                string
	Account             string
	Nameservers         []string
	Tsig_master_key_ids []string
	Tsig_slave_key_ids  []string
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

func deduplicateAddressRanges(result []string) []string {
	// TODO: Implement de-duplication
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

func expandFields(result []string) []string {
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
					ips := expandFields(spf_fields)
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

func makeSpfFields(result []string, cfg *Config) []string {
	domain := cfg.Domain
	suffix := "a"
	spf_records := []string{}
	current_record := "v=" + cfg.Version
	spf_max_chars := cfg.SpfMaxChars
	root_spf := fmt.Sprintf("%s %s include:spf%s.%s", current_record, cfg.Rawtxt, suffix, domain)

	for i, record := range result {
		if len(fmt.Sprintf("\"%s %s %s\"", current_record, record, cfg.Policy)) > spf_max_chars {
			spf_records = append(spf_records, current_record+" "+cfg.Policy)
			current_record = fmt.Sprintf("v=%s %s", cfg.Version, record)
			suffix = string([]byte(suffix)[0] + 1)
			root_spf += fmt.Sprintf(" include:spf%s.%s", suffix, domain)
		} else {
			current_record = fmt.Sprintf("%s %s", current_record, record)
		}
		if i == len(result)-1 {
			spf_records = append(spf_records, fmt.Sprintf("%s %s", current_record, cfg.Policy))
		}
	}
	root_spf += " " + cfg.Policy
	// Insert the root spf at the beginning of the array and return the result.
	return append(spf_records[:0], append([]string{root_spf}, spf_records[0:]...)...)
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

func printSpf(spf_records []string, domain string) {
	fmt.Printf("\nPacked SPF TXT records for %s.\n", domain)
	for _, v := range spf_records {
		fmt.Printf("\n%s\n", v)
	}
}

func resolveMx(field string) []string {
	ips := []string{}
	mxs, err := net.LookupMX(field)
	if err != nil {
		log.Printf("Error looking up MX %s. %s\n", field, err)
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
		log.Printf("Error looking up '%s'. %s\n", record, err)
	}
	return spf_text
}

func resolveA(record string) []string {
	ips := []string{}
	res, err := net.LookupHost(record)
	log.Printf("A: %s\n", record)
	if err != nil {
		log.Printf("A record lookup error. %s\n", err)
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

func convertRRSetToString(records []RRSet) []string {
	s := []string{}
	for _, r := range records {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			fmt.Println(red(fmt.Sprintf("error: %s", err)))
		}
		os.Stdout.Write(b)
	}
	return s
}

func updatePdns(result []RRSet, cfg *Config) {

	records := getPowerDNS(cfg.Domain, cfg)

	for i, r := range result {
		fmt.Println(yellow(fmt.Sprintf("%d) %s", i, r)))
	}

	fmt.Printf("DNS entities new=%d, original=%d\n", len(result), len(records))
	if rrsetEquivalent(result, records) {
		fmt.Println("SPF records are same.")
	} else {
		fmt.Println("SPF has changed, update DNS records.")
		//createTxtPowerDNS(result)
	}
}

func rrsetEquivalent(set1 []RRSet, set2 []RRSet) bool {
	// Sort sets to simplify comparing.
	sort.Sort(RRSets(set1))
	sort.Sort(RRSets(set2))

	if len(set1) == len(set2) {
		for i, _ := range set1 {
			if set1[i].Name == set2[i].Name {
				spf1 := "1"
				spf2 := "2"
				if len(set1[i].Records) > 1 {
					sort.Sort(Records(set1[i].Records))
					for _, r := range set1[i].Records {
						if strings.HasPrefix(r.Content, "\"v=spf1") {
							spf1 = r.Content
							break
						}
					}
				} else {
					spf1 = set1[i].Records[0].Content
				}
				if len(set2[i].Records) > 1 {
					sort.Sort(Records(set2[i].Records))
					for _, r := range set2[i].Records {
						if strings.HasPrefix(r.Content, "\"v=spf1") {
							spf2 = r.Content
							break
						}
					}
				} else {
					spf2 = set2[i].Records[0].Content
				}
				// compare records
				if spf1 != spf2 {
					fmt.Println("SPF content does not match.")
					break
				}

			} else {
				fmt.Println("Records do not match.")
				break
			}
		}
	}
	return false
}

func getOwnDomainSPF(cfg *Config) []string {
	/*
	 * Use DNS lookups to retrieve existing SPF records for the domain.
	 */
	original_spf := []string{}

	txt := resolveInclude(cfg.Domain)
	for _, field := range txt {
		original_spf = parseSPFText(field)
		// If lookup text field is valid SPF, original_spf will not be empty.
		if len(original_spf) > 0 {
			break
		}
	}
	// Only process spf records that match the source domain.
	domain_only_spf := []string{}
	for _, field := range original_spf {
		if strings.HasSuffix(field, cfg.Domain) {
			domain_only_spf = append(domain_only_spf, field)
		}
	}
	return domain_only_spf
}

func createTxtPowerDNS(results []string) bool {
	/*
	   PATCH /servers/{server_id}/zones/{zone_id}
	*/
	for _, result := range results {
		fmt.Println(red(result))
	}
	return true
}

func getPowerDNS(zone string, cfg *Config) []RRSet {
	/*
	 * Use PowerDNS API to retrieve exist SPF records for the domain.
	 */
	log.Printf("PowerDNS url=%s\n", cfg.Pdns.Api_url)

	api_url, err := url.Parse(fmt.Sprintf("%szones/%s", cfg.Pdns.Api_url, cfg.Domain))
	if err != nil {
		log.Fatal(err)
	}

	// configure client transport settings
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			ServerName: api_url.Hostname(),
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	r := http.Request{
		Method: "GET",
		URL:    api_url,
		Body:   nil,
		Header: make(http.Header),
	}
	r.SetBasicAuth(cfg.Pdns.Username, cfg.Pdns.Password)

	// apply configuration settings to the http client.
	client := &http.Client{
		Transport: tr,
	}

	// get the previous spf records for the domain.
	resp, err := client.Do(&r)
	if err != nil {
		log.Printf("Error accessing %s.  %s\n", api_url.String(), err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatal("Error communicating with " + api_url.String() + " " + resp.Status)
	}

	// process the server resposne.
	var domain_records PowerDNSZone
	err = json.Unmarshal([]byte(body), &domain_records)
	if err != nil {
		log.Fatal(err)
	}
	return filterSPF(domain_records)
}

func filterSPF(domain_records PowerDNSZone) []RRSet {
	// Return the set of SPF records for the domain.
	records := []RRSet{}
	name := strings.TrimSuffix(domain_records.Name, ".")
	for _, rr := range domain_records.Rrsets {
		ok, _ := regexp.Match("^(spf[^.]+\\.)?"+name, []byte(rr.Name))
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
