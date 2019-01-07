package main

import
(
    "os"
    "fmt"
    "log"
    "net"
    "time"
    "sort"
    "errors"
    "regexp"
    "strings"
    "io/ioutil"
    "encoding/json"
    "gopkg.in/yaml.v2"
    "net/url"
    "net/http"
    "crypto/tls"
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
    cfg PdnsConfig
    tls_config tls.Config
    transport *http.Transport
}

func (c *PowerDNSClient) setConfiguration(cfg PdnsConfig) {
    c.cfg = cfg
    c.tls_config = tls.Config {
        ServerName: "localhost",
    }
    c.transport = &http.Transport{
        MaxIdleConns: 10,
        IdleConnTimeout: 30 * time.Second,
        DisableCompression: true,
        TLSClientConfig: &c.tls_config,
        TLSHandshakeTimeout: 10 * time.Second,
    }
}

func (c *PowerDNSClient) call(verb string, url url.URL) *http.Response {
    // Set SSL certficate hostname.
    c.transport.TLSClientConfig.ServerName = url.Hostname()
    r := http.Request{
        Method: verb,
        URL: &url,
        Body: nil,
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
    cfg := LoadConfig(os.Args[0]+".yaml")
    pdns := PowerDNSClient{}
    pdns.setConfiguration(cfg.Pdns)
    dm_zone := pdns.zoneGet("", cfg.Domain)
    fmt.Println(green(dm_zone.Name), len(dm_zone.Rrsets))
    result := processConfiguration(cfg)
    result = expandFields(result)
    result = deduplicateAddressRanges(result)
    result = makeSpfFields(result, cfg)
    if (PdnsConfig{}) == cfg.Pdns {
        // PowerDNS configuration not present, display results to console.
        printSpf(result, cfg.Domain)
    } else {
        fmt.Printf("%s\n", red("Updating PowerDNS entries"))
        dm_zone
        //updatePdns(result, cfg)
    }
}

func red(s string) string {
    return fmt.Sprintf("%s%s%s","\033[31m", s, "\033[0m")
}

func green(s string) string {
    return fmt.Sprintf("%s%s%s","\033[32m", s, "\033[0m")
}

func blue(s string) string {
    return fmt.Sprintf("%s%s%s","\033[34m", s, "\033[0m")
}

func yellow(s string) string {
    return fmt.Sprintf("%s%s%s","\033[33m", s, "\033[0m")
}

type PdnsConfig struct {
    Api_key string
    Api_url string
    Client_key string
    Client_cert string
    Ca_cert string
    Username string
    Password string
}


type Config struct {
    Version string
    Domain string
    SpfMaxChars int
    Rawtxt string
    Policy string
    Ipv4 []string
    Ipv6 []string
    Includes []string
    A []string
    Mx []string
    Redirect []string
    Ptr []string
    Pdns PdnsConfig
}

type Comment struct {
    Content string
    Account string
    Modified_at int
}

type Record struct {
    Content string
    Disabled bool
    Setptr bool `json: "set-ptr"`
}

type RRSet struct {
    Name string
    Type string
    Ttl int
    Changetype string
    Records []Record
    Comments []Comment
}

type PowerDNSZone struct {
    Id string
    Name string
    Type string
    Url string
    Kind string
    Rrsets []RRSet
    Serial int
    Notified_serial int
    Masters []string
    Dnssec bool
    Nsec3param string
    Nsec3narrow bool
    Presigned bool
    Soa_edit string
    Soa_edit_api string
    Api_rectify bool
    Zone string
    Account string
    Nameservers []string
    Tsig_master_key_ids []string
    Tsig_slave_key_ids []string
}

func processConfiguration(cfg *Config) []string {
    check_list := []string{"v=" + cfg.Version}
    for _, ipv4 := range cfg.Ipv4 {
        check_list = append(check_list, "ip4:" + ipv4)
    }
    for _, ipv6 := range cfg.Ipv6 {
        check_list = append(check_list, "ip6:" + ipv6)
    }
    for _, include := range cfg.Includes {
        check_list = append(check_list, "include:" + include)
    }
    for _, a := range cfg.A {
        check_list = append(check_list, "a:" + a)
    }
    for _, mx := range cfg.Mx {
        check_list = append(check_list, "mx:" + mx)
    }
    for _, ptr := range cfg.Ptr {
        check_list = append(check_list, "ptr:" + ptr)
    }
    for _, redirect := range cfg.Redirect {
        log.Printf("Redirect not supported.  %s", redirect)
    }
    check_list = append(check_list, cfg.Policy)
    return check_list
}


func deduplicateAddressRanges(result []string) []string {
    /* TODO: Implement de-duplication
    for _, a := range(result) {
        log.Printf("%s\n", a)
    }*/
    fmt.Printf(blue("De-duplication address ranges unavailable.\n"))
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
        if len(current_record + " " + record + " " + cfg.Policy) > spf_max_chars {
            spf_records = append(spf_records,  current_record + " " + cfg.Policy)
            current_record = fmt.Sprintf("v=%s %s", cfg.Version, record)
            suffix = string([]byte(suffix)[0]+1)
            root_spf += fmt.Sprintf(" include:spf%s.%s", suffix, domain)
        } else {
            current_record = fmt.Sprintf("%s %s", current_record, record)
        }
        if i == len(result) - 1 {
            spf_records = append(spf_records, fmt.Sprintf("%s %s", current_record, cfg.Policy))
        }
    }
    root_spf += " " + cfg.Policy
    // Insert the root spf at the beginning of the array and return the result.
    return append(spf_records[:0], append([]string{root_spf}, spf_records[0:]...)...)
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

func updatePdns(result []string, cfg *Config) {
    // Call getOwnDomainSPF when not using PowerDNS
    //own_spf := getOwnDomainSPF(cfg)
    rrecords := getPowerDNS(cfg.Domain, cfg)
    records := convertRRSetToString(rrecords)

	for i, r := range result {
		fmt.Println(yellow(fmt.Sprintf("%d) %s", i, r)))
	}

    sort.Strings(result)
    sort.Strings(records)

    fmt.Printf("DNS entities new=%d, original=%d\n", len(result), len(records))
    if len(result) == len(records) {
        for i, _ := range(result) {
            fmt.Println(result[i] == records[i])
            for _, f := range(strings.Split(result[i], " ")) {
                fmt.Printf("%s\n", yellow(f))
            }
            for _, f := range(strings.Split(records[i], " ")) {
                fmt.Printf("%s\n", green(f))
            }
        }
    } else {
        fmt.Println("SPF has changed, update DNS records")
        createTxtPowerDNS(result)
    }
}


func getOwnDomainSPF(cfg *Config) []string {
/*
 * Use DNS lookups to retrieve exist SPF records for the domain.
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
        MaxIdleConns: 10,
        IdleConnTimeout: 30 * time.Second,
        DisableCompression: true,
        TLSClientConfig: &tls.Config {
            ServerName: api_url.Hostname(),
        },
        TLSHandshakeTimeout: 10 * time.Second,
    }

    r := http.Request{
        Method: "GET",
        URL: api_url,
        Body: nil,
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
        log.Fatal("Error communicating with "+api_url.String()+" "+resp.Status)
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
    // filter results for domain.
    records := []RRSet{}
    name := strings.TrimSuffix(domain_records.Name, ".")
    for _, rr := range(domain_records.Rrsets) {
        if rr.Type == "TXT" && (strings.HasPrefix(rr.Name, name) || strings.HasPrefix(rr.Name, "spf")) {
            for _, r := range(rr.Records){
                if strings.HasPrefix(r.Content, "\"v=spf1") {
                    records = append(records, rr)
                }
            }
        }
    }
    return records
}
