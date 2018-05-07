package main

import
(
	"os"
	"fmt"
	"log"
	"net"
	"errors"
	"strings"
	"gopkg.in/yaml.v2"
)

func main() {
	cfg := LoadConfig(os.Args[0]+".yaml")
	result := processConfiguration(cfg)
	result = expandFields(result)
	outputSpfText(result, cfg)
}

type Config struct {
	Version string
	Domain string
	SpfMaxChars int
	Policy string
	Ipv4 []string
	Ipv6 []string
	Includes []string
	A []string
	Mx []string
	Redirect []string
	Ptr []string
}

func processConfiguration(cfg *Config) []string {
	check_list := []string{"v=" + cfg.Version + " "}
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
		log.Printf("Ignoring text, appears to be invalid spf. %s\n", spf_text)
	}
	return fields
}

func expandFields(result []string) []string {
	spf_set := []string{}
	for _, field := range result {
		if field == "v=spf1" {
			continue
		}
		if strings.HasSuffix(field, "all") && strings.ContainsAny(string(field[0]), "+-%~") {
			continue
		}
		p := "a:"
		if strings.HasPrefix(field, p) {
			ips := resolveA(field[len(p):])
			//~ for _, ip := range ips {
				//~ fmt.Printf("a:%s/32\n", ip)
			//~ }
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

func outputSpfText(result []string, cfg *Config) {
	domain := cfg.Domain
	suffix := "a"
	include_spf := "include:spf_" + suffix + "." + domain
	spf_records := []string{}
	current_record := "v=" + cfg.Version
	spf_max_chars := cfg.SpfMaxChars

	for i, record := range result {
		if len( current_record + " " + record + " " + include_spf + " " + cfg.Policy) > spf_max_chars {
			spf_records = append(spf_records,  current_record + " " + include_spf + " " + cfg.Policy)
			current_record = "v=" + cfg.Version + " " + record
			suffix = string([]byte(suffix)[0]+1)
			include_spf = "include:spf_" + suffix + "." + domain
		} else {
			current_record += " " + record
		}
		if i == len(result)-1 {
			spf_records = append(spf_records, current_record + " " + cfg.Policy)
		}
	}
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
