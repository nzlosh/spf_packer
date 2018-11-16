package main

import
(
	"testing"
	"fmt"
	"reflect"
)

func TestProcessConfiguration(t *testing.T) {
	c := []string{
		"v=spf1",
		"ip4:127.0.0.1/8",
		"ip6:::1",
		"include:lookupdomain.test",
		"include:lookupdomain2.test",
		"a:mailhost.domain.test",
		"mx:mx1.domain.test",
		"mx:mx2.domain.test",
		"~all",
	}
	cfg := Config{
		Version: "spf1",
		Domain: "mydomain.test",
		SpfMaxChars: 500,
		Rawtxt: "include: anotherdomain.test",
		Policy: "~all",
		Ipv4: []string{"127.0.0.1/8"},
		Ipv6: []string{"::1"},
		Includes: []string{"lookupdomain.test", "lookupdomain2.test"},
		A: []string{"mailhost.domain.test"},
		Mx: []string{"mx1.domain.test", "mx2.domain.test"},
		Redirect: make([]string, 1),
		Ptr: []string{},
	}
	r := processConfiguration(&cfg)
	v := reflect.ValueOf(r)
	fmt.Println(v.Type())
	v = reflect.ValueOf(c)
	fmt.Println(v.Type())
	if ! reflect.DeepEqual(r, c) {
		t.Errorf("Process configuration expected %q but got %q.", c, r)
	}
	return
}
