package main

import (
	"reflect"
	"testing"
)

func TestFake(t *testing.T) {
	r := resolveInclude("dailymotion.com")
	if len(r) == 0 {
		t.Error("Got an empty reponse.")
	}
}

func TestDedupeAddressRangesDeduplication(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"dupe", "dupe", "dupe"})
	expectedOut := []string{"dupe"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't remove duplicates properly: expected %s, got %s", expectedOut, actualOut)
	}
}

func TestDedupeAddressRangesDeduplicationSorting(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"b", "a", "c"})
	expectedOut := []string{"a", "b", "c"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't return results sorted: expected %s, got %s", expectedOut, actualOut)
	}
}

func TestDedupeAddressRangesOverlap(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"ip4:192.168.1.0/24", "ip4:192.168.1.2", "ip4:192.168.2.2"})
	expectedOut := []string{"ip4:192.168.1.0/24", "ip4:192.168.2.2"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't remove network owerlaps properly: expected %s, got %s", expectedOut, actualOut)
	}
}

func TestDedupeAddressRangesOverlap30(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"ip4:192.168.1.0/30", "ip4:192.168.1.2", "ip4:192.168.1.4"})
	expectedOut := []string{"ip4:192.168.1.0/30", "ip4:192.168.1.4"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't remove /30 network owerlaps properly: expected %s, got %s", expectedOut, actualOut)
	}
}

func TestDedupeAddressRangesOverlapIPv6(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"ip6:1:5ee:bad:c0de::/64", "ip6:1:5ee:bad:c0de:0:0:0:1", "ip6:1:5ee:bad:cafe:0:0:0:1"})
	expectedOut := []string{"ip6:1:5ee:bad:c0de::/64", "ip6:1:5ee:bad:cafe:0:0:0:1"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't remove ipv6 network owerlaps properly: expected %s, got %s", expectedOut, actualOut)
	}
}

func TestDedupeAddressRangesOverlap52IPv6(t *testing.T) {
	actualOut := deduplicateAddressRanges([]string{"ip6:1:5ee:bad:c0de::/52", "ip6:1:5ee:bad:c0de:0:0:0:1", "ip6:1:5ee:bad:cafe:0:0:0:1"})
	expectedOut := []string{"ip6:1:5ee:bad:c0de::/52"}
	if !reflect.DeepEqual(actualOut, expectedOut) {
		t.Errorf("Deduplication didn't remove ipv6 network owerlaps properly: expected %s, got %s", expectedOut, actualOut)
	}
}
