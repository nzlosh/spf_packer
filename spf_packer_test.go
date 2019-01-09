package main

import (
	"testing"
)

func TestFake(t *testing.T) {
	r := resolveInclude("dailymotion.com")
	if len(r) == 0 {
		t.Error("Got an empty reponse.")
	}
}
