package main

import (
	"testing"

	"better-gh/internal/config"
)

func TestValidatePublicGHEConfigAllowsPrivateLoopbackBootstrap(t *testing.T) {
	cfg := &config.Config{Mode: "ghe", Bind: "127.0.0.1:7843"}
	if err := validatePublicGHEConfig(cfg); err != nil {
		t.Fatalf("validatePublicGHEConfig(loopback) = %v", err)
	}
}

func TestValidatePublicGHEConfigAllowsUnclaimedPublicBootstrap(t *testing.T) {
	cfg := &config.Config{Mode: "ghe", Bind: "127.0.0.1:7843", ExternalURL: "https://proxy.example.com"}
	if err := validatePublicGHEConfig(cfg); err != nil {
		t.Fatalf("validatePublicGHEConfig(public) = %v", err)
	}
}

func TestValidatePublicGHEConfigRejectsNonHTTPSExternalURL(t *testing.T) {
	cfg := &config.Config{Mode: "both", Bind: "127.0.0.1:7843", ExternalURL: "http://proxy.example.com"}
	if err := validatePublicGHEConfig(cfg); err == nil {
		t.Fatal("expected non-https external_url to be rejected")
	}
}

func TestValidatePublicGHEConfigRejectsInvalidHostname(t *testing.T) {
	cfg := &config.Config{Mode: "both", Bind: "127.0.0.1:7843", ExternalURL: "https://bad_name.example.com"}
	if err := validatePublicGHEConfig(cfg); err == nil {
		t.Fatal("expected invalid hostname to be rejected")
	}
}
