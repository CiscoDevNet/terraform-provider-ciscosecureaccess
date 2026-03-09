// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"
)

func TestValidateDestinationForType_ipv4(t *testing.T) {
	ipv4Type, ok := allowedDestinationTypeByName("ipv4")
	if !ok {
		t.Fatal("expected ipv4 type in destinationlists.AllowedModelTypeEnumValues")
	}

	if err := validateDestinationForType(string(ipv4Type), "127.0.0.2"); err != nil {
		t.Fatalf("expected valid IPv4 destination, got error: %v", err)
	}

	if err := validateDestinationForType(string(ipv4Type), "192.168.0.0/16"); err != nil {
		t.Fatalf("expected valid IPv4 destination, got error: %v", err)
	}

	if err := validateDestinationForType(string(ipv4Type), "example.com"); err == nil {
		t.Fatal("expected invalid IPv4 destination error, got nil")
	}
}

func TestValidateDestinationForType_domain(t *testing.T) {
	domainType, ok := allowedDestinationTypeByName("domain")
	if !ok {
		t.Fatal("expected domain type in destinationlists.AllowedModelTypeEnumValues")
	}

	if err := validateDestinationForType(string(domainType), "foo.bar.baz"); err != nil {
		t.Fatalf("expected valid domain destination, got error: %v", err)
	}

	if err := validateDestinationForType(string(domainType), "http://example.com"); err == nil {
		t.Fatal("expected invalid domain destination error, got nil")
	}
}

func TestValidateDestinationForType_url(t *testing.T) {
	urlType, ok := allowedDestinationTypeByName("url")
	if !ok {
		t.Fatal("expected url type in destinationlists.AllowedModelTypeEnumValues")
	}

	if err := validateDestinationForType(string(urlType), "http://example.com/path"); err != nil {
		t.Fatalf("expected valid url destination, got error: %v", err)
	}

	err := validateDestinationForType(string(urlType), "http://example.com")
	if err == nil {
		t.Fatal("expected invalid url destination error for empty path, got nil")
	}

	if !strings.Contains(err.Error(), "non-empty path") {
		t.Fatalf("expected non-empty path guidance, got: %v", err)
	}

	if !strings.Contains(err.Error(), "domain") {
		t.Fatalf("expected domain recommendation in error, got: %v", err)
	}
}

func TestValidateDestinationExtraCases(t *testing.T) {
	// domain with two labels should be valid
	domainType, ok := allowedDestinationTypeByName("domain")
	if !ok {
		t.Fatal("expected domain type in destinationlists.AllowedModelTypeEnumValues")
	}

	if err := validateDestinationForType(string(domainType), "bar.gaz"); err != nil {
		t.Fatalf("expected valid domain destination 'bar.gaz', got error: %v", err)
	}

	// single-label domains should be valid
	if err := validateDestinationForType(string(domainType), "us"); err != nil {
		t.Fatalf("expected valid domain destination 'us', got error: %v", err)
	}
	if err := validateDestinationForType(string(domainType), "com"); err != nil {
		t.Fatalf("expected valid domain destination 'com', got error: %v", err)
	}

	// CIDR block should be valid for IPV4 type
	ipv4Type, ok := allowedDestinationTypeByName("ipv4")
	if !ok {
		t.Fatal("expected ipv4 type in destinationlists.AllowedModelTypeEnumValues")
	}
	if err := validateDestinationForType(string(ipv4Type), "192.168.1.0/24"); err != nil {
		t.Fatalf("expected valid IPv4/CIDR destination '192.168.1.0/24', got error: %v", err)
	}
}
