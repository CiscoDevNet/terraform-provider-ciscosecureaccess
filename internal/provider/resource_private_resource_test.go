// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for private resource tests
const (
	// Test configuration constants
	testPrivateResourceNamePrefix = "tfAcc"
	testPrivateResourceAddress    = "10.10.110.2/32"
	testPrivateResourceClientAddr = "10.10.110.2"
	testPrivateResourceDesc       = "Application used for performing tests"

	// Test port and protocol constants
	testPrivateResourcePortHTTPS  = "443"
	testPrivateResourcePortUDP    = "5443"
	testPrivateResourceProtoHTTPS = "http/https"
	testPrivateResourceProtoUDP   = "udp"

	// Access type constants
	testAccessTypeNetwork = "network"
	testAccessTypeClient  = "client"

	// Resource identifiers
	testPrivateResourceName = "ciscosecureaccess_private_resource.test_resource"
)

func TestPrivateResourceResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := generateTestResourceName()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			//CheckDestroy:             testAccCheckPrivateResourceDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceConfig(rName, testAccessTypeNetwork),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_ztna(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := generateTestResourceName()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			//CheckDestroy:             testAccCheckPrivateResourceDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceConfig(rName, testAccessTypeClient),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildClientAccessStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

// generateTestResourceName creates a unique test resource name
func generateTestResourceName() string {
	return fmt.Sprintf("%s%s", testPrivateResourceNamePrefix, acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
}

// buildNetworkAccessStateChecks returns state checks for network access type
func buildNetworkAccessStateChecks(resourceName string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses").AtSliceIndex(0).AtMapKey("addresses"),
			knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceAddress)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeNetwork)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("description"),
			knownvalue.StringExact(testPrivateResourceDesc)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("name"),
			knownvalue.StringExact(resourceName)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses").AtSliceIndex(0).AtMapKey("traffic_selector").AtSliceIndex(0).AtMapKey("ports"),
			knownvalue.StringExact(testPrivateResourcePortHTTPS)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses").AtSliceIndex(0).AtMapKey("traffic_selector").AtSliceIndex(0).AtMapKey("protocol"),
			knownvalue.StringExact(testPrivateResourceProtoHTTPS)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses").AtSliceIndex(0).AtMapKey("traffic_selector").AtSliceIndex(1).AtMapKey("ports"),
			knownvalue.StringExact(testPrivateResourcePortUDP)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses").AtSliceIndex(0).AtMapKey("traffic_selector").AtSliceIndex(1).AtMapKey("protocol"),
			knownvalue.StringExact(testPrivateResourceProtoUDP)),
	}
}

// buildClientAccessStateChecks returns state checks for client access type
func buildClientAccessStateChecks(resourceName string) []statecheck.StateCheck {
	checks := buildNetworkAccessStateChecks(resourceName)

	// Add client-specific checks
	clientChecks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("client_reachable_addresses"),
			knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceClientAddr)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeClient)})),
	}

	// Replace the access_types check from network checks with client-specific one
	filteredChecks := make([]statecheck.StateCheck, 0, len(checks))
	for _, check := range checks {
		// Skip the original access_types check since we're adding a client-specific one
		filteredChecks = append(filteredChecks, check)
	}

	return append(filteredChecks[:1], append(clientChecks, filteredChecks[2:]...)...)
}

// testAccPrivateResourceConfig generates Terraform configuration for private resource tests
func testAccPrivateResourceConfig(name, accessType string) string {
	var clientAddresses string
	if accessType == testAccessTypeClient {
		clientAddresses = fmt.Sprintf(`client_reachable_addresses = ["%s"]`, testPrivateResourceClientAddr)
	}

	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource" "test_resource" {
  name         = "%s"
  access_types = ["%s"]
  description  = "%s"
  %s
  addresses = [{
    addresses = ["%s"]
    traffic_selector = [
      { ports = "%s", protocol = "%s" },
      { ports = "%s", protocol = "%s" }
    ]
  }]
}`, name, accessType, testPrivateResourceDesc, clientAddresses,
		testPrivateResourceAddress,
		testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS,
		testPrivateResourcePortUDP, testPrivateResourceProtoUDP)
}
