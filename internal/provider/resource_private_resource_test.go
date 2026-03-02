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
	testPrivateResourceFixedName  = "TFP Network Test Resource"
	testPrivateResourceAddress    = "10.10.110.2/32"
	testPrivateResourceClientAddr = "10.10.110.2"
	testPrivateResourceDesc       = "Application used for performing tests"

	// Test port and protocol constants
	testPrivateResourcePortHTTPS  = "443"
	testPrivateResourcePortUDP    = "5443"
	testPrivateResourcePortSSH    = "22"
	testPrivateResourcePortRDP    = "3389"
	testPrivateResourceProtoHTTPS = "http/https"
	testPrivateResourceProtoUDP   = "udp"
	testPrivateResourceProtoSSH   = "ssh"
	testPrivateResourceProtoRDP   = "rdp-tcp"

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

func TestPrivateResourceResource_networkReportedConfig(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := fmt.Sprintf("%s-%s", testPrivateResourceFixedName, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
				},
				{
					Config:            testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_networkReportedConfigRDP(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := fmt.Sprintf("%s-rdp-%s", testPrivateResourceFixedName, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
				},
				{
					Config:            testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
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
	return buildNetworkAccessStateChecksWithSelectors(resourceName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortUDP, testPrivateResourceProtoUDP)
}

func buildNetworkAccessStateChecksWithSelectors(resourceName, firstPort, firstProtocol, secondPort, secondProtocol string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses"),
			knownvalue.SetExact([]knownvalue.Check{
				knownvalue.ObjectExact(map[string]knownvalue.Check{
					"addresses": knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceAddress)}),
					"traffic_selector": knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"ports":    knownvalue.StringExact(firstPort),
							"protocol": knownvalue.StringExact(firstProtocol),
						}),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"ports":    knownvalue.StringExact(secondPort),
							"protocol": knownvalue.StringExact(secondProtocol),
						}),
					}),
				}),
			})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeNetwork)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("description"),
			knownvalue.StringExact(testPrivateResourceDesc)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("name"),
			knownvalue.StringExact(resourceName)),
	}
}

// buildClientAccessStateChecks returns state checks for client access type
func buildClientAccessStateChecks(resourceName string) []statecheck.StateCheck {
	checks := buildNetworkAccessStateChecks(resourceName)

	// Add client-specific checks
	clientChecks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("client_reachable_addresses"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceClientAddr)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeClient)})),
	}

	return append(checks[:1], append(clientChecks, checks[2:]...)...)
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

func testAccPrivateResourceReportedConfig(name, firstPort, firstProtocol, secondPort, secondProtocol string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource" "test_resource" {
  name         = "%s"
  access_types = ["%s"]
  description  = "%s"
  addresses = [{
    addresses = ["%s"]
    traffic_selector = [
      { ports = "%s", protocol = "%s" },
      { ports = "%s", protocol = "%s" }
    ]
  }]
}`,
		name,
		testAccessTypeNetwork,
		testPrivateResourceDesc,
		testPrivateResourceAddress,
		firstPort,
		firstProtocol,
		secondPort,
		secondProtocol,
	)
}
