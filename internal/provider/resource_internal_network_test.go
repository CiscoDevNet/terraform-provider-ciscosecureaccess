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

// Test constants for internal network resource tests
const (
	testInternalNetworkResourceName  = "ciscosecureaccess_internal_network.test_resource"
	testInternalNetworkNamePrefix    = "tfAcc"
	testInternalNetworkIPAddress     = "198.51.100.0"
	testInternalNetworkPrefixLength  = 24
	testInternalNetworkUpdatedSuffix = "updated"
)

// generateInternalNetworkTestName creates a unique test name for internal network tests
func generateInternalNetworkTestName(suffix string) string {
	return fmt.Sprintf("%s%s-%s", testInternalNetworkNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

func TestInternalNetworkResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateInternalNetworkTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalNetworkBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", testName),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "ip_address", testInternalNetworkIPAddress),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "prefix_length", fmt.Sprintf("%d", testInternalNetworkPrefixLength)),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("ip_address"), knownvalue.StringExact(testInternalNetworkIPAddress)),
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("prefix_length"), knownvalue.Int64Exact(testInternalNetworkPrefixLength)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestInternalNetworkResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateInternalNetworkTestName("update")
		updatedName := generateInternalNetworkTestName(testInternalNetworkUpdatedSuffix)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalNetworkBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", testName),
					),
				},
				{
					Config: testAccInternalNetworkBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", updatedName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccInternalNetworkBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_internal_network" "test_resource" {
  name          = %q
  ip_address    = %q
  prefix_length = %d
}
`, name, testInternalNetworkIPAddress, testInternalNetworkPrefixLength)
}
