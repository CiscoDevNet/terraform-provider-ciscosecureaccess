// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
			CheckDestroy:             testAccCheckInternalNetworkDestroy,
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
			CheckDestroy:             testAccCheckInternalNetworkDestroy,
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
resource "ciscosecureaccess_site" "test_site" {
  name = %q
}

resource "ciscosecureaccess_internal_network" "test_resource" {
  name          = %q
  ip_address    = %q
  prefix_length = %d
  site_id       = ciscosecureaccess_site.test_site.id
}
`, name+"-site", name, testInternalNetworkIPAddress, testInternalNetworkPrefixLength)
}

func testAccCheckInternalNetworkDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetInternalNetworksClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_internal_network" {
			continue
		}
		id := atoi64(rs.Primary.ID)
		_, httpRes, _ := c.InternalNetworksAPI.GetInternalNetwork(ctx, id).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("internal network %d still exists after destroy", id)
		}
	}
	return nil
}
