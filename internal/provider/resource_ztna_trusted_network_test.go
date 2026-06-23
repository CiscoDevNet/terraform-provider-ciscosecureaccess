// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const testZtnaTrustedNetworkResourceName = "ciscosecureaccess_ztna_trusted_network.test"

func TestAccZtnaTrustedNetwork_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaTrustedNetworkBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testZtnaTrustedNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "network_name", name),
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "interface_type", "0"),
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "is_default", "false"),
						resource.TestCheckResourceAttrSet(testZtnaTrustedNetworkResourceName, "rev"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaTrustedNetwork_update(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		updatedName := name + "-updated"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaTrustedNetworkBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "network_name", name),
					),
				},
				{
					Config: testAccZtnaTrustedNetworkBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "network_name", updatedName),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaTrustedNetworkBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[1]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    dns_domains = [{
      name = "test.scalex.local"
    }]
  }
}
`, name)
}
