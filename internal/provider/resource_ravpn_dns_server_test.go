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

const testRavpnDnsServerResourceName = "ciscosecureaccess_ravpn_dns_server.test"

func TestAccRavpnDnsServer_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccDns%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnDnsServerConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnDnsServerResourceName, "id"),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_name", name),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_ips.0", "8.8.8.8"),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "priority", "1"),
					),
				},
				{
					ResourceName:      testRavpnDnsServerResourceName,
					ImportState:       true,
					ImportStateVerify: true,
					ImportStateVerifyIgnore: []string{"organization_id"},
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnDnsServer_multipleIps(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccDns%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnDnsServerMultiIpConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnDnsServerResourceName, "id"),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_name", name),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_ips.#", "2"),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_ips.0", "8.8.8.8"),
						resource.TestCheckResourceAttr(testRavpnDnsServerResourceName, "server_ips.1", "8.8.4.4"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccRavpnDnsServerConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ravpn_dns_server" "test" {
  organization_id = "8376136"
  server_name     = %[1]q
  server_ips      = ["8.8.8.8"]
  priority        = 1
}
`, name)
}

func testAccRavpnDnsServerMultiIpConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ravpn_dns_server" "test" {
  organization_id = "8376136"
  server_name     = %[1]q
  server_ips      = ["8.8.8.8", "8.8.4.4"]
  priority        = 1
}
`, name)
}
