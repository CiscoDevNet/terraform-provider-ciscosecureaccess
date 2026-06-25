// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const testRavpnHeadendResourceName = "ciscosecureaccess_ravpn_headend.test"

func TestAccRavpnHeadend_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnHeadendConfig(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnHeadendResourceName, "id"),
						resource.TestCheckResourceAttrSet(testRavpnHeadendResourceName, "rev"),
						resource.TestCheckResourceAttr(testRavpnHeadendResourceName, "organization_id", "8376136"),
					),
				},
				{
					ResourceName:      testRavpnHeadendResourceName,
					ImportState:       true,
					ImportStateVerify: true,
					ImportStateVerifyIgnore: []string{"organization_id"},
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnHeadend_updateRegion(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnHeadendConfig(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnHeadendResourceName, "id"),
					),
				},
				{
					Config: testAccRavpnHeadendUpdatedConfig(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnHeadendResourceName, "id"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccRavpnHeadendConfig() string {
	return `
resource "ciscosecureaccess_ravpn_dns_server" "headend_dns" {
  organization_id = "8376136"
  server_name     = "tfAccHeadendDns"
  server_ips      = ["8.8.8.8"]
  priority        = 1
}

resource "ciscosecureaccess_ravpn_headend" "test" {
  organization_id = "8376136"

  region {
    display_name       = "US West 2"
    endpoint_ip_pool   = ["10.10.0.0/16"]
    management_ip_pool = ["10.0.0.0/22"]
    dns_id             = ciscosecureaccess_ravpn_dns_server.headend_dns.id

    named_ip_pool {
      name            = "TestPool1"
      ipv4_start_addr = "10.10.0.1"
      ipv4_end_addr   = "10.10.255.254"
      ipv4_subnet_mask = "255.255.0.0"
    }
  }
}
`
}

func testAccRavpnHeadendUpdatedConfig() string {
	return `
resource "ciscosecureaccess_ravpn_dns_server" "headend_dns" {
  organization_id = "8376136"
  server_name     = "tfAccHeadendDns"
  server_ips      = ["8.8.8.8"]
  priority        = 1
}

resource "ciscosecureaccess_ravpn_headend" "test" {
  organization_id = "8376136"

  region {
    display_name       = "US West 2"
    endpoint_ip_pool   = ["10.10.0.0/16"]
    management_ip_pool = ["10.0.0.0/22"]
    dns_id             = ciscosecureaccess_ravpn_dns_server.headend_dns.id

    named_ip_pool {
      name            = "TestPool1"
      ipv4_start_addr = "10.10.0.1"
      ipv4_end_addr   = "10.10.255.254"
      ipv4_subnet_mask = "255.255.0.0"
    }

    named_ip_pool {
      name            = "TestPool2"
      ipv4_start_addr = "10.11.0.1"
      ipv4_end_addr   = "10.11.255.254"
      ipv4_subnet_mask = "255.255.0.0"
    }
  }
}
`
}
