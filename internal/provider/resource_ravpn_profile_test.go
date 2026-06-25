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

const testRavpnProfileResourceName = "ciscosecureaccess_ravpn_profile.test"

func TestAccRavpnProfile_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccRavpn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnProfileBasicConfig(name, "cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnProfileResourceName, "id"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "name", name),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "default_domain", "cisco.com"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "authentication_type", "3"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnProfile_update(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccRavpn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnProfileBasicConfig(name, "cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "default_domain", "cisco.com"),
					),
				},
				{
					Config: testAccRavpnProfileBasicConfig(name, "updated.cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "default_domain", "updated.cisco.com"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnProfile_importState(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccRavpn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnProfileBasicConfig(name, "cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnProfileResourceName, "id"),
					),
				},
				{
					ResourceName:      testRavpnProfileResourceName,
					ImportState:       true,
					ImportStateVerify: true,
					ImportStateVerifyIgnore: []string{"organization_id"},
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnProfile_fullLifecycle(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccRavpn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnFullStackConfig(name, "cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnProfileResourceName, "id"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "name", name),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "default_domain", "cisco.com"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "authentication_type", "3"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "ip_version_mode.ipv4", "true"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "ip_version_mode.ipv6", "false"),
					),
				},
				{
					Config: testAccRavpnFullStackConfig(name, "updated.cisco.com"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "default_domain", "updated.cisco.com"),
					),
				},
				{
					ResourceName:      testRavpnProfileResourceName,
					ImportState:       true,
					ImportStateVerify: true,
					ImportStateVerifyIgnore: []string{"organization_id"},
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnProfile_advancedSettings(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccRavpn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnProfileAdvancedConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testRavpnProfileResourceName, "id"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "advanced_settings.enable_dtls", "true"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "advanced_settings.mtu_value", "1390"),
						resource.TestCheckResourceAttr(testRavpnProfileResourceName, "advanced_settings.banner_message", "Welcome to RAVPN"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccRavpnProfileBasicConfig(name, domain string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ravpn_profile" "test" {
  organization_id     = "8376136"
  name                = %[1]q
  default_domain      = %[2]q
  authentication_type = 3

  ip_version_mode {
    ipv4 = true
    ipv6 = false
  }
}
`, name, domain)
}

func testAccRavpnFullStackConfig(name, domain string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ravpn_dns_server" "profile_dns" {
  organization_id = "8376136"
  server_name     = "%[1]s-dns"
  server_ips      = ["8.8.8.8"]
  priority        = 1
}

resource "ciscosecureaccess_ravpn_headend" "profile_headend" {
  organization_id = "8376136"

  region {
    display_name       = "US West 2"
    endpoint_ip_pool   = ["10.10.0.0/16"]
    management_ip_pool = ["10.0.0.0/22"]
    dns_id             = ciscosecureaccess_ravpn_dns_server.profile_dns.id

    named_ip_pool {
      name            = "ProfilePool"
      ipv4_start_addr = "10.10.0.1"
      ipv4_end_addr   = "10.10.255.254"
      ipv4_subnet_mask = "255.255.0.0"
    }
  }
}

resource "ciscosecureaccess_ravpn_profile" "test" {
  organization_id     = "8376136"
  name                = %[1]q
  default_domain      = %[2]q
  authentication_type = 3
  dns_id              = ciscosecureaccess_ravpn_dns_server.profile_dns.id

  ip_version_mode {
    ipv4 = true
    ipv6 = false
  }

  ip_pools {
    configuration = 1
    region_to_ip_pool {
      region_id    = tolist(ciscosecureaccess_ravpn_headend.profile_headend.region)[0].id
      named_pool_id = tolist(tolist(ciscosecureaccess_ravpn_headend.profile_headend.region)[0].named_ip_pool)[0].id
    }
  }

  authentication_settings {
    authentication_timeout {
      enabled = true
      timeout = 720
    }
    disconnect_on_idle {
      enabled = true
      timeout = 30
    }
  }

  client_profile {
    tunnel_protocol = 1
    local_lan_access = 0
    split_tunneling {
      enabled    = false
      route_type = 0
    }
  }
}
`, name, domain)
}

func testAccRavpnProfileAdvancedConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ravpn_profile" "test" {
  organization_id     = "8376136"
  name                = %[1]q
  default_domain      = "cisco.com"
  authentication_type = 3

  ip_version_mode {
    ipv4 = true
    ipv6 = false
  }

  advanced_settings {
    enable_dtls        = true
    mtu_value          = 1390
    keepalive_interval = 20
    keepalive_retries  = 3
    dead_peer_detection = 300
    rekey_interval     = 3600
    banner_message     = "Welcome to RAVPN"
    max_connection_time {
      enabled = false
      value   = 0
    }
  }
}
`, name)
}
