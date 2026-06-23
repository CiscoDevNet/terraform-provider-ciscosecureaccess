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

func TestAccZtnaProfile_enforcementPause(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccEp%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileEnforcementPauseConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_private_access.enforcement_pause.enabled", "true"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_private_access.enforcement_pause.duration_minutes", "15"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.enforcement_pause.enabled", "true"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.enforcement_pause.duration_minutes", "30"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_dnsSteeringDestinations(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccDns%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileDnsSteeringConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_private_access.dns_steering_destination_ids.#", "1"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_private_access.trusted_networks_enabled", "false"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_steeringModeTransition(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccSmt%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileSteeringModeConfig(name, 0),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.steering_mode", "0"),
					),
				},
				{
					Config: testAccZtnaProfileSteeringModeConfig(name, 1),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.steering_mode", "1"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_updatePriority(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccPri%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfilePriorityConfig(name, 1),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "priority", "1"),
					),
				},
				{
					Config: testAccZtnaProfilePriorityConfig(name, 5),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "priority", "5"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_spaTndEnabled(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccSpaTnd%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileSPATNDConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_private_access.trusted_networks_enabled", "true"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.steering_mode", "0"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfileEnforcementPauseConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled          = true
      duration_minutes = 15
    }
  }

  secure_internet_access = {
    steering_mode            = 1
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled          = true
      duration_minutes = 30
    }
  }

  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}
`, name)
}

func testAccZtnaProfileDnsSteeringConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "helper" {
  profile_name = "%[1]s-h"
  priority     = 2

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_private_steering_destination" "dns_dest" {
  profile_id = ciscosecureaccess_ztna_profile.helper.id
  endpoint   = "*.dns-steer.example.com"
  exclusions = []
}

resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled     = false
    enforcement_pause            = { enabled = false }
    dns_steering_destination_ids = [ciscosecureaccess_ztna_private_steering_destination.dns_dest.id]
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}
`, name)
}

func testAccZtnaProfileSteeringModeConfig(name string, mode int) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }

  secure_internet_access = {
    steering_mode            = %[2]d
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }

  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}
`, name, mode)
}

func testAccZtnaProfilePriorityConfig(name string, priority int) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = %[2]d

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }

  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }

  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}
`, name, priority)
}

func testAccZtnaProfileSPATNDConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = true
    enforcement_pause = { enabled = false }
  }

  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }

  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}
`, name)
}
