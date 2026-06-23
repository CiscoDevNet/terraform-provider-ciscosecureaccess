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

func TestAccZtnaProfileUserMappings_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccUm%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileUserMappingsConfig(profileName, "user-id-001"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_user_mappings.test", "user_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_user_mappings.test", "user_ids.0", "user-id-001"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileUserMappings_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccUmU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileUserMappingsConfig(profileName, "user-id-001"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_user_mappings.test", "user_ids.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfileUserMappingsMultiConfig(profileName, "user-id-001", "user-id-002"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_user_mappings.test", "user_ids.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileGroupMappings_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccGm%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileGroupMappingsConfig(profileName, "group-id-001"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_group_mappings.test", "group_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_group_mappings.test", "group_ids.0", "group-id-001"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileGroupMappings_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccGmU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileGroupMappingsConfig(profileName, "group-id-001"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_group_mappings.test", "group_ids.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfileGroupMappingsMultiConfig(profileName, "group-id-001", "group-id-002"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_group_mappings.test", "group_ids.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfileUserMappingsConfig(profileName, userId string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = false }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_profile_user_mappings" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id
  user_ids   = [%[2]q]
}
`, profileName, userId)
}

func testAccZtnaProfileUserMappingsMultiConfig(profileName, userId1, userId2 string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = false }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_profile_user_mappings" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id
  user_ids   = [%[2]q, %[3]q]
}
`, profileName, userId1, userId2)
}

func testAccZtnaProfileGroupMappingsConfig(profileName, groupId string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

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
  groups_data = { all_groups_enabled = false }
}

resource "ciscosecureaccess_ztna_profile_group_mappings" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id
  group_ids  = [%[2]q]
}
`, profileName, groupId)
}

func testAccZtnaProfileGroupMappingsMultiConfig(profileName, groupId1, groupId2 string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

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
  groups_data = { all_groups_enabled = false }
}

resource "ciscosecureaccess_ztna_profile_group_mappings" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id
  group_ids  = [%[2]q, %[3]q]
}
`, profileName, groupId1, groupId2)
}
