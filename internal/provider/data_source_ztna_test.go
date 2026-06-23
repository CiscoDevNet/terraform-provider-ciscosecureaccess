// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceZtnaProfiles_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `data "ciscosecureaccess_ztna_profiles" "all" {}`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("data.ciscosecureaccess_ztna_profiles.all", "profiles.#"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccDataSourceZtnaTrustedNetworks_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `data "ciscosecureaccess_ztna_trusted_networks" "all" {}`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("data.ciscosecureaccess_ztna_trusted_networks.all", "networks.#"),
					),
				},
			},
		})
	}, minWaitTime)
}
