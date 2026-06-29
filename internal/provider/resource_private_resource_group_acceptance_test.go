// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const testPrivateResourceGroupResourceName = "ciscosecureaccess_private_resource_group.test"

func TestAccPrivateResourceGroup_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := "tfAcc-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckPrivateResourceGroupDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceGroupConfig(name, "Initial description"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceGroupResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceGroupResourceName, "name", name),
						resource.TestCheckResourceAttr(testPrivateResourceGroupResourceName, "description", "Initial description"),
						resource.TestCheckResourceAttr(testPrivateResourceGroupResourceName, "resource_ids.#", "0"),
					),
				},
				{
					Config: testAccPrivateResourceGroupConfig(name+"-updated", "Updated description"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testPrivateResourceGroupResourceName, "name", name+"-updated"),
						resource.TestCheckResourceAttr(testPrivateResourceGroupResourceName, "description", "Updated description"),
					),
				},
				{
					ResourceName:      testPrivateResourceGroupResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func testAccPrivateResourceGroupConfig(name, description string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource_group" "test" {
  name         = %q
  description  = %q
  resource_ids = []
}
`, name, description)
}

func testAccCheckPrivateResourceGroupDestroy(state *terraform.State) error {
	ctx := context.Background()
	factory, err := client.NewSSEClientFactory(
		os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
		"",
	)
	if err != nil {
		return fmt.Errorf("create client factory: %w", err)
	}
	apiClient := factory.GetPrivateAppsClient(ctx)

	for _, stateResource := range state.RootModule().Resources {
		if stateResource.Type != "ciscosecureaccess_private_resource_group" {
			continue
		}
		id, err := strconv.ParseInt(stateResource.Primary.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse private resource group ID %q: %w", stateResource.Primary.ID, err)
		}
		_, httpResp, readErr := apiClient.ResourceGroupsAPI.GetPrivateResourceGroup(ctx, id).Execute()
		if httpResp != nil && httpResp.Body != nil {
			_ = httpResp.Body.Close()
		}
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("verify private resource group %d deletion: %w", id, readErr)
		}
		return fmt.Errorf("private resource group %d still exists after destroy", id)
	}
	return nil
}
