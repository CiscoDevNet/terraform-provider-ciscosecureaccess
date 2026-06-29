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
	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const testApplicationListResourceName = "ciscosecureaccess_application_list.test"

func TestAccApplicationList_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		fixtures, err := testApplicationCatalogFixtures(t)
		if err != nil {
			t.Fatalf("failed to get application-list fixtures: %v", err)
		}
		name := "tfAcc-app-list-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
		t.Cleanup(func() { testAccCleanupApplicationListByName(t, name) })

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckApplicationListDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccApplicationListConfig(name, nil, nil),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testApplicationListResourceName, "id"),
						resource.TestCheckResourceAttr(testApplicationListResourceName, "name", name),
						resource.TestCheckResourceAttr(testApplicationListResourceName, "application_ids.#", "0"),
						resource.TestCheckResourceAttr(testApplicationListResourceName, "application_category_ids.#", "0"),
						resource.TestCheckResourceAttr(testApplicationListResourceName, "is_default", "false"),
					),
				},
				{
					Config: testAccApplicationListConfig(
						name,
						[]int64{fixtures.avcApplication.GetId()},
						[]int64{fixtures.applicationCategory.GetId()},
					),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testApplicationListResourceName, "application_ids.#", "1"),
						resource.TestCheckResourceAttr(testApplicationListResourceName, "application_category_ids.#", "1"),
					),
				},
				{
					ResourceName:      testApplicationListResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func testAccApplicationListConfig(name string, applicationIDs, applicationCategoryIDs []int64) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_application_list" "test" {
  name                     = %q
  application_ids          = %s
  application_category_ids = %s
}
`, name, terraformInt64List(applicationIDs), terraformInt64List(applicationCategoryIDs))
}

func terraformInt64List(values []int64) string {
	if len(values) == 0 {
		return "[]"
	}
	result := "["
	for index, value := range values {
		if index > 0 {
			result += ", "
		}
		result += strconv.FormatInt(value, 10)
	}
	return result + "]"
}

func testAccCheckApplicationListDestroy(state *terraform.State) error {
	ctx := context.Background()
	apiClient, err := testAccRulesClient(ctx)
	if err != nil {
		return err
	}
	for _, stateResource := range state.RootModule().Resources {
		if stateResource.Type != "ciscosecureaccess_application_list" {
			continue
		}
		id, err := strconv.ParseInt(stateResource.Primary.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse application list ID %q: %w", stateResource.Primary.ID, err)
		}
		_, httpResponse, readErr := apiClient.ApplicationListsAPI.GetApplicationList(ctx, id).Execute()
		closeApplicationListResponse(httpResponse)
		if httpResponse != nil && httpResponse.StatusCode == http.StatusNotFound {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("verify application list %d deletion: %w", id, readErr)
		}
		return fmt.Errorf("application list %d still exists after destroy", id)
	}
	return nil
}

func testAccCleanupApplicationListByName(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	apiClient, err := testAccRulesClient(ctx)
	if err != nil {
		t.Errorf("cleanup application list %q: %v", name, err)
		return
	}
	applicationLists, httpResponse, err := apiClient.ApplicationListsAPI.GetApplicationLists(ctx).Execute()
	closeApplicationListResponse(httpResponse)
	if err != nil {
		t.Errorf("cleanup list application lists for %q: %v", name, err)
		return
	}
	if applicationLists == nil {
		return
	}
	for _, applicationList := range applicationLists.Results {
		if applicationList.ApplicationListName == nil || applicationList.GetApplicationListName() != name || applicationList.GetIsDefault() {
			continue
		}
		if applicationList.ApplicationListId == nil {
			t.Errorf("cleanup application list %q: matching list has no ID", name)
			continue
		}
		_, deleteResponse, deleteErr := apiClient.ApplicationListsAPI.DeleteApplicationList(ctx, applicationList.GetApplicationListId()).Execute()
		status := applicationListResponseStatus(deleteResponse)
		closeApplicationListResponse(deleteResponse)
		if deleteErr != nil && status != http.StatusNotFound && !applicationListSuccessfulStatus(status) {
			t.Errorf("cleanup application list %q (%d): %v", name, applicationList.GetApplicationListId(), deleteErr)
		}
	}
}

func testAccRulesClient(ctx context.Context) (*rules.APIClient, error) {
	factory, err := client.NewSSEClientFactory(
		os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("create client factory: %w", err)
	}
	return factory.GetRulesClient(ctx), nil
}
