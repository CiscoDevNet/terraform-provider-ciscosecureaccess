// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccAccessPolicyMigrationLifecycle(t *testing.T) {
	rateLimitedTest(t, func() {
		name := "tfAcc-access-policy-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
		t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, name) })
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckAccessPolicyDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyMigrationConfig(name, "443", "TCP"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testAccessPolicyResourceName, "id"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "name", name),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "action", "allow"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "enabled", "false"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "source_all", "true"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "inline_destinations.#", "1"),
					),
				},
				{
					Config: testAccAccessPolicyMigrationConfig(name, "53", "UDP"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "action", "allow"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "enabled", "false"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "inline_destinations.#", "1"),
					),
				},
				{
					ResourceName:      testAccessPolicyResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func TestAccAccessPolicyWarnLifecycle(t *testing.T) {
	rateLimitedTest(t, func() {
		categoryListID, webProfileID := testAccAccessPolicyWarnFixtures(t)
		name := "tfAcc-access-policy-warn-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
		t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, name) })
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckAccessPolicyDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyWarnConfig(name, categoryListID, webProfileID),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testAccessPolicyResourceName, "id"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "name", name),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "action", "warn"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "enabled", "false"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "source_all", "true"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "content_category_list_ids.#", "1"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "web_profile_id", strconv.FormatInt(webProfileID, 10)),
					),
				},
				{
					ResourceName:      testAccessPolicyResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func TestAccAccessPolicyPublicFamiliesLifecycle(t *testing.T) {
	rateLimitedTest(t, func() {
		regularApplicationID, advancedApplicationID, categoryID := testAccAccessPolicyPublicFixtures(t)
		webProfileID := testAccPolicySettingInt64(t, "umbrella.posture.webProfileId")
		ipsProfileID := testAccPolicySettingInt64(t, "umbrella.posture.ipsProfileId")
		name := "tfAcc-access-policy-public-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
		t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, name) })

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckAccessPolicyDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyPublicApplicationConfig(name, regularApplicationID, advancedApplicationID, webProfileID, ipsProfileID),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "application_ids.#", "1"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "advanced_application_ids.#", "1"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "allow_password_protected_files", "true"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "web_profile_id", strconv.FormatInt(webProfileID, 10)),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "ips_profile_id", strconv.FormatInt(ipsProfileID, 10)),
					),
				},
				{
					Config: testAccAccessPolicyPublicCategoryConfig(name, categoryID, webProfileID, ipsProfileID),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "application_ids.#", "0"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "category_ids.#", "1"),
						resource.TestCheckResourceAttr(testAccessPolicyResourceName, "advanced_application_ids.#", "0"),
					),
				},
				{
					ResourceName:      testAccessPolicyResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func TestAccAccessPolicyPriorityReorder(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}
	testAccMutationPreCheck(t)
	rateLimitedTest(t, func() {
		ctx := context.Background()
		apiClient, err := testAccRulesClient(ctx)
		if err != nil {
			t.Fatalf("create rules client: %v", err)
		}
		before := testAccAccessPolicyPriorityMap(t, apiClient)
		baseName := "tfAcc-access-policy-priority-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
		names := []string{baseName + "-a", baseName + "-b", baseName + "-c"}
		for _, name := range names {
			fixtureName := name
			t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, fixtureName) })
		}

		createdIDs := make([]int64, 0, len(names))
		for _, name := range names {
			model := testAccPriorityAccessPolicyModel(t, ctx, name)
			payload, diags := formatCreateAccessPolicyRequest(ctx, &model)
			if diags.HasError() {
				t.Fatalf("format priority fixture %q: %v", name, diags)
			}
			created, response, createErr := apiClient.AccessRulesAPI.AddRule(ctx).AddRuleRequest(payload).Execute()
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			if createErr != nil {
				t.Fatalf("create priority fixture %q: %v", name, createErr)
			}
			createdIDs = append(createdIDs, created.GetRuleId())
		}

		created := testAccAccessPolicyPriorities(t, apiClient, createdIDs)
		sort.Slice(created, func(i, j int) bool { return created[i].priority < created[j].priority })
		if created[1].priority != created[0].priority+1 || created[2].priority != created[1].priority+1 {
			t.Fatalf("created fixture priorities are not contiguous: %v", created)
		}

		middleRule, response, err := apiClient.AccessRulesAPI.GetRule(ctx, created[1].id).Execute()
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if err != nil {
			t.Fatalf("read middle priority fixture: %v", err)
		}
		middleModel := accessPolicyResourceModel{ID: types.Int64Value(created[1].id)}
		if diags := flattenAccessPolicyResponse(ctx, middleRule, &middleModel); diags.HasError() {
			t.Fatalf("flatten middle priority fixture: %v", diags)
		}
		middleModel.Priority = types.Int64Value(created[0].priority)
		putPayload, diags := formatPutAccessPolicyRequest(ctx, &middleModel)
		if diags.HasError() {
			t.Fatalf("format middle priority reorder: %v", diags)
		}
		_, response, err = apiClient.AccessRulesAPI.PutRule(ctx, created[1].id).PutRuleRequest(putPayload).Execute()
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if err != nil {
			t.Fatalf("reorder middle priority fixture: %v", err)
		}

		reordered := testAccAccessPolicyPriorities(t, apiClient, createdIDs)
		sort.Slice(reordered, func(i, j int) bool { return reordered[i].priority < reordered[j].priority })
		if reordered[0].id != created[1].id || reordered[0].priority != created[0].priority {
			t.Fatalf("middle fixture was not moved to the requested priority: before=%v after=%v", created, reordered)
		}
		for _, fixture := range reordered {
			rule, readResponse, readErr := apiClient.AccessRulesAPI.GetRule(ctx, fixture.id).Execute()
			if readResponse != nil && readResponse.Body != nil {
				_ = readResponse.Body.Close()
			}
			if readErr != nil || rule.GetRulePriority() != fixture.priority {
				t.Fatalf("refresh fixture %d: summary priority=%d rule=%v error=%v", fixture.id, fixture.priority, rule, readErr)
			}
		}

		for index := len(createdIDs) - 1; index >= 0; index-- {
			response, deleteErr := apiClient.AccessRulesAPI.DeleteRule(ctx, createdIDs[index]).Execute()
			status := 0
			if response != nil {
				status = response.StatusCode
				if response.Body != nil {
					_ = response.Body.Close()
				}
			}
			if deleteErr != nil && status != http.StatusNotFound {
				t.Fatalf("delete priority fixture %d: %v", createdIDs[index], deleteErr)
			}
		}

		after := testAccAccessPolicyPriorityMap(t, apiClient)
		if len(after) != len(before) {
			t.Fatalf("rule count changed after priority cleanup: before=%d after=%d", len(before), len(after))
		}
		for id, priority := range before {
			if after[id] != priority {
				t.Fatalf("existing rule %d priority changed after cleanup: before=%d after=%d", id, priority, after[id])
			}
		}
	}, minWaitTime)
}

func TestAccPhase25DependencyGraph(t *testing.T) {
	rateLimitedTest(t, func() {
		fixtures, err := testApplicationCatalogFixtures(t)
		if err != nil {
			t.Fatalf("discover application catalog fixtures: %v", err)
		}
		clientProfileID := testAccPolicySettingInt64(t, "umbrella.posture.profileIdClientbased")
		webProfileID := testAccPolicySettingInt64(t, "umbrella.posture.webProfileId")
		privateSecurityProfileID := testAccPolicySettingInt64(t, "umbrella.posture.privateSecurityProfileId")
		tenantControlProfileID := testAccPolicySettingInt64(t, "sse.tenantControlProfileId")
		baseName := "tfAcc-p25-graph-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
		applicationListName := baseName + "-application-list"
		publicPolicyName := baseName + "-public-policy"
		privatePolicyName := baseName + "-private-policy"
		t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, publicPolicyName) })
		t.Cleanup(func() { testAccCleanupAccessPolicyByName(t, privatePolicyName) })
		t.Cleanup(func() { testAccCleanupApplicationListByName(t, applicationListName) })

		initialConfig := testAccPhase25DependencyGraphConfig(
			baseName,
			fixtures.avcApplication.GetLabel(),
			fixtures.applicationCategory.GetName(),
			clientProfileID,
			webProfileID,
			privateSecurityProfileID,
			tenantControlProfileID,
			false,
		)
		updatedConfig := testAccPhase25DependencyGraphConfig(
			baseName,
			fixtures.avcApplication.GetLabel(),
			fixtures.applicationCategory.GetName(),
			clientProfileID,
			webProfileID,
			privateSecurityProfileID,
			tenantControlProfileID,
			true,
		)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckPhase25DependencyGraphDestroy,
			Steps: []resource.TestStep{
				{
					Config: initialConfig,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_application_list.graph", "application_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_application_list.graph", "application_category_ids.#", "0"),
						resource.TestCheckResourceAttr("ciscosecureaccess_private_resource_group.graph", "resource_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.public", "application_list_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.public", "source_identity_type_ids.#", "2"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.private", "private_resource_group_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.private", "enabled", "false"),
					),
				},
				{
					Config: updatedConfig,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_application_list.graph", "application_ids.#", "0"),
						resource.TestCheckResourceAttr("ciscosecureaccess_application_list.graph", "application_category_ids.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.public", "description", "Updated chained public policy"),
						resource.TestCheckResourceAttr("ciscosecureaccess_access_policy.private", "description", "Updated chained private policy"),
					),
				},
				{
					Config:   updatedConfig,
					PlanOnly: true,
				},
			},
		})
	}, minWaitTime)
}

func testAccPhase25DependencyGraphConfig(baseName, applicationName, applicationCategoryName string, clientProfileID, webProfileID, privateSecurityProfileID, tenantControlProfileID int64, updated bool) string {
	applicationIDs := "[data.ciscosecureaccess_application.graph.id]"
	applicationCategoryIDs := "[]"
	publicDescription := "Initial chained public policy"
	privateDescription := "Initial chained private policy"
	if updated {
		applicationIDs = "[]"
		applicationCategoryIDs = "[data.ciscosecureaccess_application_category.graph.id]"
		publicDescription = "Updated chained public policy"
		privateDescription = "Updated chained private policy"
	}
	return fmt.Sprintf(`
data "ciscosecureaccess_application" "graph" {
  name = %q
  type = "AVC"
}

data "ciscosecureaccess_application_category" "graph" {
  name = %q
}

resource "ciscosecureaccess_application_list" "graph" {
  name                     = %q
  application_ids          = %s
  application_category_ids = %s
}

resource "ciscosecureaccess_private_resource" "graph" {
  name         = %q
  description  = "Private resource for chained provider acceptance"
  access_types = ["network"]
  addresses = [{
    addresses = ["198.51.100.254/32"]
    traffic_selector = [{
      ports    = "443"
      protocol = "http/https"
    }]
  }]
}

resource "ciscosecureaccess_private_resource_group" "graph" {
  name         = %q
  description  = "Private resource group for chained provider acceptance"
  resource_ids = [tonumber(ciscosecureaccess_private_resource.graph.id)]
}

resource "ciscosecureaccess_access_policy" "public" {
  name                       = %q
  description                = %q
  action                     = "allow"
  enabled                    = false
  log_level                  = "LOG_ALL"
  traffic_type               = "PUBLIC_INTERNET"
  source_identity_type_ids   = [34, 9]
  application_list_ids       = [ciscosecureaccess_application_list.graph.id]
  web_profile_id             = %d
  tenant_control_profile_id  = %d
}

resource "ciscosecureaccess_access_policy" "private" {
  name                        = %q
  description                 = %q
  action                      = "allow"
  enabled                     = false
  log_level                   = "LOG_ALL"
  traffic_type                = "PRIVATE_NETWORK"
  source_all                  = true
  private_resource_group_ids  = [ciscosecureaccess_private_resource_group.graph.id]
  client_posture_profile_id   = %d
  private_security_profile_id = %d
}
`,
		applicationName,
		applicationCategoryName,
		baseName+"-application-list",
		applicationIDs,
		applicationCategoryIDs,
		baseName+"-private-resource",
		baseName+"-private-resource-group",
		baseName+"-public-policy",
		publicDescription,
		webProfileID,
		tenantControlProfileID,
		baseName+"-private-policy",
		privateDescription,
		clientProfileID,
		privateSecurityProfileID,
	)
}

func testAccCheckPhase25DependencyGraphDestroy(state *terraform.State) error {
	checks := []func(*terraform.State) error{
		testAccCheckAccessPolicyDestroy,
		testAccCheckApplicationListDestroy,
		testAccCheckPrivateResourceGroupDestroy,
		testAccCheckPrivateResourceDestroy,
	}
	for _, check := range checks {
		if err := check(state); err != nil {
			return err
		}
	}
	return nil
}

type testAccessPolicyPriority struct {
	id       int64
	priority int64
}

func testAccPriorityAccessPolicyModel(t *testing.T, ctx context.Context, name string) accessPolicyResourceModel {
	t.Helper()
	inline := accessPolicyInlineDestinationModel{
		IPAddresses: mustStringSet(t, ctx, "192.0.2.10"),
		Ports:       mustStringSet(t, ctx, "443"),
		Protocol:    types.StringValue("TCP"),
	}
	inlineSet, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: accessPolicyInlineDestinationModel{}.AttrTypes()}, []accessPolicyInlineDestinationModel{inline})
	if diags.HasError() {
		t.Fatalf("build priority fixture inline destination: %v", diags)
	}
	return accessPolicyResourceModel{
		Name:               types.StringValue(name),
		Action:             types.StringValue("allow"),
		Description:        types.StringValue("Disabled Terraform priority reorder probe"),
		Enabled:            types.BoolValue(false),
		Priority:           types.Int64Null(),
		SourceAll:          types.BoolValue(true),
		InlineDestinations: inlineSet,
		LogLevel:           types.StringValue("LOG_ALL"),
		TrafficType:        types.StringValue("PRIVATE_NETWORK"),
	}
}

func testAccAccessPolicyPriorities(t *testing.T, apiClient *rules.APIClient, ids []int64) []testAccessPolicyPriority {
	t.Helper()
	all := testAccAccessPolicyPriorityMap(t, apiClient)
	priorities := make([]testAccessPolicyPriority, 0, len(ids))
	for _, id := range ids {
		priority, ok := all[id]
		if !ok {
			t.Fatalf("priority fixture %d is missing from the rule list", id)
		}
		priorities = append(priorities, testAccessPolicyPriority{id: id, priority: priority})
	}
	return priorities
}

func testAccAccessPolicyPriorityMap(t *testing.T, apiClient *rules.APIClient) map[int64]int64 {
	t.Helper()
	ruleList, response, err := apiClient.AccessRulesAPI.ListRules(context.Background()).Limit(1000).Execute()
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatalf("list access-policy priorities: %v", err)
	}
	priorities := make(map[int64]int64, len(ruleList.GetResults()))
	for _, rule := range ruleList.GetResults() {
		priorities[rule.GetRuleId()] = rule.GetRulePriority()
	}
	return priorities
}

func testAccAccessPolicyMigrationConfig(name, port, protocol string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
  name         = %q
  description  = "Disabled Terraform migration contract probe"
  action       = "allow"
  enabled      = false
  log_level    = "LOG_ALL"
  traffic_type = "PRIVATE_NETWORK"
  source_all   = true

  inline_destinations = [{
    ip_addresses = ["8.8.8.8"]
    ports        = [%q]
    protocol     = %q
	  }]
}
`, name, port, protocol)
}

func testAccAccessPolicyWarnConfig(name string, categoryListID, webProfileID int64) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
  name                      = %q
  description               = "Disabled Terraform warn action probe"
  action                    = "warn"
  enabled                   = false
  log_level                 = "LOG_ALL"
  traffic_type              = "PUBLIC_INTERNET"
  source_all                = true
	  content_category_list_ids = [%d]
	  web_profile_id            = %d
}
`, name, categoryListID, webProfileID)
}

func testAccAccessPolicyPublicApplicationConfig(name string, applicationID, advancedApplicationID, webProfileID, ipsProfileID int64) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
  name                           = %q
  description                    = "Disabled Terraform public application probe"
  action                         = "allow"
  enabled                        = false
  log_level                      = "LOG_ALL"
  traffic_type                   = "PUBLIC_INTERNET"
  source_all                     = true
  application_ids                = [%d]
  allow_password_protected_files = true
  advanced_application_ids       = [%d]
  web_profile_id                 = %d
  ips_profile_id                 = %d
}
`, name, applicationID, advancedApplicationID, webProfileID, ipsProfileID)
}

func testAccAccessPolicyPublicCategoryConfig(name string, categoryID, webProfileID, ipsProfileID int64) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
  name                           = %q
  description                    = "Disabled Terraform public category probe"
  action                         = "allow"
  enabled                        = false
  log_level                      = "LOG_ALL"
  traffic_type                   = "PUBLIC_INTERNET"
  source_all                     = true
  category_ids                   = [%d]
  allow_password_protected_files = true
  web_profile_id                 = %d
  ips_profile_id                 = %d
}
`, name, categoryID, webProfileID, ipsProfileID)
}

func testAccAccessPolicyPublicFixtures(t *testing.T) (int64, int64, int64) {
	t.Helper()
	ctx := context.Background()
	reportingClient := testClientFactory(t).GetReportsClient(ctx)
	applicationResponse, httpResponse, err := readApplicationCatalog(ctx, reportingClient, "")
	if httpResponse != nil && httpResponse.Body != nil {
		_ = httpResponse.Body.Close()
	}
	if err != nil || applicationResponse == nil {
		t.Fatalf("discover target application fixtures: response=%v error=%v", applicationResponse, err)
	}
	var regularApplicationID, advancedApplicationID int64
	for _, application := range applicationResponse.Data.Applications {
		if application.Id == nil || application.Type == nil || application.GetType() != "AVC" {
			continue
		}
		id := application.GetId()
		if id > 0 && id < 5_000_000 && regularApplicationID == 0 {
			regularApplicationID = id
		}
		if id >= 5_000_000 && advancedApplicationID == 0 {
			advancedApplicationID = id
		}
		if regularApplicationID > 0 && advancedApplicationID > 0 {
			break
		}
	}
	if regularApplicationID == 0 || advancedApplicationID == 0 {
		t.Fatalf("target catalog did not contain regular and advanced AVC application IDs")
	}

	categories, categoryResponse, err := reportingClient.UtilityAPI.GetCategories(ctx).Execute()
	if categoryResponse != nil && categoryResponse.Body != nil {
		_ = categoryResponse.Body.Close()
	}
	if err != nil || categories == nil {
		t.Fatalf("discover target web category fixture: response=%v error=%v", categories, err)
	}
	for _, category := range categories.Data {
		if category.Id > 0 && !category.Deprecated && category.Type == "content" {
			return regularApplicationID, advancedApplicationID, category.Id
		}
	}
	t.Fatal("target catalog did not contain a non-deprecated content category")
	return 0, 0, 0
}

func testAccPolicySettingInt64(t *testing.T, name string) int64 {
	t.Helper()
	ctx := context.Background()
	apiClient := testClientFactory(t).GetRulesClient(ctx)
	setting, response, err := apiClient.RuleSettingsAndDefaultsAPI.GetPolicySetting(ctx, name).Execute()
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil || setting == nil || setting.SettingValue.Int64 == nil {
		t.Fatalf("discover target policy setting %q: setting=%v error=%v", name, setting, err)
	}
	return *setting.SettingValue.Int64
}

func testAccAccessPolicyWarnFixtures(t *testing.T) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	factory := testClientFactory(t)
	webProfileID := testAccPolicySettingInt64(t, "umbrella.posture.webProfileId")
	if webProfileID <= 0 {
		t.Fatal("target web profile policy setting did not contain a positive ID")
	}

	contentClient := factory.GetContentCategoriesClient(ctx)
	categories, categoryResponse, err := contentClient.ContentCategoriesAPI.
		GetCategorySettings(ctx).
		Page(1).
		Limit(100).
		Execute()
	if categoryResponse != nil && categoryResponse.Body != nil {
		_ = categoryResponse.Body.Close()
	}
	if err != nil {
		t.Fatalf("discover target content category list: %v", err)
	}
	for _, category := range categories {
		if category.Id != nil && category.Name != nil && category.GetName() == "Default Web Settings" {
			return category.GetId(), webProfileID
		}
	}
	t.Fatal("target does not contain the Default Web Settings content category list")
	return 0, 0
}

func testAccCheckAccessPolicyDestroy(state *terraform.State) error {
	ctx := context.Background()
	apiClient, err := testAccRulesClient(ctx)
	if err != nil {
		return err
	}
	for _, stateResource := range state.RootModule().Resources {
		if stateResource.Type != "ciscosecureaccess_access_policy" {
			continue
		}
		id, err := strconv.ParseInt(stateResource.Primary.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse access policy ID %q: %w", stateResource.Primary.ID, err)
		}
		_, httpResponse, readErr := apiClient.AccessRulesAPI.GetRule(ctx, id).Execute()
		status := 0
		if httpResponse != nil {
			status = httpResponse.StatusCode
			if httpResponse.Body != nil {
				_ = httpResponse.Body.Close()
			}
		}
		if status == http.StatusNotFound {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("verify access policy %d deletion: %w", id, readErr)
		}
		return fmt.Errorf("access policy %d still exists after destroy", id)
	}
	return nil
}

func testAccCleanupAccessPolicyByName(t *testing.T, name string) {
	t.Helper()
	if os.Getenv("CISCOSECUREACCESS_KEY_ID") == "" || os.Getenv("CISCOSECUREACCESS_KEY_SECRET") == "" {
		return
	}
	ctx := context.Background()
	apiClient, err := testAccRulesClient(ctx)
	if err != nil {
		t.Errorf("cleanup access policy %q: %v", name, err)
		return
	}
	ruleList, response, err := apiClient.AccessRulesAPI.ListRules(ctx).RuleName(name).Limit(100).Execute()
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Errorf("cleanup list access policies for %q: %v", name, err)
		return
	}
	for _, rule := range ruleList.GetResults() {
		if rule.GetRuleName() != name || rule.GetRuleIsDefault() {
			continue
		}
		deleteResponse, deleteErr := apiClient.AccessRulesAPI.DeleteRule(ctx, rule.GetRuleId()).Execute()
		status := 0
		if deleteResponse != nil {
			status = deleteResponse.StatusCode
			if deleteResponse.Body != nil {
				_ = deleteResponse.Body.Close()
			}
		}
		if deleteErr != nil && status != http.StatusNotFound {
			t.Errorf("cleanup access policy %q (%d): %v", name, rule.GetRuleId(), deleteErr)
		}
	}
}
