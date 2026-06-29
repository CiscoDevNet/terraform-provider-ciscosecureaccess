// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for access policy tests
const (
	testAccessPolicyResourceName = "ciscosecureaccess_access_policy.test_resource"
	testAccessPolicyDescription  = "Test rule for terraform private access policy support"
	testAccessPolicyNamePrefix   = "tfAcc"
)

// Common test helper functions

// generateTestName creates a unique test name with the given suffix
func generateAccessPolicyTestName(suffix string) string {
	return fmt.Sprintf("%s%s_%s", testAccessPolicyNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

// commonAccessPolicyChecks returns the basic checks that should be performed for all access policy tests
func commonAccessPolicyChecks(resourceName, expectedName string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, "id"),
		resource.TestCheckResourceAttr(resourceName, "name", expectedName),
	)
}

// commonAccessPolicyStateChecks returns the common state checks for access policy resources
func commonAccessPolicyStateChecks(resourceName, expectedName string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(expectedName)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(testAccessPolicyDescription)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("log_level"), knownvalue.StringExact("LOG_ALL")),
	}
}

func TestAccessPolicy_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateAccessPolicyTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyResource(testName),
					Check:  commonAccessPolicyChecks(testAccessPolicyResourceName, testName),
					ConfigStateChecks: append(
						commonAccessPolicyStateChecks(testAccessPolicyResourceName, testName),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("source_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(NETWORKS)})),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("private_destination_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(PRIVATE_APPS_SCHEMA)})),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccessPolicy_publicInternet(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateAccessPolicyTestName("public")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyPublicInternetConfig(testName),
					Check:  commonAccessPolicyChecks(testAccessPolicyResourceName, testName),
					ConfigStateChecks: append(
						commonAccessPolicyStateChecks(testAccessPolicyResourceName, testName),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("source_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(DIRECTORY_USERS)})),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("public_destination_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(PUBLIC_INTERNET_SCHEMA)})),
					),
				},
			},
		})
	}, minWaitTime)
}

// TestAccessPolicy_update tests update operations on access policies
func TestAccessPolicy_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateAccessPolicyTestName("update")
		updatedTestName := testName + "_updated"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource
					Config: testAccAccessPolicyResource(testName),
					Check:  commonAccessPolicyChecks(testAccessPolicyResourceName, testName),
				},
				{
					// Update the resource
					Config: testAccAccessPolicyResource(updatedTestName),
					Check:  commonAccessPolicyChecks(testAccessPolicyResourceName, updatedTestName),
					ConfigStateChecks: append(
						commonAccessPolicyStateChecks(testAccessPolicyResourceName, updatedTestName),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("source_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(NETWORKS)})),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("private_destination_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(PRIVATE_APPS_SCHEMA)})),
					),
				},
			},
		})
	}, minWaitTime)
}

// TestAccessPolicy_blockAction tests access policy with block action
func TestAccessPolicy_blockAction(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateAccessPolicyTestName("block")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccMutationPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccAccessPolicyBlockConfig(testName),
					Check:  commonAccessPolicyChecks(testAccessPolicyResourceName, testName),
					ConfigStateChecks: append(
						[]statecheck.StateCheck{
							statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
							statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("action"), knownvalue.StringExact("block")),
							statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
							statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("log_level"), knownvalue.StringExact("LOG_SECURITY")),
						},
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("source_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(NETWORKS)})),
						statecheck.ExpectKnownValue(testAccessPolicyResourceName, tfjsonpath.New("private_destination_types"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(PRIVATE_APPS_SCHEMA)})),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestFormatPutAccessPolicyRequestIncludesMutableFields(t *testing.T) {
	ctx := context.Background()
	model := accessPolicyResourceModel{
		Name:                    types.StringValue("tfAccPayloadTest"),
		Action:                  types.StringValue("allow"),
		Description:             types.StringValue("updated description"),
		Enabled:                 types.BoolValue(false),
		LogLevel:                types.StringValue("LOG_ALL"),
		Priority:                types.Int64Value(123),
		PrivateResourceIds:      types.SetNull(types.Int64Type),
		DestinationListIds:      types.SetNull(types.Int64Type),
		ContentCategoryListIds:  types.SetNull(types.Int64Type),
		SourceIds:               types.SetNull(types.Int64Type),
		SourceTypes:             mustStringSet(t, ctx, NETWORKS),
		PrivateDestinationTypes: mustStringSet(t, ctx, PRIVATE_APPS_SCHEMA),
		PublicDestinationTypes:  types.SetNull(types.StringType),
		TrafficType:             types.StringValue("PRIVATE_NETWORK"),
	}

	payload, diags := formatPutAccessPolicyRequest(ctx, &model)
	if diags.HasError() {
		t.Fatalf("formatting PUT payload failed: %v", diags)
	}
	if payload.RuleIsEnabled == nil || *payload.RuleIsEnabled {
		t.Fatalf("expected PUT payload to include ruleIsEnabled=false, got %#v", payload.RuleIsEnabled)
	}
	if payload.RuleDescription == nil || *payload.RuleDescription != "updated description" {
		t.Fatalf("expected PUT payload to include ruleDescription, got %#v", payload.RuleDescription)
	}
	if payload.RulePriority != 123 {
		t.Fatalf("expected PUT payload priority 123, got %d", payload.RulePriority)
	}
}

func mustStringSet(t *testing.T, ctx context.Context, values ...string) types.Set {
	t.Helper()
	set, diags := types.SetValueFrom(ctx, types.StringType, values)
	if diags.HasError() {
		t.Fatalf("building test set failed: %v", diags)
	}
	return set
}

// Configuration generators for different test scenarios

// testAccAccessPolicyResource returns a configuration for a private network access policy
func testAccAccessPolicyResource(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
    name = "%s"
    action = "allow"
    enabled = false
    log_level = "LOG_ALL"
    source_types = ["networks"]
    private_destination_types = ["private_apps"]
    description = "%s"
}`, name, testAccessPolicyDescription)
}

// testAccAccessPolicyPublicInternetConfig returns a configuration for a public internet access policy
func testAccAccessPolicyPublicInternetConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
    name = "%s"
    action = "allow"
    enabled = false
    log_level = "LOG_ALL"
    source_types = ["directory_users"]
    public_destination_types = ["internet"]
    description = "%s"
}`, name, testAccessPolicyDescription)
}

// testAccAccessPolicyBlockConfig returns a configuration for a block access policy
func testAccAccessPolicyBlockConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_access_policy" "test_resource" {
    name = "%s"
    action = "block"
    enabled = false
    log_level = "LOG_SECURITY"
    source_types = ["networks"]
    private_destination_types = ["private_apps"]
    description = "%s"
}`, name, testAccessPolicyDescription)
}
