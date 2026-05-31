// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/sites"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for site resource tests
const (
	testSiteResourceName  = "ciscosecureaccess_site.test_resource"
	testSiteNamePrefix    = "tfAcc"
	testSiteUpdatedSuffix = "updated"
)

// generateSiteTestName creates a unique test name for site tests
func generateSiteTestName(suffix string) string {
	return fmt.Sprintf("%s%s-%s", testSiteNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

func TestSiteResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateSiteTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccSiteBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", testName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("is_default"), knownvalue.Bool(false)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestSiteResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateSiteTestName("update")
		updatedName := generateSiteTestName(testSiteUpdatedSuffix)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccSiteBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", testName),
					),
				},
				{
					Config: testAccSiteBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", updatedName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccSiteBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_site" "test_resource" {
  name = %q
}
`, name)
}

func TestFlattenSiteObject_AllFieldsPresent(t *testing.T) {
	typeVal := "internal"
	netCount := int64(5)
	vaCount := int64(2)

	site := &sites.SiteObject{
		SiteId:               42,
		Name:                 "headquarters",
		OriginId:             100,
		IsDefault:            true,
		Type:                 &typeVal,
		InternalNetworkCount: &netCount,
		VaCount:              &vaCount,
	}

	var model siteResourceModel
	flattenSiteObject(site, &model)

	if model.Id.ValueInt64() != 42 {
		t.Errorf("expected Id=42, got %d", model.Id.ValueInt64())
	}
	if model.Name.ValueString() != "headquarters" {
		t.Errorf("expected Name=headquarters, got %s", model.Name.ValueString())
	}
	if model.OriginId.ValueInt64() != 100 {
		t.Errorf("expected OriginId=100, got %d", model.OriginId.ValueInt64())
	}
	if !model.IsDefault.ValueBool() {
		t.Errorf("expected IsDefault=true, got false")
	}
	if model.Type.IsNull() || model.Type.ValueString() != "internal" {
		t.Errorf("expected Type=internal, got %v", model.Type)
	}
	if model.InternalNetworkCount.IsNull() || model.InternalNetworkCount.ValueInt64() != 5 {
		t.Errorf("expected InternalNetworkCount=5, got %v", model.InternalNetworkCount)
	}
	if model.VaCount.IsNull() || model.VaCount.ValueInt64() != 2 {
		t.Errorf("expected VaCount=2, got %v", model.VaCount)
	}
}

func TestFlattenSiteObject_TypeAbsent(t *testing.T) {
	netCount := int64(3)
	vaCount := int64(1)

	site := &sites.SiteObject{
		SiteId:               10,
		Name:                 "site-no-type",
		OriginId:             200,
		IsDefault:            false,
		Type:                 nil,
		InternalNetworkCount: &netCount,
		VaCount:              &vaCount,
	}

	var model siteResourceModel
	flattenSiteObject(site, &model)

	if !model.Type.IsNull() {
		t.Errorf("expected Type to be null when absent, got %v", model.Type)
	}
	if model.Name.ValueString() != "site-no-type" {
		t.Errorf("expected Name=site-no-type, got %s", model.Name.ValueString())
	}
	if model.InternalNetworkCount.ValueInt64() != 3 {
		t.Errorf("expected InternalNetworkCount=3, got %d", model.InternalNetworkCount.ValueInt64())
	}
	if model.VaCount.ValueInt64() != 1 {
		t.Errorf("expected VaCount=1, got %d", model.VaCount.ValueInt64())
	}
}

func TestFlattenSiteObject_InternalNetworkCountAbsent(t *testing.T) {
	typeVal := "external"
	vaCount := int64(7)

	site := &sites.SiteObject{
		SiteId:               99,
		Name:                 "site-no-count",
		OriginId:             300,
		IsDefault:            false,
		Type:                 &typeVal,
		InternalNetworkCount: nil,
		VaCount:              &vaCount,
	}

	var model siteResourceModel
	flattenSiteObject(site, &model)

	if !model.InternalNetworkCount.IsNull() {
		t.Errorf("expected InternalNetworkCount to be null when absent, got %v", model.InternalNetworkCount)
	}
	if model.Type.ValueString() != "external" {
		t.Errorf("expected Type=external, got %s", model.Type.ValueString())
	}
	if model.VaCount.ValueInt64() != 7 {
		t.Errorf("expected VaCount=7, got %d", model.VaCount.ValueInt64())
	}
}

func TestFlattenSiteObject_VaCountAbsent(t *testing.T) {
	typeVal := "branch"
	netCount := int64(4)

	site := &sites.SiteObject{
		SiteId:               55,
		Name:                 "site-no-va",
		OriginId:             400,
		IsDefault:            true,
		Type:                 &typeVal,
		InternalNetworkCount: &netCount,
		VaCount:              nil,
	}

	var model siteResourceModel
	flattenSiteObject(site, &model)

	if !model.VaCount.IsNull() {
		t.Errorf("expected VaCount to be null when absent, got %v", model.VaCount)
	}
	if model.InternalNetworkCount.ValueInt64() != 4 {
		t.Errorf("expected InternalNetworkCount=4, got %d", model.InternalNetworkCount.ValueInt64())
	}
}
