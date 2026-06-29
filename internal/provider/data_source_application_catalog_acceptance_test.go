// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	testAVCApplicationDataSourceName      = "data.ciscosecureaccess_application.avc"
	testNBARApplicationDataSourceName     = "data.ciscosecureaccess_application.nbar"
	testApplicationCategoryDataSourceName = "data.ciscosecureaccess_application_category.test"
	testWebCategoryDataSourceName         = "data.ciscosecureaccess_web_category.test"
)

type applicationCatalogFixtures struct {
	avcApplication      reports.Application
	nbarApplication     reports.Application
	applicationCategory reports.ApplicationCategories
	webCategory         reports.CategoryWithLegacyId
}

func TestAccApplicationCatalogDataSources_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		fixtures, err := testApplicationCatalogFixtures(t)
		if err != nil {
			t.Fatalf("failed to get application catalog fixtures: %v", err)
		}

		avcApplication := fixtures.avcApplication
		nbarApplication := fixtures.nbarApplication
		applicationCategory := fixtures.applicationCategory
		webCategory := fixtures.webCategory
		avcCatalogKey := fmt.Sprintf("%s:%d", avcApplication.GetType(), avcApplication.GetId())
		nbarCatalogKey := fmt.Sprintf("%s:%d", nbarApplication.GetType(), nbarApplication.GetId())
		config := testAccApplicationCatalogDataSourcesConfig(
			avcApplication.GetLabel(),
			nbarApplication.GetLabel(),
			applicationCategory.GetName(),
			webCategory.Label,
			webCategory.Type,
		)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testAVCApplicationDataSourceName, tfjsonpath.New("id"), knownvalue.Int64Exact(avcApplication.GetId())),
						statecheck.ExpectKnownValue(testAVCApplicationDataSourceName, tfjsonpath.New("catalog_key"), knownvalue.StringExact(avcCatalogKey)),
						statecheck.ExpectKnownValue(testNBARApplicationDataSourceName, tfjsonpath.New("id"), knownvalue.Int64Exact(nbarApplication.GetId())),
						statecheck.ExpectKnownValue(testNBARApplicationDataSourceName, tfjsonpath.New("catalog_key"), knownvalue.StringExact(nbarCatalogKey)),
						statecheck.ExpectKnownValue(testApplicationCategoryDataSourceName, tfjsonpath.New("id"), knownvalue.Int64Exact(applicationCategory.GetId())),
						statecheck.ExpectKnownValue(testWebCategoryDataSourceName, tfjsonpath.New("id"), knownvalue.Int64Exact(webCategory.Id)),
						statecheck.ExpectKnownValue(testWebCategoryDataSourceName, tfjsonpath.New("legacy_id"), knownvalue.Int64Exact(webCategory.Legacyid)),
						statecheck.ExpectKnownValue(testWebCategoryDataSourceName, tfjsonpath.New("deprecated"), knownvalue.Bool(webCategory.Deprecated)),
					},
				},
				{
					Config:   config,
					PlanOnly: true,
				},
			},
		})
	}, minWaitTime)
}

func testApplicationCatalogFixtures(t *testing.T) (*applicationCatalogFixtures, error) {
	ctx := context.Background()
	reportingClient := testClientFactory(t).GetReportsClient(ctx)

	applicationResponse, httpResponse, err := readApplicationCatalog(ctx, reportingClient, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get applications: %w", err)
	}
	if httpResponse == nil || httpResponse.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected applications HTTP response: %v", httpResponse)
	}
	if applicationResponse == nil {
		return nil, fmt.Errorf("applications response is nil")
	}

	applicationCounts := make(map[string]int)
	for _, application := range applicationResponse.Data.Applications {
		if application.Label != nil && application.Type != nil {
			applicationCounts[*application.Label+"\x00"+*application.Type]++
		}
	}

	var avcApplicationFixture *reports.Application
	var nbarApplicationFixture *reports.Application
	for index := range applicationResponse.Data.Applications {
		application := &applicationResponse.Data.Applications[index]
		if application.Id == nil || application.Label == nil || application.Type == nil {
			continue
		}
		if applicationCounts[*application.Label+"\x00"+*application.Type] != 1 {
			continue
		}
		switch *application.Type {
		case "AVC":
			if avcApplicationFixture == nil {
				avcApplicationFixture = application
			}
		case "NBAR":
			if nbarApplicationFixture == nil {
				nbarApplicationFixture = application
			}
		}
		if avcApplicationFixture != nil && nbarApplicationFixture != nil {
			break
		}
	}
	if avcApplicationFixture == nil || nbarApplicationFixture == nil {
		return nil, fmt.Errorf("unique AVC and NBAR application fixtures were not both returned")
	}

	categoryCounts := make(map[string]int)
	for _, category := range applicationResponse.Data.Categories {
		if category.Name != nil {
			categoryCounts[*category.Name]++
		}
	}

	var applicationCategoryFixture *reports.ApplicationCategories
	for index := range applicationResponse.Data.Categories {
		category := &applicationResponse.Data.Categories[index]
		if category.Id != nil && category.Name != nil && categoryCounts[*category.Name] == 1 {
			applicationCategoryFixture = category
			break
		}
	}
	if applicationCategoryFixture == nil {
		return nil, fmt.Errorf("no unique application category fixture was returned")
	}

	webCategoryResponse, httpResponse, err := reportingClient.UtilityAPI.GetCategories(ctx).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get web categories: %w", err)
	}
	if httpResponse == nil || httpResponse.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected web categories HTTP response: %v", httpResponse)
	}
	if webCategoryResponse == nil {
		return nil, fmt.Errorf("web categories response is nil")
	}

	webCategoryCounts := make(map[string]int)
	for _, category := range webCategoryResponse.Data {
		webCategoryCounts[category.Label+"\x00"+category.Type]++
	}

	var webCategoryFixture *reports.CategoryWithLegacyId
	for index := range webCategoryResponse.Data {
		category := &webCategoryResponse.Data[index]
		if category.Label != "" && category.Type != "" && webCategoryCounts[category.Label+"\x00"+category.Type] == 1 {
			webCategoryFixture = category
			break
		}
	}
	if webCategoryFixture == nil {
		return nil, fmt.Errorf("no unique web category fixture was returned")
	}

	return &applicationCatalogFixtures{
		avcApplication:      *avcApplicationFixture,
		nbarApplication:     *nbarApplicationFixture,
		applicationCategory: *applicationCategoryFixture,
		webCategory:         *webCategoryFixture,
	}, nil
}

func testAccApplicationCatalogDataSourcesConfig(avcApplicationName, nbarApplicationName, applicationCategoryName, webCategoryName, webCategoryType string) string {
	return fmt.Sprintf(`
data "ciscosecureaccess_application" "avc" {
  name = %q
  type = "AVC"
}

data "ciscosecureaccess_application" "nbar" {
  name = %q
  type = "NBAR"
}

data "ciscosecureaccess_application_category" "test" {
  name = %q
}

data "ciscosecureaccess_web_category" "test" {
  name = %q
  type = %q
}
`, avcApplicationName, nbarApplicationName, applicationCategoryName, webCategoryName, webCategoryType)
}
