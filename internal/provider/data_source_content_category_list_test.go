// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/contentcategories"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	testContentCategoryListDataSourceName = "data.ciscosecureaccess_content_category_list.cats"
)

// --- Acceptance tests (require TF_ACC + CISCOSECUREACCESS_KEY_ID/SECRET) ---

// TestContentCategoryListDataSource_basic exercises the data source against
// the live API: it fetches a known category via the API, then verifies the
// data source returns that same category when filtered by its exact name.
func TestContentCategoryListDataSource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		fixture, err := testContentCategoryFixture(t)
		if err != nil {
			t.Fatalf("Failed to get content category fixture: %v", err)
		}
		if fixture.Name == nil || fixture.Id == nil {
			t.Fatalf("fixture missing required fields: %+v", fixture)
		}

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccContentCategoryListDataSourceConfig(*fixture.Name),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							testContentCategoryListDataSourceName,
							tfjsonpath.New("content_category_lists").AtSliceIndex(0).AtMapKey("id"),
							knownvalue.Int64Exact(*fixture.Id),
						),
						statecheck.ExpectKnownValue(
							testContentCategoryListDataSourceName,
							tfjsonpath.New("content_category_lists").AtSliceIndex(0).AtMapKey("name"),
							knownvalue.StringExact(*fixture.Name),
						),
					},
				},
			},
		})
	}, minWaitTime)
}

// TestContentCategoryListDataSource_noFilter verifies that the data source
// returns at least one entry when no filter is supplied. Every organization
// has at least one default content category setting.
func TestContentCategoryListDataSource_noFilter(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `data "ciscosecureaccess_content_category_list" "cats" {}`,
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							testContentCategoryListDataSourceName,
							tfjsonpath.New("content_category_lists").AtSliceIndex(0).AtMapKey("id"),
							knownvalue.NotNull(),
						),
					},
				},
			},
		})
	}, minWaitTime)
}

// testContentCategoryFixture retrieves a sample content category list for testing.
func testContentCategoryFixture(t *testing.T) (*contentcategories.ContentCategorySetting, error) {
	apiClient := testClientFactory(t).GetContentCategoriesClient(context.Background())

	categories, httpResp, err := apiClient.ContentCategoriesAPI.GetCategorySettings(context.Background()).
		Page(1).
		Limit(contentCategoryBatchSize).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get content categories: %w", err)
	}

	if httpResp == nil {
		return nil, fmt.Errorf("HTTP response is nil")
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected HTTP status: %d - %s", httpResp.StatusCode, httpResp.Status)
	}

	if len(categories) == 0 {
		return nil, fmt.Errorf("no content categories returned from API")
	}

	// Prefer a default category when present for a stable, well-known fixture.
	for i := range categories {
		if categories[i].IsDefault != nil && *categories[i].IsDefault {
			return &categories[i], nil
		}
	}
	return &categories[0], nil
}

// testAccContentCategoryListDataSourceConfig returns a configuration for the
// content category list data source filtered by the supplied name.
func testAccContentCategoryListDataSourceConfig(filter string) string {
	return fmt.Sprintf(`
data "ciscosecureaccess_content_category_list" "cats" {
  filter = %q
}`, filter)
}

// --- Unit tests (hermetic, no credentials required) ---

// newTestContentCategoriesClient returns an APIClient wired to handler via an
// httptest.Server so getContentCategoryLists can be exercised without network access.
func newTestContentCategoriesClient(t *testing.T, handler http.Handler) (*contentcategories.APIClient, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	cfg := contentcategories.NewConfiguration()
	cfg.Servers = contentcategories.ServerConfigurations{
		{URL: server.URL},
	}
	cfg.HTTPClient = server.Client()
	return contentcategories.NewAPIClient(cfg), server.Close
}

func makeCategoryPage(start, count int) []contentcategories.ContentCategorySetting {
	out := make([]contentcategories.ContentCategorySetting, count)
	for i := 0; i < count; i++ {
		idx := start + i
		out[i] = contentcategories.ContentCategorySetting{
			Id:        ptrInt64(int64(idx)),
			Name:      ptrString(fmt.Sprintf("Category-%d", idx)),
			Type:      ptrString("standard"),
			IsDefault: ptrBool(idx == 1),
		}
	}
	return out
}

// TestGetContentCategoryLists_paginates verifies that the data source helper
// follows the API's page-based pagination until a short page is returned, and
// produces the full set of results across all pages.
func TestGetContentCategoryLists_paginates(t *testing.T) {
	// First page: full batch (100). Second page: 30 items (signals end).
	page1 := makeCategoryPage(1, contentCategoryBatchSize)
	page2 := makeCategoryPage(contentCategoryBatchSize+1, 30)

	var pagesSeen int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/categorySettings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		atomic.AddInt32(&pagesSeen, 1)

		w.Header().Set("Content-Type", "application/json")
		switch page {
		case 1:
			_ = json.NewEncoder(w).Encode(page1)
		case 2:
			_ = json.NewEncoder(w).Encode(page2)
		default:
			_ = json.NewEncoder(w).Encode([]contentcategories.ContentCategorySetting{})
		}
	})

	client, cleanup := newTestContentCategoriesClient(t, handler)
	defer cleanup()

	results, diags := getContentCategoryLists(context.Background(), client, "")
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}

	wantCount := contentCategoryBatchSize + 30
	if len(results) != wantCount {
		t.Fatalf("expected %d results, got %d", wantCount, len(results))
	}
	if got := atomic.LoadInt32(&pagesSeen); got != 2 {
		t.Fatalf("expected 2 page requests, got %d", got)
	}

	// Spot-check first and last entries map correctly.
	if results[0].Id.ValueInt64() != 1 || results[0].Name.ValueString() != "Category-1" {
		t.Fatalf("unexpected first result: %+v", results[0])
	}
	if !results[0].IsDefault.ValueBool() {
		t.Fatalf("expected first result to be default")
	}
	last := results[len(results)-1]
	if last.Id.ValueInt64() != int64(wantCount) {
		t.Fatalf("unexpected last id: %d", last.Id.ValueInt64())
	}
}

// TestGetContentCategoryLists_filterCaseInsensitive verifies that the optional
// filter applies a case-insensitive substring match against the category name.
func TestGetContentCategoryLists_filterCaseInsensitive(t *testing.T) {
	categories := []contentcategories.ContentCategorySetting{
		{Id: ptrInt64(1), Name: ptrString("Social Media"), Type: ptrString("standard"), IsDefault: ptrBool(false)},
		{Id: ptrInt64(2), Name: ptrString("Streaming Video"), Type: ptrString("standard"), IsDefault: ptrBool(false)},
		{Id: ptrInt64(3), Name: ptrString("Productivity"), Type: ptrString("standard"), IsDefault: ptrBool(true)},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		if page == 1 {
			_ = json.NewEncoder(w).Encode(categories)
			return
		}
		_ = json.NewEncoder(w).Encode([]contentcategories.ContentCategorySetting{})
	})

	client, cleanup := newTestContentCategoriesClient(t, handler)
	defer cleanup()

	results, diags := getContentCategoryLists(context.Background(), client, "STREAM")
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 filtered result, got %d", len(results))
	}
	if results[0].Name.ValueString() != "Streaming Video" {
		t.Fatalf("unexpected filtered result: %s", results[0].Name.ValueString())
	}

	// Empty filter must return everything.
	all, diags := getContentCategoryLists(context.Background(), client, "")
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}
	if len(all) != len(categories) {
		t.Fatalf("expected %d results with empty filter, got %d", len(categories), len(all))
	}
}

// TestGetContentCategoryLists_noResultsOnEmptyFirstPage verifies that a single
// short first page terminates pagination immediately.
func TestGetContentCategoryLists_noResultsOnEmptyFirstPage(t *testing.T) {
	var calls int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]contentcategories.ContentCategorySetting{})
	})

	client, cleanup := newTestContentCategoriesClient(t, handler)
	defer cleanup()

	results, diags := getContentCategoryLists(context.Background(), client, "")
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 request, got %d", got)
	}
}

// TestGetContentCategoryLists_nilFieldsHandled verifies that entries with nil
// optional fields are normalized to zero values rather than panicking.
func TestGetContentCategoryLists_nilFieldsHandled(t *testing.T) {
	categories := []contentcategories.ContentCategorySetting{
		{}, // all fields nil
		{Name: ptrString("Has Name Only")},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		if page == 1 {
			_ = json.NewEncoder(w).Encode(categories)
			return
		}
		_ = json.NewEncoder(w).Encode([]contentcategories.ContentCategorySetting{})
	})

	client, cleanup := newTestContentCategoriesClient(t, handler)
	defer cleanup()

	results, diags := getContentCategoryLists(context.Background(), client, "")
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Id.ValueInt64() != 0 || results[0].Name.ValueString() != "" ||
		results[0].Type.ValueString() != "" || results[0].IsDefault.ValueBool() {
		t.Fatalf("expected zero values for nil fields, got %+v", results[0])
	}
	if results[1].Name.ValueString() != "Has Name Only" {
		t.Fatalf("unexpected second result: %+v", results[1])
	}
}

// TestContentCategoryListModel_AttrTypes guards the schema attribute map used
// to project the slice into a Terraform list value.
func TestContentCategoryListModel_AttrTypes(t *testing.T) {
	attrs := ContentCategoryListModel{}.AttrTypes()
	for _, key := range []string{"id", "name", "type", "is_default"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("missing attribute %q in AttrTypes()", key)
		}
	}
	if len(attrs) != 4 {
		t.Fatalf("expected 4 attributes, got %d", len(attrs))
	}
}
