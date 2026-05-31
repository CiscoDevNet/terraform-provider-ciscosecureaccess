// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/internaldomains"
)

func newInternalDomainObject(id int64, domain, description string, includeAllVAs, includeAllMobileDevices bool, siteIds []int64, createdAt, modifiedAt time.Time) *internaldomains.InternalDomainObject {
	return internaldomains.NewInternalDomainObject(id, domain, description, includeAllVAs, includeAllMobileDevices, createdAt, modifiedAt, siteIds)
}

func collectDiagFunc(diags *[]string) func(string, string) {
	return func(summary, detail string) {
		*diags = append(*diags, summary+": "+detail)
	}
}

func TestSetInternalDomainState_NormalWithSiteIds(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	modified := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	obj := newInternalDomainObject(42, "corp.example.com", "desc", false, true, []int64{1, 2, 3}, created, modified)

	state := &internalDomainResourceModel{
		SiteIds: types.ListNull(types.Int64Type),
	}
	var errs []string
	setInternalDomainState(context.Background(), obj, state, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if state.Id.ValueInt64() != 42 {
		t.Errorf("Id = %d, want 42", state.Id.ValueInt64())
	}
	if state.Domain.ValueString() != "corp.example.com" {
		t.Errorf("Domain = %s", state.Domain.ValueString())
	}
	if state.Description.ValueString() != "desc" {
		t.Errorf("Description = %s", state.Description.ValueString())
	}
	if state.IncludeAllVAs.ValueBool() != false {
		t.Errorf("IncludeAllVAs = %v", state.IncludeAllVAs.ValueBool())
	}
	if state.IncludeAllMobileDevices.ValueBool() != true {
		t.Errorf("IncludeAllMobileDevices = %v", state.IncludeAllMobileDevices.ValueBool())
	}
	if state.CreatedAt.ValueString() != created.Format(time.RFC3339) {
		t.Errorf("CreatedAt = %s", state.CreatedAt.ValueString())
	}
	if state.ModifiedAt.ValueString() != modified.Format(time.RFC3339) {
		t.Errorf("ModifiedAt = %s", state.ModifiedAt.ValueString())
	}
	if state.SiteIds.IsNull() {
		t.Fatalf("SiteIds should not be null")
	}
	if len(state.SiteIds.Elements()) != 3 {
		t.Errorf("SiteIds len = %d, want 3", len(state.SiteIds.Elements()))
	}
}

func TestSetInternalDomainState_EmptySiteIdsStateNullStaysNull(t *testing.T) {
	obj := newInternalDomainObject(1, "a.example.com", "", false, false, nil, time.Time{}, time.Time{})

	state := &internalDomainResourceModel{
		SiteIds: types.ListNull(types.Int64Type),
	}
	var errs []string
	setInternalDomainState(context.Background(), obj, state, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !state.SiteIds.IsNull() {
		t.Errorf("SiteIds should remain null when API returns empty and state was null")
	}
	if state.CreatedAt.ValueString() != "" {
		t.Errorf("CreatedAt should be empty for zero time, got %q", state.CreatedAt.ValueString())
	}
}

func TestSetInternalDomainState_EmptySiteIdsStateNonNullBecomesEmptyList(t *testing.T) {
	obj := newInternalDomainObject(1, "a.example.com", "", false, false, []int64{}, time.Time{}, time.Time{})

	existing, diags := types.ListValueFrom(context.Background(), types.Int64Type, []int64{99})
	if diags.HasError() {
		t.Fatalf("setup: %v", diags)
	}
	state := &internalDomainResourceModel{
		SiteIds: existing,
	}
	var errs []string
	setInternalDomainState(context.Background(), obj, state, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if state.SiteIds.IsNull() {
		t.Fatalf("SiteIds should not be null when state was non-null")
	}
	if len(state.SiteIds.Elements()) != 0 {
		t.Errorf("SiteIds should be empty list, got %d elements", len(state.SiteIds.Elements()))
	}
}

func TestBuildInternalDomainRequest_OnlyDomain(t *testing.T) {
	plan := internalDomainResourceModel{
		Domain:                  types.StringValue("only.example.com"),
		Description:             types.StringNull(),
		IncludeAllVAs:           types.BoolNull(),
		IncludeAllMobileDevices: types.BoolNull(),
		SiteIds:                 types.ListNull(types.Int64Type),
	}
	var errs []string
	req := buildInternalDomainRequest(context.Background(), plan, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if req.GetDomain() != "only.example.com" {
		t.Errorf("Domain = %s", req.GetDomain())
	}
	if req.HasDescription() {
		t.Errorf("Description should not be set")
	}
	if req.HasIncludeAllVAs() {
		t.Errorf("IncludeAllVAs should not be set")
	}
	if req.HasIncludeAllMobileDevices() {
		t.Errorf("IncludeAllMobileDevices should not be set")
	}
	if req.HasSiteIds() {
		t.Errorf("SiteIds should not be set")
	}
}

func TestBuildInternalDomainRequest_AllFields(t *testing.T) {
	siteIds, diags := types.ListValueFrom(context.Background(), types.Int64Type, []int64{10, 20})
	if diags.HasError() {
		t.Fatalf("setup: %v", diags)
	}
	plan := internalDomainResourceModel{
		Domain:                  types.StringValue("all.example.com"),
		Description:             types.StringValue("desc"),
		IncludeAllVAs:           types.BoolValue(true),
		IncludeAllMobileDevices: types.BoolValue(true),
		SiteIds:                 siteIds,
	}
	var errs []string
	req := buildInternalDomainRequest(context.Background(), plan, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if req.GetDomain() != "all.example.com" {
		t.Errorf("Domain = %s", req.GetDomain())
	}
	if req.GetDescription() != "desc" {
		t.Errorf("Description = %s", req.GetDescription())
	}
	if req.GetIncludeAllVAs() != true {
		t.Errorf("IncludeAllVAs = %v", req.GetIncludeAllVAs())
	}
	if req.GetIncludeAllMobileDevices() != true {
		t.Errorf("IncludeAllMobileDevices = %v", req.GetIncludeAllMobileDevices())
	}
	gotSiteIds := req.GetSiteIds()
	if len(gotSiteIds) != 2 || gotSiteIds[0] != 10 || gotSiteIds[1] != 20 {
		t.Errorf("SiteIds = %v", gotSiteIds)
	}
}

func TestBuildInternalDomainRequest_SiteIdsIncluded(t *testing.T) {
	siteIds, diags := types.ListValueFrom(context.Background(), types.Int64Type, []int64{7})
	if diags.HasError() {
		t.Fatalf("setup: %v", diags)
	}
	plan := internalDomainResourceModel{
		Domain:                  types.StringValue("site.example.com"),
		Description:             types.StringNull(),
		IncludeAllVAs:           types.BoolNull(),
		IncludeAllMobileDevices: types.BoolNull(),
		SiteIds:                 siteIds,
	}
	var errs []string
	req := buildInternalDomainRequest(context.Background(), plan, collectDiagFunc(&errs))

	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !req.HasSiteIds() {
		t.Fatalf("SiteIds should be set")
	}
	got := req.GetSiteIds()
	if len(got) != 1 || got[0] != 7 {
		t.Errorf("SiteIds = %v", got)
	}
}

var _ = attr.Value(nil)

const (
	testInternalDomainResourceName  = "ciscosecureaccess_internal_domain.test_resource"
	testInternalDomainPrefix        = "tfacc"
	testInternalDomainBaseDomain    = ".internal.example.com"
	testInternalDomainUpdatedSuffix = "updated"
)

func generateInternalDomainTestName(suffix string) string {
	return fmt.Sprintf("%s%s%s%s", testInternalDomainPrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix, testInternalDomainBaseDomain)
}

func TestInternalDomainResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		domain := generateInternalDomainTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckInternalDomainDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalDomainBasicConfig(domain),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalDomainResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "domain", domain),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "description", "basic acceptance test domain"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalDomainResourceName, tfjsonpath.New("domain"), knownvalue.StringExact(domain)),
						statecheck.ExpectKnownValue(testInternalDomainResourceName, tfjsonpath.New("description"), knownvalue.StringExact("basic acceptance test domain")),
					},
				},
				{
					ResourceName:      testInternalDomainResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func TestInternalDomainResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		domain := generateInternalDomainTestName("upd")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckInternalDomainDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalDomainBasicConfig(domain),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalDomainResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "domain", domain),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "description", "basic acceptance test domain"),
					),
				},
				{
					Config: testAccInternalDomainUpdatedConfig(domain),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalDomainResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "domain", domain),
						resource.TestCheckResourceAttr(testInternalDomainResourceName, "description", "updated acceptance test domain"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalDomainResourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated acceptance test domain")),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccCheckInternalDomainDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetInternalDomainsClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_internal_domain" {
			continue
		}
		id := atoi64(rs.Primary.ID)
		_, httpRes, _ := c.InternalDomainsAPI.GetInternalDomain(ctx, id).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("internal domain %d still exists after destroy", id)
		}
	}
	return nil
}

func testAccInternalDomainBasicConfig(domain string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_internal_domain" "test_resource" {
  domain      = %q
  description = "basic acceptance test domain"
}
`, domain)
}

func testAccInternalDomainUpdatedConfig(domain string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_internal_domain" "test_resource" {
  domain      = %q
  description = "updated acceptance test domain"
}
`, domain)
}
