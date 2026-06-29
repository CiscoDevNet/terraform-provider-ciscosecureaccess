// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &webCategoryDataSource{}
	_ datasource.DataSourceWithConfigure = &webCategoryDataSource{}
)

type webCategoryDataSource struct {
	client reports.APIClient
}

type webCategoryDataSourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	LegacyID    types.Int64  `tfsdk:"legacy_id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Integration types.Bool   `tfsdk:"integration"`
	Deprecated  types.Bool   `tfsdk:"deprecated"`
}

func NewWebCategoryDataSource() datasource.DataSource {
	return &webCategoryDataSource{}
}

func (d *webCategoryDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_web_category"
}

func (d *webCategoryDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData),
		)
		return
	}

	d.client = *factory.GetReportsClient(ctx)
}

func (d *webCategoryDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a web content category in the Cisco Secure Access reporting catalog by exact name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Web category ID.",
				Computed:    true,
			},
			"legacy_id": schema.Int64Attribute{
				Description: "Legacy web category ID.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Exact web category name.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "Category type. Set this when the name is not unique across types.",
				Optional:    true,
				Computed:    true,
			},
			"integration": schema.BoolAttribute{
				Description: "Whether this category represents an integration.",
				Computed:    true,
			},
			"deprecated": schema.BoolAttribute{
				Description: "Whether this legacy category is deprecated.",
				Computed:    true,
			},
		},
	}
}

func (d *webCategoryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data webCategoryDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()
	categoryType := ""
	if !data.Type.IsNull() && !data.Type.IsUnknown() {
		categoryType = data.Type.ValueString()
	}
	tflog.Info(ctx, "Reading web category", map[string]interface{}{
		"name": name,
		"type": categoryType,
	})

	category, httpResponse, err := readWebCategory(ctx, &d.client, name, categoryType)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Resolve Web Category",
			fmt.Sprintf("Could not resolve web category %q: %v%s", name, err, reportsHTTPStatus(httpResponse)),
		)
		return
	}

	data.ID = types.Int64Value(category.Id)
	data.LegacyID = types.Int64Value(category.Legacyid)
	data.Name = types.StringValue(category.Label)
	data.Type = types.StringValue(category.Type)
	data.Integration = types.BoolValue(category.Integration)
	data.Deprecated = types.BoolValue(category.Deprecated)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func readWebCategory(ctx context.Context, apiClient *reports.APIClient, name, categoryType string) (reports.CategoryWithLegacyId, *http.Response, error) {
	result, httpResponse, err := apiClient.UtilityAPI.GetCategories(ctx).Execute()
	if err != nil {
		return reports.CategoryWithLegacyId{}, httpResponse, err
	}
	if result == nil {
		return reports.CategoryWithLegacyId{}, httpResponse, fmt.Errorf("the reports API returned an empty response")
	}

	category, err := selectWebCategory(result.Data, name, categoryType)
	return category, httpResponse, err
}

func selectWebCategory(categories []reports.CategoryWithLegacyId, name, categoryType string) (reports.CategoryWithLegacyId, error) {
	matches := make([]reports.CategoryWithLegacyId, 0, 1)
	for _, category := range categories {
		if category.Label == name && (categoryType == "" || category.Type == categoryType) {
			matches = append(matches, category)
		}
	}

	selector := fmt.Sprintf("exact name %q", name)
	if categoryType != "" {
		selector += fmt.Sprintf(" and type %q", categoryType)
	}
	if len(matches) == 0 {
		return reports.CategoryWithLegacyId{}, fmt.Errorf("no web category found with %s", selector)
	}
	if len(matches) > 1 {
		return reports.CategoryWithLegacyId{}, fmt.Errorf("found %d web categories with %s; set type to disambiguate the catalog entry", len(matches), selector)
	}

	return matches[0], nil
}

func reportsHTTPStatus(response *http.Response) string {
	if response == nil {
		return ""
	}
	return fmt.Sprintf(" (HTTP status %d)", response.StatusCode)
}
