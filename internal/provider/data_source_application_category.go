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
	_ datasource.DataSource              = &applicationCategoryDataSource{}
	_ datasource.DataSourceWithConfigure = &applicationCategoryDataSource{}
)

type applicationCategoryDataSource struct {
	client reports.APIClient
}

type applicationCategoryDataSourceModel struct {
	ID   types.Int64  `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
}

func NewApplicationCategoryDataSource() datasource.DataSource {
	return &applicationCategoryDataSource{}
}

func (d *applicationCategoryDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application_category"
}

func (d *applicationCategoryDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *applicationCategoryDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up an application category in the Cisco Secure Access application catalog by exact name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Application category ID.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Exact application category name.",
				Required:    true,
			},
		},
	}
}

func (d *applicationCategoryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data applicationCategoryDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()
	tflog.Info(ctx, "Reading application category", map[string]interface{}{"name": name})

	category, httpResponse, err := readApplicationCategory(ctx, &d.client, name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Resolve Application Category",
			fmt.Sprintf("Could not resolve application category %q: %v%s", name, err, reportsHTTPStatus(httpResponse)),
		)
		return
	}

	data.ID = types.Int64Value(*category.Id)
	data.Name = types.StringValue(*category.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func readApplicationCategory(ctx context.Context, apiClient *reports.APIClient, name string) (reports.ApplicationCategories, *http.Response, error) {
	result, httpResponse, err := readApplicationCatalog(ctx, apiClient, "")
	if err != nil {
		return reports.ApplicationCategories{}, httpResponse, err
	}
	if result == nil {
		return reports.ApplicationCategories{}, httpResponse, fmt.Errorf("the reports API returned an empty response")
	}

	category, err := selectApplicationCategory(result.Data.Categories, name)
	return category, httpResponse, err
}

func selectApplicationCategory(categories []reports.ApplicationCategories, name string) (reports.ApplicationCategories, error) {
	matches := make([]reports.ApplicationCategories, 0, 1)
	for _, category := range categories {
		if category.Name != nil && *category.Name == name {
			matches = append(matches, category)
		}
	}

	if len(matches) == 0 {
		return reports.ApplicationCategories{}, fmt.Errorf("no application category found with exact name %q", name)
	}
	if len(matches) > 1 {
		return reports.ApplicationCategories{}, fmt.Errorf("found %d application categories with exact name %q; the catalog response is ambiguous", len(matches), name)
	}
	if matches[0].Id == nil || matches[0].Name == nil {
		return reports.ApplicationCategories{}, fmt.Errorf("application category %q is missing a required id or name", name)
	}

	return matches[0], nil
}
