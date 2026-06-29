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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &applicationDataSource{}
	_ datasource.DataSourceWithConfigure = &applicationDataSource{}
)

type applicationDataSource struct {
	client reports.APIClient
}

type applicationDataSourceModel struct {
	ID           types.Int64  `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	CatalogKey   types.String `tfsdk:"catalog_key"`
	CategoryID   types.Int64  `tfsdk:"category_id"`
	CategoryName types.String `tfsdk:"category_name"`
}

func NewApplicationDataSource() datasource.DataSource {
	return &applicationDataSource{}
}

func (d *applicationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application"
}

func (d *applicationDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *applicationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up an application in the Cisco Secure Access application catalog by exact name and type.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Application ID. IDs are unique only within an application type.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Exact application name.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "Application catalog type.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("AVC", "NBAR"),
				},
			},
			"catalog_key": schema.StringAttribute{
				Description: "Stable provider key composed as type:id.",
				Computed:    true,
			},
			"category_id": schema.Int64Attribute{
				Description: "Application category ID, when supplied by the API.",
				Computed:    true,
			},
			"category_name": schema.StringAttribute{
				Description: "Application category name, when supplied by the API.",
				Computed:    true,
			},
		},
	}
}

func (d *applicationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data applicationDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()
	applicationType := data.Type.ValueString()
	tflog.Info(ctx, "Reading application catalog entry", map[string]interface{}{
		"name": name,
		"type": applicationType,
	})

	application, httpResponse, err := readApplicationCatalogEntry(ctx, &d.client, name, applicationType)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Resolve Application",
			fmt.Sprintf("Could not resolve application %q with type %q: %v%s", name, applicationType, err, reportsHTTPStatus(httpResponse)),
		)
		return
	}

	data.ID = types.Int64Value(*application.Id)
	data.Name = types.StringValue(*application.Label)
	data.Type = types.StringValue(*application.Type)
	data.CatalogKey = types.StringValue(fmt.Sprintf("%s:%d", *application.Type, *application.Id))
	data.CategoryID = types.Int64Null()
	data.CategoryName = types.StringNull()
	if application.Category != nil {
		if application.Category.Id != nil {
			data.CategoryID = types.Int64Value(*application.Category.Id)
		}
		if application.Category.Label != nil {
			data.CategoryName = types.StringValue(*application.Category.Label)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func readApplicationCatalogEntry(ctx context.Context, apiClient *reports.APIClient, name, applicationType string) (reports.Application, *http.Response, error) {
	result, httpResponse, err := readApplicationCatalog(ctx, apiClient, name)
	if err != nil {
		return reports.Application{}, httpResponse, err
	}
	if result == nil {
		return reports.Application{}, httpResponse, fmt.Errorf("the reports API returned an empty response")
	}

	application, err := selectApplication(result.Data.Applications, name, applicationType)
	return application, httpResponse, err
}

func selectApplication(applications []reports.Application, name, applicationType string) (reports.Application, error) {
	matches := make([]reports.Application, 0, 1)
	for _, application := range applications {
		if application.Label != nil && application.Type != nil &&
			*application.Label == name && *application.Type == applicationType {
			matches = append(matches, application)
		}
	}

	if len(matches) == 0 {
		return reports.Application{}, fmt.Errorf("no application found with exact name %q and type %q", name, applicationType)
	}
	if len(matches) > 1 {
		return reports.Application{}, fmt.Errorf("found %d applications with exact name %q and type %q; the catalog response is ambiguous", len(matches), name, applicationType)
	}
	if matches[0].Id == nil || matches[0].Label == nil || matches[0].Type == nil {
		return reports.Application{}, fmt.Errorf("application %q with type %q is missing a required id, label, or type", name, applicationType)
	}

	return matches[0], nil
}
