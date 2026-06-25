// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ravpnprofiles"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ravpnProfilesDataSource{}
	_ datasource.DataSourceWithConfigure = &ravpnProfilesDataSource{}
)

func NewRavpnProfilesDataSource() datasource.DataSource {
	return &ravpnProfilesDataSource{}
}

type ravpnProfilesDataSource struct {
	client *ravpnprofiles.APIClient
}

type ravpnProfilesDataSourceModel struct {
	OrganizationID types.String                  `tfsdk:"organization_id"`
	NameFilter     types.String                  `tfsdk:"name_filter"`
	Profiles       []ravpnProfileSummaryModel    `tfsdk:"profiles"`
}

type ravpnProfileSummaryModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	DefaultDomain types.String `tfsdk:"default_domain"`
}

func (d *ravpnProfilesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ravpn_profiles"
}

func (d *ravpnProfilesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	d.client = factory.GetRavpnProfilesClient(ctx)
}

func (d *ravpnProfilesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists RAVPN profiles in the organization.",
		Attributes: map[string]schema.Attribute{
			"organization_id": schema.StringAttribute{
				Description: "Organization ID.",
				Required:    true,
			},
			"name_filter": schema.StringAttribute{
				Description: "Optional filter to match profile names (substring match).",
				Optional:    true,
			},
			"profiles": schema.ListNestedAttribute{
				Description: "List of RAVPN profiles.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Profile ID.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Profile name.",
							Computed:    true,
						},
						"default_domain": schema.StringAttribute{
							Description: "Default domain for the profile.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *ravpnProfilesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ravpnProfilesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := config.OrganizationID.ValueString()
	nameFilter := config.NameFilter.ValueString()

	list, _, err := d.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error listing RAVPN profiles", err.Error())
		return
	}

	profiles := make([]ravpnProfileSummaryModel, 0, len(list))
	for _, p := range list {
		if nameFilter != "" && !containsSubstring(p.Name, nameFilter) {
			continue
		}
		profiles = append(profiles, ravpnProfileSummaryModel{
			ID:            types.StringValue(p.ID),
			Name:          types.StringValue(p.Name),
			DefaultDomain: types.StringValue(p.DefaultDomain),
		})
	}
	config.Profiles = profiles

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func containsSubstring(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (s == substr || len(s) > 0 && contains(s, substr))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
