// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &ztnaProfilesDataSource{}
	_ datasource.DataSourceWithConfigure = &ztnaProfilesDataSource{}
)

func NewZtnaProfilesDataSource() datasource.DataSource {
	return &ztnaProfilesDataSource{}
}

type ztnaProfilesDataSource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfilesDataSourceModel struct {
	Profiles []ztnaProfileSummaryModel `tfsdk:"profiles"`
}

type ztnaProfileSummaryModel struct {
	ID          types.String `tfsdk:"id"`
	ProfileName types.String `tfsdk:"profile_name"`
	Priority    types.Int64  `tfsdk:"priority"`
}

func (d *ztnaProfilesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profiles"
}

func (d *ztnaProfilesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	d.client = factory.GetZtnaProfilesClient(ctx)
}

func (d *ztnaProfilesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all ZTNA profiles in the organization.",
		Attributes: map[string]schema.Attribute{
			"profiles": schema.ListNestedAttribute{
				Description: "List of ZTNA profiles.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique ID of the ZTNA profile.",
							Computed:    true,
						},
						"profile_name": schema.StringAttribute{
							Description: "Display name of the ZTNA profile.",
							Computed:    true,
						},
						"priority": schema.Int64Attribute{
							Description: "Priority of the ZTNA profile.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *ztnaProfilesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state ztnaProfilesDataSourceModel

	list, _, err := d.client.ZtnaProfilesAPI.ListZtnaProfiles(ctx).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error listing ZTNA profiles", err.Error())
		return
	}

	profiles := make([]ztnaProfileSummaryModel, len(list.Items))
	for i, p := range list.Items {
		summary := ztnaProfileSummaryModel{}
		if p.ProfileId != nil {
			summary.ID = types.StringValue(*p.ProfileId)
		}
		if p.ProfileName != nil {
			summary.ProfileName = types.StringValue(*p.ProfileName)
		}
		if p.Priority != nil {
			summary.Priority = types.Int64Value(int64(*p.Priority))
		}
		profiles[i] = summary
	}
	state.Profiles = profiles

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
