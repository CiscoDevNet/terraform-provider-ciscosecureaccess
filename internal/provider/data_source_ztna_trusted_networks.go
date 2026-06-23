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
	_ datasource.DataSource              = &ztnaTrustedNetworksDataSource{}
	_ datasource.DataSourceWithConfigure = &ztnaTrustedNetworksDataSource{}
)

func NewZtnaTrustedNetworksDataSource() datasource.DataSource {
	return &ztnaTrustedNetworksDataSource{}
}

type ztnaTrustedNetworksDataSource struct {
	client *ztnaprofiles.APIClient
}

type ztnaTrustedNetworksDataSourceModel struct {
	NameFilter types.String            `tfsdk:"name_filter"`
	Networks   []ztnaTrustedNetSummary `tfsdk:"networks"`
}

type ztnaTrustedNetSummary struct {
	ID          types.String `tfsdk:"id"`
	NetworkName types.String `tfsdk:"network_name"`
	IsDefault   types.Bool   `tfsdk:"is_default"`
}

func (d *ztnaTrustedNetworksDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_trusted_networks"
}

func (d *ztnaTrustedNetworksDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ztnaTrustedNetworksDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists ZTNA trusted networks in the organization.",
		Attributes: map[string]schema.Attribute{
			"name_filter": schema.StringAttribute{
				Description: "Optional filter: only return networks whose name contains this string.",
				Optional:    true,
			},
			"networks": schema.ListNestedAttribute{
				Description: "List of trusted networks.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique ID of the trusted network.",
							Computed:    true,
						},
						"network_name": schema.StringAttribute{
							Description: "Name of the trusted network.",
							Computed:    true,
						},
						"is_default": schema.BoolAttribute{
							Description: "Whether this is the default trusted network.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *ztnaTrustedNetworksDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ztnaTrustedNetworksDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := d.client.TrustedNetworksAPI.ListZTNATrustedNetworks(ctx)
	if !config.NameFilter.IsNull() && !config.NameFilter.IsUnknown() {
		listReq = listReq.NetworkName(config.NameFilter.ValueString())
	}

	list, _, err := listReq.Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error listing ZTNA trusted networks", err.Error())
		return
	}

	networks := make([]ztnaTrustedNetSummary, len(list.Items))
	for i, n := range list.Items {
		summary := ztnaTrustedNetSummary{}
		if n.NetworkId != nil {
			summary.ID = types.StringValue(*n.NetworkId)
		}
		if n.NetworkName != nil {
			summary.NetworkName = types.StringValue(*n.NetworkName)
		}
		if n.IsDefault != nil {
			summary.IsDefault = types.BoolValue(*n.IsDefault)
		}
		networks[i] = summary
	}
	config.Networks = networks

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
