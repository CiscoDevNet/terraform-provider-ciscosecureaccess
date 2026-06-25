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
	_ datasource.DataSource              = &ravpnHeadendsDataSource{}
	_ datasource.DataSourceWithConfigure = &ravpnHeadendsDataSource{}
)

func NewRavpnHeadendsDataSource() datasource.DataSource {
	return &ravpnHeadendsDataSource{}
}

type ravpnHeadendsDataSource struct {
	client *ravpnprofiles.APIClient
}

type ravpnHeadendsDataSourceModel struct {
	OrganizationID types.String                    `tfsdk:"organization_id"`
	HeadendID      types.String                    `tfsdk:"headend_id"`
	FQDN           types.String                    `tfsdk:"fqdn"`
	HostName       types.String                    `tfsdk:"hostname"`
	Rev            types.Int64                     `tfsdk:"rev"`
	Regions        []ravpnHeadendRegionDataModel   `tfsdk:"regions"`
}

type ravpnHeadendRegionDataModel struct {
	ID               types.String                  `tfsdk:"id"`
	DisplayName      types.String                  `tfsdk:"display_name"`
	EndpointIpPool   []types.String                `tfsdk:"endpoint_ip_pool"`
	ManagementIpPool []types.String                `tfsdk:"management_ip_pool"`
	DnsID            types.String                  `tfsdk:"dns_id"`
	NamedIpPools     []ravpnNamedIpPoolDataModel   `tfsdk:"named_ip_pools"`
}

type ravpnNamedIpPoolDataModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	IPv4StartAddr  types.String `tfsdk:"ipv4_start_addr"`
	IPv4EndAddr    types.String `tfsdk:"ipv4_end_addr"`
	IPv4SubnetMask types.String `tfsdk:"ipv4_subnet_mask"`
}

func (d *ravpnHeadendsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ravpn_headends"
}

func (d *ravpnHeadendsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ravpnHeadendsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the RAVPN headend configuration for an organization.",
		Attributes: map[string]schema.Attribute{
			"organization_id": schema.StringAttribute{
				Description: "Organization ID.",
				Required:    true,
			},
			"headend_id": schema.StringAttribute{
				Description: "Headend ID.",
				Computed:    true,
			},
			"fqdn": schema.StringAttribute{
				Description: "Headend FQDN.",
				Computed:    true,
			},
			"hostname": schema.StringAttribute{
				Description: "Headend hostname.",
				Computed:    true,
			},
			"rev": schema.Int64Attribute{
				Description: "Revision number.",
				Computed:    true,
			},
			"regions": schema.ListNestedAttribute{
				Description: "List of regions configured on the headend.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Region ID.",
							Computed:    true,
						},
						"display_name": schema.StringAttribute{
							Description: "Region display name.",
							Computed:    true,
						},
						"endpoint_ip_pool": schema.ListAttribute{
							Description: "Endpoint IP pool CIDRs.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"management_ip_pool": schema.ListAttribute{
							Description: "Management IP pool CIDRs.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"dns_id": schema.StringAttribute{
							Description: "DNS server ID for this region.",
							Computed:    true,
						},
						"named_ip_pools": schema.ListNestedAttribute{
							Description: "Named IP pools in this region.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Description: "Named IP pool ID.",
										Computed:    true,
									},
									"name": schema.StringAttribute{
										Description: "Named IP pool name.",
										Computed:    true,
									},
									"ipv4_start_addr": schema.StringAttribute{
										Description: "IPv4 start address.",
										Computed:    true,
									},
									"ipv4_end_addr": schema.StringAttribute{
										Description: "IPv4 end address.",
										Computed:    true,
									},
									"ipv4_subnet_mask": schema.StringAttribute{
										Description: "IPv4 subnet mask.",
										Computed:    true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *ravpnHeadendsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ravpnHeadendsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := config.OrganizationID.ValueString()
	headend, _, err := d.client.HeadendsAPI.GetHeadend(ctx, orgID).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error reading RAVPN headend", err.Error())
		return
	}
	if headend == nil {
		config.HeadendID = types.StringValue("")
		config.FQDN = types.StringValue("")
		config.HostName = types.StringValue("")
		config.Rev = types.Int64Value(0)
		config.Regions = []ravpnHeadendRegionDataModel{}
		resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
		return
	}

	config.HeadendID = types.StringValue(headend.HeadendID)
	config.FQDN = types.StringValue(headend.FQDN)
	config.HostName = types.StringValue(headend.HostName)
	config.Rev = types.Int64Value(int64(headend.Rev))

	regions := make([]ravpnHeadendRegionDataModel, len(headend.Regions))
	for i, r := range headend.Regions {
		region := ravpnHeadendRegionDataModel{
			ID:          types.StringValue(r.ID),
			DisplayName: types.StringValue(r.DisplayName),
			DnsID:       types.StringValue(r.DnsID),
		}
		region.EndpointIpPool = make([]types.String, len(r.EndpointIpPool))
		for j, ip := range r.EndpointIpPool {
			region.EndpointIpPool[j] = types.StringValue(ip)
		}
		region.ManagementIpPool = make([]types.String, len(r.ManagementIpPool))
		for j, ip := range r.ManagementIpPool {
			region.ManagementIpPool[j] = types.StringValue(ip)
		}
		pools := make([]ravpnNamedIpPoolDataModel, len(r.NamedIpPools))
		for j, p := range r.NamedIpPools {
			pools[j] = ravpnNamedIpPoolDataModel{
				ID:             types.StringValue(p.ID),
				Name:           types.StringValue(p.Name),
				IPv4StartAddr:  types.StringValue(p.IPv4StartAddr),
				IPv4EndAddr:    types.StringValue(p.IPv4EndAddr),
				IPv4SubnetMask: types.StringValue(p.IPv4SubnetMask),
			}
		}
		region.NamedIpPools = pools
		regions[i] = region
	}
	config.Regions = regions

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
