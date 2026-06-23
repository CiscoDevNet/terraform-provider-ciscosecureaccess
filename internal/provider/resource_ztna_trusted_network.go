// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	retry "github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &ztnaTrustedNetworkResource{}
	_ resource.ResourceWithConfigure = &ztnaTrustedNetworkResource{}
)

func NewZtnaTrustedNetworkResource() resource.Resource {
	return &ztnaTrustedNetworkResource{}
}

type ztnaTrustedNetworkResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaTrustedNetworkModel struct {
	ID             types.String            `tfsdk:"id"`
	NetworkName    types.String            `tfsdk:"network_name"`
	InterfaceType  types.Int64             `tfsdk:"interface_type"`
	IsDefault      types.Bool              `tfsdk:"is_default"`
	Rev            types.Int64             `tfsdk:"rev"`
	OrganizationId types.String            `tfsdk:"organization_id"`
	CreatedAt      types.String            `tfsdk:"created_at"`
	ModifiedAt     types.String            `tfsdk:"modified_at"`
	Criteria       *ztnaTrustedNetCriteria `tfsdk:"criteria"`
}

type ztnaTrustedNetCriteria struct {
	DnsServers     []ztnaDnsServerModel     `tfsdk:"dns_servers"`
	DnsDomains     []ztnaDnsDomainModel     `tfsdk:"dns_domains"`
	TrustedServers []ztnaTrustedServerModel `tfsdk:"trusted_servers"`
}

type ztnaDnsServerModel struct {
	ServerIp types.String `tfsdk:"server_ip"`
}

type ztnaDnsDomainModel struct {
	Name types.String `tfsdk:"name"`
}

type ztnaTrustedServerModel struct {
	Url             types.String `tfsdk:"url"`
	CertificateHash types.String `tfsdk:"certificate_hash"`
}

func (r *ztnaTrustedNetworkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_trusted_network"
}

func (r *ztnaTrustedNetworkResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = factory.GetZtnaProfilesClient(ctx)
}

func (r *ztnaTrustedNetworkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access ZTNA Trusted Network.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of the trusted network.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"network_name": schema.StringAttribute{
				Description: "Name of the trusted network.",
				Required:    true,
			},
			"interface_type": schema.Int64Attribute{
				Description: "Interface type: 0=physical only, 1=physical and virtual.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"is_default": schema.BoolAttribute{
				Description: "Whether this is the default trusted network.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"rev": schema.Int64Attribute{
				Description: "Optimistic-concurrency revision number.",
				Computed:    true,
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID that owns the trusted network.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "Timestamp when the trusted network was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				Description: "Timestamp when the trusted network was last modified.",
				Computed:    true,
			},
			"criteria": schema.SingleNestedAttribute{
				Description: "Criteria for detecting this trusted network.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"dns_servers": schema.ListNestedAttribute{
						Description: "DNS server IP addresses that identify this network.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"server_ip": schema.StringAttribute{
									Description: "IP address of the DNS server.",
									Required:    true,
								},
							},
						},
					},
					"dns_domains": schema.ListNestedAttribute{
						Description: "DNS domain suffixes that identify this network.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Description: "Domain name suffix.",
									Required:    true,
								},
							},
						},
					},
					"trusted_servers": schema.ListNestedAttribute{
						Description: "Trusted server URLs that identify this network.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"url": schema.StringAttribute{
									Description: "URL of the trusted server.",
									Required:    true,
								},
								"certificate_hash": schema.StringAttribute{
									Description: "Certificate hash for the trusted server.",
									Optional:    true,
									Computed:    true,
									PlanModifiers: []planmodifier.String{
										stringplanmodifier.UseStateForUnknown(),
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

func (r *ztnaTrustedNetworkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaTrustedNetworkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := ztnaprofiles.TrustedNetworkCreateInput{
		NetworkName: plan.NetworkName.ValueString(),
		Criteria:    expandTrustedNetworkCriteria(plan.Criteria),
	}
	if !plan.InterfaceType.IsNull() && !plan.InterfaceType.IsUnknown() {
		v := int32(plan.InterfaceType.ValueInt64())
		input.InterfaceType = &v
	}
	if !plan.IsDefault.IsNull() && !plan.IsDefault.IsUnknown() {
		v := plan.IsDefault.ValueBool()
		input.IsDefault = &v
	}

	created, _, err := r.client.TrustedNetworksAPI.AddZTNATrustedNetwork(ctx).TrustedNetworkCreateInput(input).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error creating ZTNA trusted network", err.Error())
		return
	}

	flattenTrustedNetwork(created, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaTrustedNetworkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaTrustedNetworkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tn, httpResp, err := r.client.TrustedNetworksAPI.GetZTNATrustedNetwork(ctx, state.ID.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Trusted network not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading ZTNA trusted network", err.Error())
		return
	}

	flattenTrustedNetwork(tn, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaTrustedNetworkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaTrustedNetworkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.ID.ValueString()
	var updated *ztnaprofiles.TrustedNetwork

	err := retry.Do(func() error {
		current, _, readErr := r.client.TrustedNetworksAPI.GetZTNATrustedNetwork(ctx, networkId).Execute()
		if readErr != nil {
			return retry.Unrecoverable(readErr)
		}

		input := ztnaprofiles.TrustedNetworkUpdateInput{
			NetworkName: plan.NetworkName.ValueString(),
			Criteria:    expandTrustedNetworkCriteria(plan.Criteria),
			Rev:         current.Rev,
		}
		if !plan.InterfaceType.IsNull() && !plan.InterfaceType.IsUnknown() {
			v := int32(plan.InterfaceType.ValueInt64())
			input.InterfaceType = &v
		}
		if !plan.IsDefault.IsNull() && !plan.IsDefault.IsUnknown() {
			v := plan.IsDefault.ValueBool()
			input.IsDefault = &v
		}

		var putErr error
		var httpResp *http.Response
		updated, httpResp, putErr = r.client.TrustedNetworksAPI.UpdateZTNATrustedNetwork(ctx, networkId).TrustedNetworkUpdateInput(input).Execute()
		if putErr != nil && httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			return putErr
		}
		if putErr != nil {
			return retry.Unrecoverable(putErr)
		}
		return nil
	}, retry.Attempts(5))

	if err != nil {
		resp.Diagnostics.AddError("Error updating ZTNA trusted network", err.Error())
		return
	}

	flattenTrustedNetwork(updated, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaTrustedNetworkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaTrustedNetworkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpResp, err := r.client.TrustedNetworksAPI.DeleteZTNATrustedNetwork(ctx, state.ID.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			return
		}
		resp.Diagnostics.AddError("Error deleting ZTNA trusted network", err.Error())
	}
}

func flattenTrustedNetwork(tn *ztnaprofiles.TrustedNetwork, m *ztnaTrustedNetworkModel) {
	if tn.NetworkId != nil {
		m.ID = types.StringValue(*tn.NetworkId)
	}
	if tn.NetworkName != nil {
		m.NetworkName = types.StringValue(*tn.NetworkName)
	}
	if tn.InterfaceType != nil {
		m.InterfaceType = types.Int64Value(int64(*tn.InterfaceType))
	}
	if tn.IsDefault != nil {
		m.IsDefault = types.BoolValue(*tn.IsDefault)
	}
	if tn.Rev != nil {
		m.Rev = types.Int64Value(int64(*tn.Rev))
	}
	if tn.OrganizationId != nil {
		m.OrganizationId = types.StringValue(*tn.OrganizationId)
	}
	if tn.CreatedAt != nil {
		m.CreatedAt = types.StringValue(*tn.CreatedAt)
	}
	if tn.ModifiedAt != nil {
		m.ModifiedAt = types.StringValue(*tn.ModifiedAt)
	}
	if tn.Criteria != nil {
		m.Criteria = flattenTrustedNetworkCriteria(tn.Criteria)
	}
}

func flattenTrustedNetworkCriteria(c *ztnaprofiles.TrustedNetworkCriteria) *ztnaTrustedNetCriteria {
	if c == nil {
		return nil
	}
	out := &ztnaTrustedNetCriteria{}
	for _, s := range c.DnsServers {
		out.DnsServers = append(out.DnsServers, ztnaDnsServerModel{ServerIp: types.StringValue(s.ServerIp)})
	}
	for _, d := range c.DnsDomains {
		out.DnsDomains = append(out.DnsDomains, ztnaDnsDomainModel{Name: types.StringValue(d.Name)})
	}
	for _, t := range c.TrustedServers {
		m := ztnaTrustedServerModel{Url: types.StringValue(t.Url)}
		if t.CertificateHash != nil {
			m.CertificateHash = types.StringValue(*t.CertificateHash)
		} else {
			m.CertificateHash = types.StringNull()
		}
		out.TrustedServers = append(out.TrustedServers, m)
	}
	return out
}

func expandTrustedNetworkCriteria(m *ztnaTrustedNetCriteria) ztnaprofiles.TrustedNetworkCriteria {
	if m == nil {
		return ztnaprofiles.TrustedNetworkCriteria{}
	}
	out := ztnaprofiles.TrustedNetworkCriteria{}
	for _, s := range m.DnsServers {
		out.DnsServers = append(out.DnsServers, ztnaprofiles.DnsServer{ServerIp: s.ServerIp.ValueString()})
	}
	for _, d := range m.DnsDomains {
		out.DnsDomains = append(out.DnsDomains, ztnaprofiles.DnsDomain{Name: d.Name.ValueString()})
	}
	for _, t := range m.TrustedServers {
		ts := ztnaprofiles.TrustedServer{Url: t.Url.ValueString()}
		if !t.CertificateHash.IsNull() && !t.CertificateHash.IsUnknown() {
			s := t.CertificateHash.ValueString()
			ts.CertificateHash = &s
		}
		out.TrustedServers = append(out.TrustedServers, ts)
	}
	return out
}
