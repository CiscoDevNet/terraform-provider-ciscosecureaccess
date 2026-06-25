// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ravpnprofiles"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &ravpnDnsServerResource{}
	_ resource.ResourceWithConfigure   = &ravpnDnsServerResource{}
	_ resource.ResourceWithImportState = &ravpnDnsServerResource{}
)

func NewRavpnDnsServerResource() resource.Resource {
	return &ravpnDnsServerResource{}
}

type ravpnDnsServerResource struct {
	client *ravpnprofiles.APIClient
}

type ravpnDnsServerModel struct {
	ID             types.String `tfsdk:"id"`
	OrganizationID types.String `tfsdk:"organization_id"`
	ServerName     types.String `tfsdk:"server_name"`
	ServerIps      types.List   `tfsdk:"server_ips"`
	Priority       types.Int64  `tfsdk:"priority"`
}

func (r *ravpnDnsServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ravpn_dns_server"
}

func (r *ravpnDnsServerResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = factory.GetRavpnProfilesClient(ctx)
}

func (r *ravpnDnsServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access RAVPN DNS server resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Resource instance ID of the DNS server.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID that owns the DNS server resource.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server_name": schema.StringAttribute{
				Description: "Display name of the DNS server.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server_ips": schema.ListAttribute{
				Description: "List of DNS server IP addresses.",
				Required:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
			"priority": schema.Int64Attribute{
				Description: "Priority of the DNS server (default: 1).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(1),
			},
		},
	}
}

func (r *ravpnDnsServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ravpnDnsServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serverIps := expandStringList(ctx, plan.ServerIps)

	input := ravpnprofiles.DNSServerCreateInput{
		DnsServers: ravpnprofiles.DNSServerData{
			ServerName: plan.ServerName.ValueString(),
			ServerIps:  serverIps,
			Priority:   int(plan.Priority.ValueInt64()),
		},
	}

	orgID := plan.OrganizationID.ValueString()

	existing, _, listErr := r.client.DnsServersAPI.ListDnsServers(ctx, orgID).Execute()
	if listErr == nil {
		for _, s := range existing {
			if s.DnsServers.ServerName == plan.ServerName.ValueString() {
				tflog.Info(ctx, "RAVPN DNS server already exists, adopting", map[string]interface{}{
					"server_name": s.DnsServers.ServerName,
					"id":          s.ResourceInstanceID,
				})
				plan.ID = types.StringValue(strconv.FormatInt(s.ResourceInstanceID, 10))
				resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
				return
			}
		}
	}

	created, httpResp, err := r.client.DnsServersAPI.CreateDnsServer(ctx, orgID).DNSServerCreateInput(input).Execute()
	if err != nil {
		detail := fmt.Sprintf("failed to create RAVPN DNS server: %s", err.Error())
		if httpResp != nil {
			detail = fmt.Sprintf("%s (HTTP %d)", detail, httpResp.StatusCode)
		}
		resp.Diagnostics.AddError("Error creating RAVPN DNS server", detail)
		return
	}

	plan.ID = types.StringValue(strconv.FormatInt(created.ResourceInstanceID, 10))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ravpnDnsServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ravpnDnsServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := state.OrganizationID.ValueString()
	servers, httpResp, err := r.client.DnsServersAPI.ListDnsServers(ctx, orgID).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, "RAVPN DNS server org not found, removing from state", map[string]interface{}{"org_id": orgID})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading RAVPN DNS servers", err.Error())
		return
	}

	targetID := state.ID.ValueString()
	var found *ravpnprofiles.DNSServerResource
	for i := range servers {
		if strconv.FormatInt(servers[i].ResourceInstanceID, 10) == targetID {
			found = &servers[i]
			break
		}
	}

	if found == nil {
		tflog.Info(ctx, "RAVPN DNS server not found, removing from state", map[string]interface{}{"id": targetID})
		resp.State.RemoveResource(ctx)
		return
	}

	state.ServerName = types.StringValue(found.DnsServers.ServerName)
	state.Priority = types.Int64Value(int64(found.DnsServers.Priority))

	ipElems := make([]attr.Value, len(found.DnsServers.ServerIps))
	for i, ip := range found.DnsServers.ServerIps {
		ipElems[i] = types.StringValue(ip)
	}
	listVal, diags := types.ListValue(types.StringType, ipElems)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ServerIps = listVal

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ravpnDnsServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// No update API exists. All mutable attributes use RequiresReplace,
	// so Terraform will never call Update. This is a no-op safeguard.
	resp.Diagnostics.AddError(
		"Update not supported",
		"RAVPN DNS server resources do not support in-place updates. All changes require replacement.",
	)
}

func (r *ravpnDnsServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ravpnDnsServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := state.OrganizationID.ValueString()
	serverID := state.ID.ValueString()

	httpResp, err := r.client.DnsServersAPI.DeleteDnsServer(ctx, orgID, serverID).Execute()
	if err != nil {
		if httpResp != nil && (httpResp.StatusCode == http.StatusNotFound || httpResp.StatusCode == http.StatusBadRequest) {
			tflog.Warn(ctx, "DNS server delete returned non-success, removing from state anyway", map[string]interface{}{
				"id":     serverID,
				"status": httpResp.StatusCode,
			})
			return
		}
		resp.Diagnostics.AddError("Error deleting RAVPN DNS server",
			fmt.Sprintf("failed to delete DNS server %s: %s", serverID, err.Error()))
	}
}

func (r *ravpnDnsServerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

