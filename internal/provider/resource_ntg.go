// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ntg"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &networkTunnelGroupResource{}
	_ resource.ResourceWithConfigure = &networkTunnelGroupResource{}
)

// NewNetworkTunnelGroupResource is a helper function to simplify the provider implementation.
func NewNetworkTunnelGroupResource() resource.Resource {
	return &networkTunnelGroupResource{}
}

// networkTunnelGroupResource is the resource implementation.
type networkTunnelGroupResource struct {
	client ntg.APIClient
}

// ntgResourceModel maps the data schema data.
type ntgResourceModel struct {
	Id               types.Int64    `tfsdk:"id"`
	NetworkCidrs     []types.String `tfsdk:"network_cidrs"`
	Name             types.String   `tfsdk:"name"`
	Region           types.String   `tfsdk:"region"`
	IdentifierPrefix types.String   `tfsdk:"identifier_prefix"`
	PresharedKey     types.String   `tfsdk:"preshared_key"`
	DeviceType       types.String   `tfsdk:"device_type"`
	Hubs             types.List     `tfsdk:"hubs"`
}

type hubModel struct {
	Id         types.Int64     `tfsdk:"id"`
	Datacenter datacenterModel `tfsdk:"datacenter"`
	AuthID     types.String    `tfsdk:"auth_id"`
	IsPrimary  types.Bool      `tfsdk:"is_primary"`
}

func (h hubModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":         types.Int64Type,
		"datacenter": types.ObjectType{AttrTypes: datacenterModel{}.AttrTypes()},
		"auth_id":    types.StringType,
		"is_primary": types.BoolType,
	}
}

type datacenterModel struct {
	Name types.String `tfsdk:"name"`
	IP   types.String `tfsdk:"ip"`
}

func (d datacenterModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType,
		"ip":   types.StringType,
	}
}

// Metadata returns the resource type name.
func (r *networkTunnelGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_tunnel_group"
}

// Configure adds the provider configured client to the resource.
func (r *networkTunnelGroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = *factory.GetNtgClient(ctx)
}

// Schema defines the schema for the resource.
func (r *networkTunnelGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		//TODO: BGP support
		Description: "Cisco Secure Access Network Tunnel Group resource, currently supports static routes only",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of network tunnel group",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"network_cidrs": schema.ListAttribute{
				Description: "Inside Network CIDR addresses of network tunnel group",
				Optional:    true,
				ElementType: types.StringType,
			},
			"name": schema.StringAttribute{
				Description: "Name of network tunnel group",
				Required:    true,
			},
			"region": schema.StringAttribute{
				Description:   "Deployment region of network tunnel group",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"identifier_prefix": schema.StringAttribute{
				Description:   "Prefix for tunnel authentication ID",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"preshared_key": schema.StringAttribute{
				Description: "Secret preshared key used to authenticate network tunnel group",
				Sensitive:   true,
				Required:    true,
			},
			"device_type": schema.StringAttribute{
				Description: "Type of device used to terminate network tunnel group",
				Required:    true,
				//TODO: Input validation
			},
			"hubs": schema.ListNestedAttribute{
				Description: "Remote connection endpoints for connecting network tunnel group",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "Unique ID of remote hub",
							Computed:    true,
						},
						"is_primary": schema.BoolAttribute{
							Description: "Whether or not hub is designated as 'primary'",
							Computed:    true,
						},
						"datacenter": schema.SingleNestedAttribute{
							Description: "Datacenter information for hub",
							Computed:    true,
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Description: "Name of datacenter where hub is located",
									Computed:    true,
								},
								"ip": schema.StringAttribute{
									Description: "External IP of datacenter where hub is located",
									Computed:    true,
								},
							},
						},
						"auth_id": schema.StringAttribute{
							Description: "IPSec authentication ID used for connecting to remote hub",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *networkTunnelGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Network Tunnel Group")
	// Retrieve values from plan
	var plan ntgResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	planRep, _ := json.Marshal(plan)
	tflog.Debug(ctx, "Local tunnel definition", map[string]interface{}{"definition": string(planRep)})

	var err error

	tunnelIdentifier := plan.IdentifierPrefix.ValueString()
	name := plan.Name.ValueString()
	routeList := convertNetworkCidrsToStrings(plan.NetworkCidrs)
	region := plan.Region.ValueString()
	presharedKey := plan.PresharedKey.ValueString()
	devTypeDescription := plan.DeviceType.ValueString()

	addNetworkTunnelGroupRequest := *ntg.NewAddNetworkTunnelGroupRequest(name, region, ntg.StringAsAddNetworkTunnelGroupRequestAuthIdPrefix(&tunnelIdentifier), presharedKey)
	staticRoute := ntg.RoutingRequest{Type: "static", Data: ntg.RoutingRequestData{StaticDataRequestObj: &ntg.StaticDataRequestObj{NetworkCIDRs: routeList}}}
	addNetworkTunnelGroupRequest.SetRouting(staticRoute)
	deviceType, err := ntg.NewDeviceTypeFromValue(devTypeDescription)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing device type for tunnel",
			"Unexpected error: "+err.Error(),
		)
		return
	}
	addNetworkTunnelGroupRequest.SetDeviceType(*deviceType)

	createResp, httpResp, err := r.client.NetworkTunnelGroupsAPI.AddNetworkTunnelGroup(ctx).AddNetworkTunnelGroupRequest(addNetworkTunnelGroupRequest).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			tflog.Info(ctx, "Network tunnel group already exists (409), adopting existing resource", map[string]interface{}{"name": name})
			r.adoptExistingTunnel(ctx, name, &plan, resp)
			return
		}
		resp.Diagnostics.AddError(
			"Error creating network tunnel group",
			fmt.Sprintf("Failed to create network tunnel group '%s': %v", name, err),
		)
		return
	}

	tflog.Debug(ctx, "Created network tunnel group", map[string]interface{}{
		"id":   createResp.GetId(),
		"name": name,
	})
	plan.Id = types.Int64Value(createResp.GetId())

	// Convert API hubs to terraform models
	var hubs []hubModel
	for _, hub := range createResp.Hubs {
		if hub.Id == nil || hub.AuthId == nil || hub.IsPrimary == nil || hub.Datacenter == nil || hub.Datacenter.Name == nil || hub.Datacenter.Ip == nil {
			resp.Diagnostics.AddError("Unexpected API Response", "Hub data is incomplete in the API response")
			return
		}
		dc := datacenterModel{
			Name: types.StringValue(*hub.Datacenter.Name),
			IP:   types.StringValue(*hub.Datacenter.Ip),
		}
		hubInstance := hubModel{
			Id:         types.Int64Value(*hub.Id),
			Datacenter: dc,
			AuthID:     types.StringValue(*hub.AuthId),
			IsPrimary:  types.BoolValue(*hub.IsPrimary),
		}
		hubs = append(hubs, hubInstance)
	}

	plan.Hubs, diags = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: hubModel{}.AttrTypes()}, hubs)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

func (r *networkTunnelGroupResource) adoptExistingTunnel(ctx context.Context, name string, plan *ntgResourceModel, resp *resource.CreateResponse) {
	tunnelId, searched, err := r.findExistingTunnelByName(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error adopting existing network tunnel group",
			fmt.Sprintf("Tunnel '%s' returned 409 but could not be found via List API: %v", name, err),
		)
		return
	}
	if tunnelId == 0 {
		resp.Diagnostics.AddError(
			"Error adopting existing network tunnel group",
			fmt.Sprintf("Tunnel '%s' returned 409 but no exact name match found in %d List API results", name, searched),
		)
		return
	}
	tflog.Info(ctx, "Found existing tunnel, reading full details", map[string]interface{}{"id": tunnelId, "name": name})

	readResp, _, readErr := r.client.NetworkTunnelGroupsAPI.GetNetworkTunnelGroup(ctx, tunnelId).Execute()
	if readErr != nil {
		resp.Diagnostics.AddError(
			"Error reading adopted network tunnel group",
			fmt.Sprintf("Could not read tunnel group ID %d: %v", tunnelId, readErr),
		)
		return
	}

	if readResp.Name == nil || readResp.Region == nil || readResp.DeviceType == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Core fields (name, region, device_type) are nil in the API response")
		return
	}
	if readResp.Routing == nil || readResp.Routing.Data.StaticDataResponseObj == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Routing data is nil in the API response")
		return
	}

	plan.Id = types.Int64Value(tunnelId)
	plan.Name = types.StringValue(*readResp.Name)
	plan.Region = types.StringValue(*readResp.Region)
	plan.NetworkCidrs = convertStringsToNetworkCidrs(readResp.Routing.Data.StaticDataResponseObj.NetworkCIDRs)
	plan.DeviceType = types.StringValue(string(*readResp.DeviceType))

	var hubs []hubModel
	for _, hub := range readResp.Hubs {
		if hub.Id == nil || hub.AuthId == nil || hub.IsPrimary == nil || hub.Datacenter == nil || hub.Datacenter.Name == nil || hub.Datacenter.Ip == nil {
			resp.Diagnostics.AddError("Unexpected API Response", "Hub data is incomplete in the API response")
			return
		}
		dc := datacenterModel{
			Name: types.StringValue(*hub.Datacenter.Name),
			IP:   types.StringValue(*hub.Datacenter.Ip),
		}
		hubInstance := hubModel{
			Id:         types.Int64Value(*hub.Id),
			Datacenter: dc,
			AuthID:     types.StringValue(*hub.AuthId),
			IsPrimary:  types.BoolValue(*hub.IsPrimary),
		}
		hubs = append(hubs, hubInstance)
	}

	var diags diag.Diagnostics
	plan.Hubs, diags = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: hubModel{}.AttrTypes()}, hubs)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

const (
	networkTunnelGroupAdoptionPageLimit = int64(100)
	networkTunnelGroupAdoptionMaxPages  = 1000
)

func (r *networkTunnelGroupResource) findExistingTunnelByName(ctx context.Context, name string) (int64, int, error) {
	var offset int64
	searched := 0

	for page := 0; page < networkTunnelGroupAdoptionMaxPages; page++ {
		listResp, _, err := r.client.NetworkTunnelGroupsAPI.ListNetworkTunnelGroups(ctx).
			Offset(offset).
			Limit(networkTunnelGroupAdoptionPageLimit).
			Execute()
		if err != nil {
			return 0, searched, fmt.Errorf("list network tunnel groups at offset %d: %w", offset, err)
		}
		if listResp == nil {
			return 0, searched, fmt.Errorf("list network tunnel groups returned nil response at offset %d", offset)
		}
		if len(listResp.Data) == 0 {
			return 0, searched, nil
		}

		for _, candidate := range listResp.Data {
			searched++
			candidateName := ""
			if candidate.Name != nil {
				candidateName = *candidate.Name
			}
			tflog.Debug(ctx, "Checking tunnel candidate for adoption", map[string]interface{}{
				"candidate_name": candidateName,
				"looking_for":    name,
				"match":          strings.EqualFold(candidateName, name),
			})
			if candidate.Name == nil || !strings.EqualFold(*candidate.Name, name) {
				continue
			}
			if candidate.Id == nil {
				return 0, searched, fmt.Errorf("matched tunnel '%s' but List API response did not include an ID", name)
			}
			return *candidate.Id, searched, nil
		}

		nextOffset := offset + int64(len(listResp.Data))
		if listResp.HasTotal() && nextOffset >= listResp.GetTotal() {
			return 0, searched, nil
		}
		if nextOffset <= offset {
			return 0, searched, fmt.Errorf("list network tunnel groups pagination did not advance from offset %d", offset)
		}
		offset = nextOffset
	}

	return 0, searched, fmt.Errorf("searched %d pages without finding tunnel '%s'", networkTunnelGroupAdoptionMaxPages, name)
}

func (r *networkTunnelGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state ntgResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnelId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading network tunnel group", map[string]interface{}{"id": tunnelId})

	readResp, httpRes, err := r.client.NetworkTunnelGroupsAPI.GetNetworkTunnelGroup(ctx, tunnelId).Execute()
	if err != nil {
		if httpRes != nil && httpRes.StatusCode == 404 {
			tflog.Info(ctx, "Network tunnel group not found, removing from state", map[string]interface{}{"id": tunnelId})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading network tunnel group",
			fmt.Sprintf("Could not read network tunnel group ID %d: %s", tunnelId, err.Error()),
		)
		return
	}

	// Ensure httpRes is not nil before accessing its fields in Read
	if httpRes == nil {
		resp.Diagnostics.AddError(
			"HTTP Response Error",
			fmt.Sprintf("Received nil HTTP response while reading network tunnel group ID %d", tunnelId),
		)
		return
	}

	if readResp.Name == nil || readResp.Region == nil || readResp.DeviceType == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Core fields (name, region, device_type) are nil in the API response")
		return
	}
	if readResp.Routing == nil || readResp.Routing.Data.StaticDataResponseObj == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Routing data is nil in the API response")
		return
	}

	state.Name = types.StringValue(*readResp.Name)
	state.Region = types.StringValue(*readResp.Region)
	state.NetworkCidrs = convertStringsToNetworkCidrs(readResp.Routing.Data.StaticDataResponseObj.NetworkCIDRs)
	state.DeviceType = types.StringValue(string(*readResp.DeviceType))

	// Convert API hubs to terraform models
	var hubs []hubModel
	for _, hub := range readResp.Hubs {
		if hub.Id == nil || hub.AuthId == nil || hub.IsPrimary == nil || hub.Datacenter == nil || hub.Datacenter.Name == nil || hub.Datacenter.Ip == nil {
			resp.Diagnostics.AddError("Unexpected API Response", "Hub data is incomplete in the API response")
			return
		}
		dc := datacenterModel{
			Name: types.StringValue(*hub.Datacenter.Name),
			IP:   types.StringValue(*hub.Datacenter.Ip),
		}
		hubInstance := hubModel{
			Id:         types.Int64Value(*hub.Id),
			Datacenter: dc,
			AuthID:     types.StringValue(*hub.AuthId),
			IsPrimary:  types.BoolValue(*hub.IsPrimary),
		}
		hubs = append(hubs, hubInstance)
	}

	state.Hubs, diags = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: hubModel{}.AttrTypes()}, hubs)
	if diags.HasError() {
		resp.Diagnostics.AddError(
			"Error processing network tunnel group hubs",
			"Could not convert hubs to terraform state format",
		)
		return
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

}

func compareStringSlicesAsSets(a []basetypes.StringValue, b []basetypes.StringValue) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]int, len(a))
	for _, v := range a {
		set[v.ValueString()]++
	}
	for _, v := range b {
		set[v.ValueString()]--
		if set[v.ValueString()] < 0 {
			return false
		}
	}
	return true
}

// Helper functions

// convertNetworkCidrsToStrings converts terraform string values to string slice
func convertNetworkCidrsToStrings(cidrs []types.String) []string {
	result := make([]string, len(cidrs))
	for i, cidr := range cidrs {
		result[i] = cidr.ValueString()
	}
	return result
}

// convertStringsToNetworkCidrs converts string slice to terraform string values
func convertStringsToNetworkCidrs(cidrs []string) []basetypes.StringValue {
	result := make([]basetypes.StringValue, len(cidrs))
	for i, cidr := range cidrs {
		result[i] = types.StringValue(cidr)
	}
	return result
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *networkTunnelGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Network Tunnel Group")

	// Retrieve values from plan and state
	var plan, state ntgResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnelId := plan.Id.ValueInt64()
	var patchInners []ntg.PatchNetworkTunnelGroupRequestInner

	// Check for name changes
	if !plan.Name.Equal(state.Name) {
		name := plan.Name.ValueString()
		valueField := ntg.StringAsPatchNetworkTunnelGroupRequestInnerValue(&name)
		patchInners = append(patchInners, *ntg.NewPatchNetworkTunnelGroupRequestInner("replace", "/name", valueField))
	}

	// Check for preshared key changes
	if !plan.PresharedKey.Equal(state.PresharedKey) {
		key := plan.PresharedKey.ValueString()
		keyField := ntg.StringAsPatchNetworkTunnelGroupRequestInnerValue(&key)
		patchInners = append(patchInners, *ntg.NewPatchNetworkTunnelGroupRequestInner("replace", "/passphrase", keyField))
	}

	// Check for network CIDR changes
	if !compareStringSlicesAsSets(state.NetworkCidrs, plan.NetworkCidrs) {
		routeList := convertNetworkCidrsToStrings(plan.NetworkCidrs)
		route := ntg.RoutingRequest{
			Type: "static",
			Data: ntg.RoutingRequestData{
				StaticDataRequestObj: &ntg.StaticDataRequestObj{NetworkCIDRs: routeList},
			},
		}
		valueField := ntg.RoutingRequestAsPatchNetworkTunnelGroupRequestInnerValue(&route)
		patchInners = append(patchInners, *ntg.NewPatchNetworkTunnelGroupRequestInner("replace", "/routing", valueField))
	}

	// Only make API call if there are changes
	if len(patchInners) > 0 {
		updateResp, _, err := r.client.NetworkTunnelGroupsAPI.PatchNetworkTunnelGroup(ctx, tunnelId).PatchNetworkTunnelGroupRequestInner(patchInners).Execute()
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating network tunnel group",
				fmt.Sprintf("Could not update tunnel group ID %d: %s", tunnelId, err.Error()),
			)
			return
		}

		tflog.Debug(ctx, "Updated network tunnel group", map[string]interface{}{
			"id":      tunnelId,
			"changes": len(patchInners),
		})

		// Log the response for debugging
		if updateResp != nil {
			updateString, _ := json.Marshal(updateResp)
			tflog.Debug(ctx, "Update response for tunnel", map[string]interface{}{"tunnel_id": tunnelId, "response": string(updateString)})
		}
	}

	// Refresh full state from API to pick up server-assigned fields (e.g. hubs)
	refreshResp, _, refreshErr := r.client.NetworkTunnelGroupsAPI.GetNetworkTunnelGroup(ctx, tunnelId).Execute()
	if refreshErr != nil {
		resp.Diagnostics.AddError(
			"Error refreshing network tunnel group after update",
			fmt.Sprintf("Could not read tunnel group ID %d after update: %s", tunnelId, refreshErr.Error()),
		)
		return
	}

	if refreshResp.Name == nil || refreshResp.Region == nil || refreshResp.DeviceType == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Core fields (name, region, device_type) are nil in the API response")
		return
	}
	if refreshResp.Routing == nil || refreshResp.Routing.Data.StaticDataResponseObj == nil {
		resp.Diagnostics.AddError("Unexpected API Response", "Routing data is nil in the API response")
		return
	}

	state.Name = types.StringValue(*refreshResp.Name)
	state.Region = types.StringValue(*refreshResp.Region)
	state.NetworkCidrs = convertStringsToNetworkCidrs(refreshResp.Routing.Data.StaticDataResponseObj.NetworkCIDRs)
	state.DeviceType = types.StringValue(string(*refreshResp.DeviceType))
	// Preserve the preshared key from plan since the API does not return it
	state.PresharedKey = plan.PresharedKey

	var refreshHubs []hubModel
	for _, hub := range refreshResp.Hubs {
		if hub.Id == nil || hub.AuthId == nil || hub.IsPrimary == nil || hub.Datacenter == nil || hub.Datacenter.Name == nil || hub.Datacenter.Ip == nil {
			resp.Diagnostics.AddError("Unexpected API Response", "Hub data is incomplete in the API response")
			return
		}
		dc := datacenterModel{
			Name: types.StringValue(*hub.Datacenter.Name),
			IP:   types.StringValue(*hub.Datacenter.Ip),
		}
		refreshHubs = append(refreshHubs, hubModel{
			Id:         types.Int64Value(*hub.Id),
			Datacenter: dc,
			AuthID:     types.StringValue(*hub.AuthId),
			IsPrimary:  types.BoolValue(*hub.IsPrimary),
		})
	}

	var hubDiags diag.Diagnostics
	state.Hubs, hubDiags = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: hubModel{}.AttrTypes()}, refreshHubs)
	if hubDiags.HasError() {
		resp.Diagnostics.Append(hubDiags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *networkTunnelGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state ntgResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tunnelId := state.Id.ValueInt64()
	tflog.Info(ctx, "Deleting network tunnel group", map[string]interface{}{"id": tunnelId})

	// Delete existing tunnel
	httpRes, err := r.client.NetworkTunnelGroupsAPI.DeleteNetworkTunnelGroup(ctx, tunnelId).Execute()
	if err != nil {
		if httpRes != nil && httpRes.StatusCode == 404 {
			// Resource already deleted
			tflog.Info(ctx, "Network tunnel group already deleted", map[string]interface{}{"id": tunnelId})
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting network tunnel group",
			fmt.Sprintf("Could not delete tunnel group ID %d: %s", tunnelId, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted network tunnel group", map[string]interface{}{
		"id":     tunnelId,
		"status": httpRes.Status,
	})
}
