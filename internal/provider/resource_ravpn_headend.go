// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ravpnprofiles"
	retry "github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &ravpnHeadendResource{}
	_ resource.ResourceWithConfigure   = &ravpnHeadendResource{}
	_ resource.ResourceWithImportState = &ravpnHeadendResource{}
)

func NewRavpnHeadendResource() resource.Resource {
	return &ravpnHeadendResource{}
}

type ravpnHeadendResource struct {
	client *ravpnprofiles.APIClient
}

type ravpnHeadendModel struct {
	ID             types.String `tfsdk:"id"`
	OrganizationID types.String `tfsdk:"organization_id"`
	Rev            types.Int64  `tfsdk:"rev"`
	FQDN           types.String `tfsdk:"fqdn"`
	HostName       types.String `tfsdk:"hostname"`
	Regions        types.List   `tfsdk:"region"`
}

type ravpnHeadendRegionModel struct {
	ID               types.String `tfsdk:"id"`
	DisplayName      types.String `tfsdk:"display_name"`
	EndpointIpPool   types.List   `tfsdk:"endpoint_ip_pool"`
	ManagementIpPool types.List   `tfsdk:"management_ip_pool"`
	DnsID            types.String `tfsdk:"dns_id"`
	ServerGroupIds   types.List   `tfsdk:"server_group_ids"`
	NamedIpPools     types.List   `tfsdk:"named_ip_pool"`
}

type ravpnNamedIpPoolModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	IPv4StartAddr  types.String `tfsdk:"ipv4_start_addr"`
	IPv4EndAddr    types.String `tfsdk:"ipv4_end_addr"`
	IPv4SubnetMask types.String `tfsdk:"ipv4_subnet_mask"`
}

func (r *ravpnHeadendResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ravpn_headend"
}

func (r *ravpnHeadendResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ravpnHeadendResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access RAVPN Headend. Only one headend exists per organization.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of the RAVPN headend.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID that owns the headend.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rev": schema.Int64Attribute{
				Description: "Optimistic-concurrency revision number.",
				Computed:    true,
			},
			"fqdn": schema.StringAttribute{
				Description: "Fully qualified domain name of the headend.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"hostname": schema.StringAttribute{
				Description: "Hostname of the headend.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.ListNestedAttribute{
				Description: "Regions configured for this headend.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "AWS region identifier (e.g. us-west-2). Required for creation, computed thereafter.",
							Optional:    true,
							Computed:    true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"display_name": schema.StringAttribute{
							Description: "Display name of the region.",
							Required:    true,
						},
						"endpoint_ip_pool": schema.ListAttribute{
							Description: "Endpoint IP pool addresses for the region.",
							Required:    true,
							ElementType: types.StringType,
						},
						"management_ip_pool": schema.ListAttribute{
							Description: "Management IP pool addresses for the region.",
							Required:    true,
							ElementType: types.StringType,
						},
						"dns_id": schema.StringAttribute{
							Description: "DNS server ID for the region.",
							Required:    true,
						},
						"server_group_ids": schema.ListAttribute{
							Description: "Server group IDs for the region.",
							Optional:    true,
							Computed:    true,
							ElementType: types.StringType,
							PlanModifiers: []planmodifier.List{
								listplanmodifier.UseStateForUnknown(),
							},
						},
						"named_ip_pool": schema.ListNestedAttribute{
							Description: "Named IP pools configured for this region.",
							Optional:    true,
							Computed:    true,
							PlanModifiers: []planmodifier.List{
								listplanmodifier.UseStateForUnknown(),
							},
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Description: "Unique ID of the named IP pool.",
										Computed:    true,
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
										},
									},
									"name": schema.StringAttribute{
										Description: "Name of the IP pool.",
										Required:    true,
									},
									"ipv4_start_addr": schema.StringAttribute{
										Description: "Start address of the IPv4 range.",
										Required:    true,
									},
									"ipv4_end_addr": schema.StringAttribute{
										Description: "End address of the IPv4 range.",
										Required:    true,
									},
									"ipv4_subnet_mask": schema.StringAttribute{
										Description: "Subnet mask of the IPv4 range.",
										Required:    true,
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

func (r *ravpnHeadendResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ravpnHeadendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := plan.OrganizationID.ValueString()

	// Check if a headend already exists for this org (only one per org)
	existing, _, err := r.client.HeadendsAPI.GetHeadend(ctx, orgID).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error checking existing headend", err.Error())
		return
	}

	if existing != nil {
		// Adopt existing headend and update its regions
		tflog.Info(ctx, "Headend already exists for org, adopting and updating", map[string]interface{}{
			"org_id":     orgID,
			"headend_id": existing.HeadendID,
		})

		regions := expandHeadendRegions(ctx, plan.Regions)
		input := ravpnprofiles.HeadendUpdateInput{
			HeadendID: existing.HeadendID,
			Rev:       existing.Rev,
			Regions:   regions,
		}

		updated, _, updateErr := r.client.HeadendsAPI.UpdateHeadend(ctx, orgID).HeadendUpdateInput(input).Execute()
		if updateErr != nil {
			resp.Diagnostics.AddError("Error updating adopted headend", updateErr.Error())
			return
		}

		flattenHeadend(ctx, updated, &plan)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// No headend exists, create one via POST
	regions := expandHeadendRegions(ctx, plan.Regions)
	input := ravpnprofiles.HeadendCreateInput{
		Regions: regions,
	}

	created, _, createErr := r.client.HeadendsAPI.CreateHeadend(ctx, orgID).HeadendCreateInput(input).Execute()
	if createErr != nil {
		resp.Diagnostics.AddError("Error creating RAVPN headend", createErr.Error())
		return
	}

	flattenHeadend(ctx, created, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ravpnHeadendResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ravpnHeadendModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := state.OrganizationID.ValueString()
	headend, _, err := r.client.HeadendsAPI.GetHeadend(ctx, orgID).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error reading RAVPN headend", err.Error())
		return
	}

	if headend == nil || headend.HeadendID != state.ID.ValueString() {
		tflog.Info(ctx, "RAVPN headend not found, removing from state", map[string]interface{}{
			"id": state.ID.ValueString(),
		})
		resp.State.RemoveResource(ctx)
		return
	}

	flattenHeadend(ctx, headend, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ravpnHeadendResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ravpnHeadendModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := plan.OrganizationID.ValueString()
	var updated *ravpnprofiles.Headend

	err := retry.Do(func() error {
		current, _, readErr := r.client.HeadendsAPI.GetHeadend(ctx, orgID).Execute()
		if readErr != nil {
			return retry.Unrecoverable(readErr)
		}
		if current == nil {
			return retry.Unrecoverable(fmt.Errorf("headend not found for org %s", orgID))
		}

		regions := expandHeadendRegions(ctx, plan.Regions)
		input := ravpnprofiles.HeadendUpdateInput{
			HeadendID: current.HeadendID,
			Rev:       current.Rev,
			Regions:   regions,
		}

		var putErr error
		var httpResp *http.Response
		updated, httpResp, putErr = r.client.HeadendsAPI.UpdateHeadend(ctx, orgID).HeadendUpdateInput(input).Execute()
		if putErr != nil && httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			return putErr
		}
		if putErr != nil {
			return retry.Unrecoverable(putErr)
		}
		return nil
	},
		retry.Attempts(5),
	)

	if err != nil {
		resp.Diagnostics.AddError("Error updating RAVPN headend", err.Error())
		return
	}

	flattenHeadend(ctx, updated, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ravpnHeadendResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Only one headend per org and it may not be deletable.
	// Remove from Terraform state only.
	tflog.Info(ctx, "RAVPN headend cannot be deleted, removing from state only")
}

func (r *ravpnHeadendResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- expand helpers ----

func expandHeadendRegions(ctx context.Context, regionsList types.List) []ravpnprofiles.HeadendRegion {
	if regionsList.IsNull() || regionsList.IsUnknown() {
		return nil
	}

	var regionModels []ravpnHeadendRegionModel
	regionsList.ElementsAs(ctx, &regionModels, false)

	regions := make([]ravpnprofiles.HeadendRegion, 0, len(regionModels))
	for _, rm := range regionModels {
		endpointIps := expandStringList(ctx, rm.EndpointIpPool)
		managementIps := expandStringList(ctx, rm.ManagementIpPool)
		serverGroupIds := expandStringList(ctx, rm.ServerGroupIds)

		region := ravpnprofiles.HeadendRegion{
			DisplayName:      rm.DisplayName.ValueString(),
			EndpointIpPool:   endpointIps,
			ManagementIpPool: managementIps,
			DnsID:            rm.DnsID.ValueString(),
			ServerGroupIds:   serverGroupIds,
			NamedIpPools:     expandNamedIpPools(ctx, rm.NamedIpPools, endpointIps),
		}
		if !rm.ID.IsNull() && !rm.ID.IsUnknown() {
			region.ID = rm.ID.ValueString()
		}
		regions = append(regions, region)
	}
	return regions
}

func expandNamedIpPools(ctx context.Context, poolsList types.List, endpointIpPool []string) []ravpnprofiles.NamedIpPool {
	if poolsList.IsNull() || poolsList.IsUnknown() {
		return nil
	}

	var poolModels []ravpnNamedIpPoolModel
	poolsList.ElementsAs(ctx, &poolModels, false)

	pools := make([]ravpnprofiles.NamedIpPool, 0, len(poolModels))
	for _, pm := range poolModels {
		pool := ravpnprofiles.NamedIpPool{
			Name:           pm.Name.ValueString(),
			IpPoolName:     pm.Name.ValueString(),
			Subnets:        endpointIpPool,
			IPv4StartAddr:  pm.IPv4StartAddr.ValueString(),
			IPv4EndAddr:    pm.IPv4EndAddr.ValueString(),
			IPv4SubnetMask: pm.IPv4SubnetMask.ValueString(),
		}
		if !pm.ID.IsNull() && !pm.ID.IsUnknown() {
			pool.ID = pm.ID.ValueString()
		}
		pools = append(pools, pool)
	}
	return pools
}

// expandStringList extracts a []string from a types.List with StringType elements.
func expandStringList(ctx context.Context, list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var elems []types.String
	list.ElementsAs(ctx, &elems, false)
	result := make([]string, 0, len(elems))
	for _, e := range elems {
		if !e.IsNull() && !e.IsUnknown() {
			result = append(result, e.ValueString())
		}
	}
	return result
}

// ---- flatten helpers ----

func flattenHeadend(ctx context.Context, h *ravpnprofiles.Headend, m *ravpnHeadendModel) {
	if h == nil {
		return
	}

	var planRegions []ravpnHeadendRegionModel
	if !m.Regions.IsNull() && !m.Regions.IsUnknown() {
		m.Regions.ElementsAs(ctx, &planRegions, false)
	}

	m.ID = types.StringValue(h.HeadendID)
	m.Rev = types.Int64Value(int64(h.Rev))
	m.FQDN = types.StringValue(h.FQDN)
	m.HostName = types.StringValue(h.HostName)

	m.Regions = flattenHeadendRegions(ctx, h.Regions, planRegions)
}

func flattenHeadendRegions(ctx context.Context, regions []ravpnprofiles.HeadendRegion, planRegions []ravpnHeadendRegionModel) types.List {
	if len(regions) == 0 {
		return types.ListValueMust(regionObjectType(), []attr.Value{})
	}

	regionValues := make([]attr.Value, 0, len(regions))
	for i, r := range regions {
		var planPools []ravpnNamedIpPoolModel
		if i < len(planRegions) {
			planRegions[i].NamedIpPools.ElementsAs(ctx, &planPools, false)
		}

		regionObj, _ := types.ObjectValue(regionAttrTypes(), map[string]attr.Value{
			"id":                 types.StringValue(r.ID),
			"display_name":      types.StringValue(r.DisplayName),
			"endpoint_ip_pool":  flattenStringList(r.EndpointIpPool),
			"management_ip_pool": flattenStringList(r.ManagementIpPool),
			"dns_id":            types.StringValue(r.DnsID),
			"server_group_ids":  flattenStringList(r.ServerGroupIds),
			"named_ip_pool":     flattenNamedIpPools(r.NamedIpPools, planPools),
		})
		regionValues = append(regionValues, regionObj)
	}

	listVal, _ := types.ListValue(regionObjectType(), regionValues)
	return listVal
}

func flattenNamedIpPools(pools []ravpnprofiles.NamedIpPool, planPools []ravpnNamedIpPoolModel) types.List {
	if len(pools) == 0 {
		return types.ListValueMust(namedIpPoolObjectType(), []attr.Value{})
	}

	poolModels := make([]attr.Value, 0, len(pools))
	for i, p := range pools {
		name := p.Name
		if name == "" {
			name = p.IpPoolName
		}

		ipv4Start := p.IPv4StartAddr
		ipv4End := p.IPv4EndAddr
		ipv4Mask := p.IPv4SubnetMask

		if i < len(planPools) {
			if ipv4Start == "" && !planPools[i].IPv4StartAddr.IsNull() {
				ipv4Start = planPools[i].IPv4StartAddr.ValueString()
			}
			if ipv4End == "" && !planPools[i].IPv4EndAddr.IsNull() {
				ipv4End = planPools[i].IPv4EndAddr.ValueString()
			}
			if ipv4Mask == "" && !planPools[i].IPv4SubnetMask.IsNull() {
				ipv4Mask = planPools[i].IPv4SubnetMask.ValueString()
			}
			if name == "" && !planPools[i].Name.IsNull() {
				name = planPools[i].Name.ValueString()
			}
		}

		poolObj, _ := types.ObjectValue(namedIpPoolAttrTypes(), map[string]attr.Value{
			"id":               types.StringValue(p.ID),
			"name":             types.StringValue(name),
			"ipv4_start_addr":  types.StringValue(ipv4Start),
			"ipv4_end_addr":    types.StringValue(ipv4End),
			"ipv4_subnet_mask": types.StringValue(ipv4Mask),
		})
		poolModels = append(poolModels, poolObj)
	}

	listVal, _ := types.ListValue(namedIpPoolObjectType(), poolModels)
	return listVal
}

func flattenStringList(items []string) types.List {
	if items == nil {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}

	elems := make([]attr.Value, 0, len(items))
	for _, item := range items {
		elems = append(elems, types.StringValue(item))
	}

	listVal, _ := types.ListValue(types.StringType, elems)
	return listVal
}

// ---- type helpers ----

func namedIpPoolAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.StringType,
		"name":             types.StringType,
		"ipv4_start_addr":  types.StringType,
		"ipv4_end_addr":    types.StringType,
		"ipv4_subnet_mask": types.StringType,
	}
}

func namedIpPoolObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: namedIpPoolAttrTypes()}
}

func regionAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"display_name":      types.StringType,
		"endpoint_ip_pool":  types.ListType{ElemType: types.StringType},
		"management_ip_pool": types.ListType{ElemType: types.StringType},
		"dns_id":            types.StringType,
		"server_group_ids":  types.ListType{ElemType: types.StringType},
		"named_ip_pool":     types.ListType{ElemType: namedIpPoolObjectType()},
	}
}

func regionObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: regionAttrTypes()}
}
