// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/privateapps"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &privateResourceGroupResource{}
	_ resource.ResourceWithConfigure   = &privateResourceGroupResource{}
	_ resource.ResourceWithImportState = &privateResourceGroupResource{}
)

const (
	privateResourceGroupReadAttempts = 3
	privateResourceGroupReadDelay    = 2 * time.Second
)

var privateResourceGroupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9 -]+$`)

type privateResourceGroupResource struct {
	client privateapps.APIClient
}

type privateResourceGroupModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	ResourceIDs types.Set    `tfsdk:"resource_ids"`
	CreatedAt   types.String `tfsdk:"created_at"`
	ModifiedAt  types.String `tfsdk:"modified_at"`
}

func NewPrivateResourceGroupResource() resource.Resource {
	return &privateResourceGroupResource{}
}

func (r *privateResourceGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_resource_group"
}

func (r *privateResourceGroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = *factory.GetPrivateAppsClient(ctx)
}

func (r *privateResourceGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access private resource group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of the private resource group.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the private resource group. Only letters, numbers, spaces, and hyphens are allowed.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						privateResourceGroupNamePattern,
						"must contain only letters, numbers, spaces, and hyphens",
					),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the private resource group.",
				Optional:    true,
			},
			"resource_ids": schema.SetAttribute{
				Description: "IDs of private resources that belong to the group. The set may be empty.",
				Required:    true,
				ElementType: types.Int64Type,
				Validators: []validator.Set{
					setvalidator.ValueInt64sAre(int64validator.AtLeast(1)),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "Creation timestamp returned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				Description: "Last-modified timestamp returned by the API.",
				Computed:    true,
			},
		},
	}
}

func (r *privateResourceGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan privateResourceGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, diags := expandPrivateResourceGroupRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, status, err := r.createPrivateResourceGroup(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating private resource group",
			privateResourceGroupErrorDetail("create private resource group", 0, status, err),
		)
		return
	}
	if created == nil || created.ResourceGroupId == nil || created.GetResourceGroupId() <= 0 {
		resp.Diagnostics.AddError(
			"Invalid private resource group response",
			"The create response did not include a valid resourceGroupId.",
		)
		return
	}

	plan.ID = types.Int64Value(created.GetResourceGroupId())
	plan.CreatedAt = types.StringNull()
	plan.ModifiedAt = types.StringNull()
	// Persist the ID before the read-back so an unexpected refresh failure does not lose ownership.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	refreshed, err := r.readPrivateResourceGroupAfterMutation(ctx, plan.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading private resource group after create", err.Error())
		return
	}
	resp.Diagnostics.Append(flattenPrivateResourceGroupResponse(ctx, refreshed, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created private resource group", map[string]interface{}{"resource_group_id": plan.ID.ValueInt64()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *privateResourceGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state privateResourceGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, status, err := r.getPrivateResourceGroup(ctx, state.ID.ValueInt64())
	if err != nil {
		if status == http.StatusNotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading private resource group",
			privateResourceGroupErrorDetail("read private resource group", state.ID.ValueInt64(), status, err),
		)
		return
	}

	resp.Diagnostics.Append(flattenPrivateResourceGroupResponse(ctx, group, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *privateResourceGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state privateResourceGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = state.ID
	payload, diags := expandPrivateResourceGroupRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, status, err := r.updatePrivateResourceGroup(ctx, plan.ID.ValueInt64(), payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating private resource group",
			privateResourceGroupErrorDetail("update private resource group", plan.ID.ValueInt64(), status, err),
		)
		return
	}
	plan.CreatedAt = state.CreatedAt
	plan.ModifiedAt = state.ModifiedAt
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	refreshed, err := r.readPrivateResourceGroupAfterMutation(ctx, plan.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading private resource group after update", err.Error())
		return
	}
	resp.Diagnostics.Append(flattenPrivateResourceGroupResponse(ctx, refreshed, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated private resource group", map[string]interface{}{"resource_group_id": plan.ID.ValueInt64()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *privateResourceGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state privateResourceGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	status, err := r.deletePrivateResourceGroup(ctx, state.ID.ValueInt64())
	if err == nil || status == http.StatusNotFound {
		return
	}

	detail := privateResourceGroupErrorDetail("delete private resource group", state.ID.ValueInt64(), status, err)
	if status == http.StatusBadRequest || status == http.StatusConflict {
		detail += " Remove policy references to the group before deleting it; the provider will not force deletion."
	}
	resp.Diagnostics.AddError("Error deleting private resource group", detail)
}

func (r *privateResourceGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := parsePrivateResourceGroupID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func expandPrivateResourceGroupRequest(ctx context.Context, model *privateResourceGroupModel) (privateapps.PrivateResourceGroupRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	resourceIDs := make([]int64, 0)
	diags.Append(model.ResourceIDs.ElementsAs(ctx, &resourceIDs, false)...)
	if diags.HasError() {
		return privateapps.PrivateResourceGroupRequest{}, diags
	}
	sort.Slice(resourceIDs, func(i, j int) bool { return resourceIDs[i] < resourceIDs[j] })

	payload := privateapps.NewPrivateResourceGroupRequest(model.Name.ValueString(), resourceIDs)
	if !model.Description.IsNull() && !model.Description.IsUnknown() {
		payload.SetDescription(model.Description.ValueString())
	}

	return *payload, diags
}

func flattenPrivateResourceGroupResponse(ctx context.Context, group *privateapps.PrivateResourceGroupResponse, model *privateResourceGroupModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if group == nil {
		diags.AddError("Invalid private resource group response", "The API returned an empty private resource group response.")
		return diags
	}

	if group.ResourceGroupId != nil {
		model.ID = types.Int64Value(group.GetResourceGroupId())
	} else if model.ID.IsNull() || model.ID.IsUnknown() {
		diags.AddError("Invalid private resource group response", "The API response did not include resourceGroupId.")
	}

	if group.Name != nil {
		model.Name = types.StringValue(group.GetName())
	} else if model.Name.IsNull() || model.Name.IsUnknown() {
		diags.AddError("Invalid private resource group response", "The API response did not include name.")
	}

	if group.Description != nil {
		model.Description = types.StringValue(group.GetDescription())
	} else {
		model.Description = types.StringNull()
	}

	if group.ResourceIds == nil {
		diags.AddError("Invalid private resource group response", "The API response did not include resourceIds.")
	} else {
		resourceIDs := make([]int64, len(group.ResourceIds))
		copy(resourceIDs, group.ResourceIds)
		var setDiags diag.Diagnostics
		model.ResourceIDs, setDiags = types.SetValueFrom(ctx, types.Int64Type, resourceIDs)
		diags.Append(setDiags...)
	}

	if group.CreatedAt != nil {
		model.CreatedAt = types.StringValue(group.GetCreatedAt().UTC().Format(time.RFC3339Nano))
	} else {
		model.CreatedAt = types.StringNull()
	}
	if group.ModifiedAt != nil {
		model.ModifiedAt = types.StringValue(group.GetModifiedAt().UTC().Format(time.RFC3339Nano))
	} else {
		model.ModifiedAt = types.StringNull()
	}

	return diags
}

func parsePrivateResourceGroupID(value string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("expected a positive numeric private resource group ID, got %q", value)
	}
	return id, nil
}

func (r *privateResourceGroupResource) createPrivateResourceGroup(ctx context.Context, payload privateapps.PrivateResourceGroupRequest) (*privateapps.PrivateResourceGroupResponse, int, error) {
	group, httpResp, err := r.client.ResourceGroupsAPI.AddPrivateResourceGroup(ctx).PrivateResourceGroupRequest(payload).Execute()
	status := privateResourceGroupResponseStatus(httpResp)
	closePrivateResourceGroupResponse(httpResp)
	return group, status, err
}

func (r *privateResourceGroupResource) getPrivateResourceGroup(ctx context.Context, id int64) (*privateapps.PrivateResourceGroupResponse, int, error) {
	group, httpResp, err := r.client.ResourceGroupsAPI.GetPrivateResourceGroup(ctx, id).Execute()
	status := privateResourceGroupResponseStatus(httpResp)
	closePrivateResourceGroupResponse(httpResp)
	return group, status, err
}

func (r *privateResourceGroupResource) updatePrivateResourceGroup(ctx context.Context, id int64, payload privateapps.PrivateResourceGroupRequest) (*privateapps.PrivateResourceGroupResponse, int, error) {
	group, httpResp, err := r.client.ResourceGroupsAPI.PutPrivateResourceGroup(ctx, id).PrivateResourceGroupRequest(payload).Execute()
	status := privateResourceGroupResponseStatus(httpResp)
	closePrivateResourceGroupResponse(httpResp)
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return group, status, nil
	}
	if err == nil {
		err = fmt.Errorf("unexpected HTTP status %d", status)
	}
	return group, status, err
}

func (r *privateResourceGroupResource) deletePrivateResourceGroup(ctx context.Context, id int64) (int, error) {
	_, httpResp, err := r.client.ResourceGroupsAPI.DeletePrivateResourceGroup(ctx, id).Force(false).Execute()
	status := privateResourceGroupResponseStatus(httpResp)
	closePrivateResourceGroupResponse(httpResp)
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return status, nil
	}
	if err == nil {
		err = fmt.Errorf("unexpected HTTP status %d", status)
	}
	return status, err
}

func (r *privateResourceGroupResource) readPrivateResourceGroupAfterMutation(ctx context.Context, id int64) (*privateapps.PrivateResourceGroupResponse, error) {
	var lastErr error
	for attempt := 1; attempt <= privateResourceGroupReadAttempts; attempt++ {
		group, status, err := r.getPrivateResourceGroup(ctx, id)
		if err == nil {
			return group, nil
		}
		lastErr = fmt.Errorf("read private resource group %d failed (HTTP %d): %w", id, status, err)
		if status != http.StatusNotFound || attempt == privateResourceGroupReadAttempts {
			break
		}

		timer := time.NewTimer(privateResourceGroupReadDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func privateResourceGroupResponseStatus(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func closePrivateResourceGroupResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func privateResourceGroupErrorDetail(action string, id int64, status int, err error) string {
	resource := ""
	if id > 0 {
		resource = fmt.Sprintf(" %d", id)
	}
	if status > 0 {
		return fmt.Sprintf("Failed to %s%s (HTTP %d): %v", action, resource, status, err)
	}
	return fmt.Sprintf("Failed to %s%s: %v", action, resource, err)
}
