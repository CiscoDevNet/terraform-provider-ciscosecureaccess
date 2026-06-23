// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/resconn"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &connectorGroupResourceMappingsResource{}
	_ resource.ResourceWithConfigure = &connectorGroupResourceMappingsResource{}
)

func NewConnectorGroupResourceMappingsResource() resource.Resource {
	return &connectorGroupResourceMappingsResource{}
}

type connectorGroupResourceMappingsResource struct {
	client resconn.APIClient
}

type connectorGroupResourceMappingsModel struct {
	ConnectorGroupId types.Int64   `tfsdk:"connector_group_id"`
	ResourceIds      []types.Int64 `tfsdk:"resource_ids"`
}

func (r *connectorGroupResourceMappingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connector_group_resource_mappings"
}

func (r *connectorGroupResourceMappingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = *factory.GetResConnClient(ctx)
}

func (r *connectorGroupResourceMappingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the private resource ID mappings on a Resource Connector Group. Binds private resources to a connector group so that ACA connectors can reach them.",
		Attributes: map[string]schema.Attribute{
			"connector_group_id": schema.Int64Attribute{
				Description: "ID of the Resource Connector Group.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"resource_ids": schema.ListAttribute{
				Description: "List of private resource IDs to bind to this connector group.",
				Required:    true,
				ElementType: types.Int64Type,
			},
		},
	}
}

func (r *connectorGroupResourceMappingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan connectorGroupResourceMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyResourceIds(ctx, plan.ConnectorGroupId.ValueInt64(), plan.ResourceIds); err != nil {
		resp.Diagnostics.AddError("Error creating connector group resource mappings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *connectorGroupResourceMappingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state connectorGroupResourceMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupId := state.ConnectorGroupId.ValueInt64()
	group, httpResp, err := r.client.ConnectorGroupsAPI.GetConnectorGroup(ctx, groupId).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Connector group not found, removing from state", map[string]interface{}{
				"connector_group_id": groupId,
			})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading connector group", fmt.Sprintf("Could not read connector group %d: %s", groupId, err.Error()))
		return
	}

	ids := make([]types.Int64, len(group.GetResourceIds()))
	for i, id := range group.GetResourceIds() {
		ids[i] = types.Int64Value(id)
	}
	state.ResourceIds = ids

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *connectorGroupResourceMappingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan connectorGroupResourceMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyResourceIds(ctx, plan.ConnectorGroupId.ValueInt64(), plan.ResourceIds); err != nil {
		resp.Diagnostics.AddError("Error updating connector group resource mappings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *connectorGroupResourceMappingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state connectorGroupResourceMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyResourceIds(ctx, state.ConnectorGroupId.ValueInt64(), nil); err != nil {
		resp.Diagnostics.AddError("Error removing connector group resource mappings", err.Error())
	}
}

func (r *connectorGroupResourceMappingsResource) applyResourceIds(ctx context.Context, groupId int64, desired []types.Int64) error {
	ids := make([]int64, 0, len(desired))
	for _, d := range desired {
		if !d.IsNull() && !d.IsUnknown() {
			ids = append(ids, d.ValueInt64())
		}
	}

	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("marshalling resource IDs: %w", err)
	}

	tflog.Debug(ctx, "Patching connector group resourceIds", map[string]interface{}{
		"connector_group_id": groupId,
		"resource_ids":       string(idsJSON),
	})

	op := resconn.REPLACE
	patchReq := []resconn.ConnectorGroupPatchReqInner{
		*resconn.NewConnectorGroupPatchReqInner(op, "/resourceIds", string(idsJSON)),
	}

	result, httpResp, err := r.client.ConnectorGroupsAPI.PatchConnectorGroup(ctx, groupId).
		ConnectorGroupPatchReqInner(patchReq).
		Execute()
	if err != nil {
		var detail string
		if httpResp != nil && httpResp.Body != nil {
			defer httpResp.Body.Close()
			detail = " (HTTP " + strconv.Itoa(httpResp.StatusCode) + ")"
		}
		return fmt.Errorf("patching connector group %d%s: %w", groupId, detail, err)
	}

	tflog.Debug(ctx, "Successfully patched connector group resourceIds", map[string]interface{}{
		"connector_group_id":  groupId,
		"result_resource_ids": result.GetResourceIds(),
	})

	return nil
}
