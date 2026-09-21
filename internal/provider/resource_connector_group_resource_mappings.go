// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/resconn"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = (*connectorGroupResourceMappingsResource)(nil)
	_ resource.ResourceWithConfigure = (*connectorGroupResourceMappingsResource)(nil)
)

type connectorGroupResourceMappingsResource struct {
	client resconn.APIClient
}

type connectorGroupResourceMappingsResourceModel struct {
	ConnectorGroupID types.Int64 `tfsdk:"connector_group_id"`
	ResourceIDs      types.Set   `tfsdk:"resource_ids"`
}

func NewConnectorGroupResourceMappingsResource() resource.Resource {
	return &connectorGroupResourceMappingsResource{}
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
		resp.Diagnostics.AddError(
			"Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData),
		)
		return
	}

	r.client = *factory.GetResConnClient(ctx)
}

func (r *connectorGroupResourceMappingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Additively manages private-resource mappings for an existing Resource Connector Group without removing mappings owned elsewhere.",
		Attributes: map[string]schema.Attribute{
			"connector_group_id": schema.Int64Attribute{
				Description: "ID of the existing Resource Connector Group.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"resource_ids": schema.SetAttribute{
				Description: "IDs of private resources to map to the Resource Connector Group. Other existing mappings are preserved.",
				ElementType: types.Int64Type,
				Required:    true,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
		},
	}
}

func (r *connectorGroupResourceMappingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan connectorGroupResourceMappingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.getConnectorGroup(ctx, plan.ConnectorGroupID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading Resource Connector Group", err.Error())
		return
	}

	managedIDs := resourceIDsFromSet(ctx, plan.ResourceIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.patchResourceIDs(ctx, plan.ConnectorGroupID.ValueInt64(), unionResourceIDs(group.GetResourceIds(), managedIDs)); err != nil {
		resp.Diagnostics.AddError("Error mapping private resources to Resource Connector Group", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *connectorGroupResourceMappingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state connectorGroupResourceMappingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.getConnectorGroup(ctx, state.ConnectorGroupID.ValueInt64())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading Resource Connector Group", err.Error())
		return
	}

	managedIDs := resourceIDsFromSet(ctx, state.ResourceIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	presentIDs := intersectResourceIDs(managedIDs, group.GetResourceIds())
	resourceIDs, diags := types.SetValueFrom(ctx, types.Int64Type, presentIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ResourceIDs = resourceIDs

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *connectorGroupResourceMappingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan connectorGroupResourceMappingsResourceModel
	var state connectorGroupResourceMappingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.getConnectorGroup(ctx, plan.ConnectorGroupID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading Resource Connector Group", err.Error())
		return
	}

	oldManagedIDs := resourceIDsFromSet(ctx, state.ResourceIDs, &resp.Diagnostics)
	newManagedIDs := resourceIDsFromSet(ctx, plan.ResourceIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceIDs := unionResourceIDs(subtractResourceIDs(group.GetResourceIds(), oldManagedIDs), newManagedIDs)
	if err := r.patchResourceIDs(ctx, plan.ConnectorGroupID.ValueInt64(), resourceIDs); err != nil {
		resp.Diagnostics.AddError("Error updating private-resource mappings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *connectorGroupResourceMappingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state connectorGroupResourceMappingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.getConnectorGroup(ctx, state.ConnectorGroupID.ValueInt64())
	if err != nil {
		if isNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Error reading Resource Connector Group", err.Error())
		return
	}

	managedIDs := resourceIDsFromSet(ctx, state.ResourceIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.patchResourceIDs(ctx, state.ConnectorGroupID.ValueInt64(), subtractResourceIDs(group.GetResourceIds(), managedIDs)); err != nil {
		resp.Diagnostics.AddError("Error removing private-resource mappings", err.Error())
	}
}

func (r *connectorGroupResourceMappingsResource) getConnectorGroup(ctx context.Context, groupID int64) (*resconn.ConnectorGroupResponse, error) {
	group, httpResp, err := r.client.ConnectorGroupsAPI.GetConnectorGroup(ctx, groupID).Execute()
	if httpResp != nil {
		httpResp.Body.Close()
	}
	if err != nil {
		if httpResp != nil {
			return nil, &connectorGroupHTTPError{statusCode: httpResp.StatusCode, operation: "get", groupID: groupID, err: err}
		}
		return nil, fmt.Errorf("could not get Resource Connector Group %d: %w", groupID, err)
	}
	if group == nil {
		return nil, fmt.Errorf("received an empty response for Resource Connector Group %d", groupID)
	}
	return group, nil
}

func (r *connectorGroupResourceMappingsResource) patchResourceIDs(ctx context.Context, groupID int64, resourceIDs []int64) error {
	value := formatResourceIDs(resourceIDs)
	patch := *resconn.NewConnectorGroupPatchReqInner(resconn.REPLACE, "/resourceIds", value)
	_, httpResp, patchErr := r.client.ConnectorGroupsAPI.PatchConnectorGroup(ctx, groupID).
		ConnectorGroupPatchReqInner([]resconn.ConnectorGroupPatchReqInner{patch}).
		Execute()
	if httpResp != nil {
		httpResp.Body.Close()
	}

	verifyErr := retry.Do(
		func() error {
			group, err := r.getConnectorGroup(ctx, groupID)
			if err != nil {
				return err
			}
			if !sameResourceIDs(group.GetResourceIds(), resourceIDs) {
				return fmt.Errorf("Resource Connector Group %d has resource IDs %v; expected %v", groupID, group.GetResourceIds(), resourceIDs)
			}
			return nil
		},
		retry.Attempts(3),
		retry.Delay(2*time.Second),
		retry.Context(ctx),
	)
	if verifyErr != nil {
		if patchErr != nil {
			if httpResp != nil {
				return &connectorGroupHTTPError{statusCode: httpResp.StatusCode, operation: "patch", groupID: groupID, err: patchErr}
			}
			return fmt.Errorf("could not patch Resource Connector Group %d: %w", groupID, patchErr)
		}
		return fmt.Errorf("could not verify private-resource mappings for Resource Connector Group %d: %w", groupID, verifyErr)
	}
	if patchErr != nil {
		tflog.Warn(ctx, "Resource Connector Group patch returned an error but the requested mappings were verified", map[string]interface{}{
			"connector_group_id": groupID,
			"error":              patchErr.Error(),
		})
	}

	tflog.Info(ctx, "Updated Resource Connector Group private-resource mappings", map[string]interface{}{
		"connector_group_id": groupID,
		"resource_ids":       resourceIDs,
	})
	return nil
}

type connectorGroupHTTPError struct {
	statusCode int
	operation  string
	groupID    int64
	err        error
}

func (e *connectorGroupHTTPError) Error() string {
	return fmt.Sprintf("could not %s Resource Connector Group %d (HTTP %d): %v", e.operation, e.groupID, e.statusCode, e.err)
}

func (e *connectorGroupHTTPError) Unwrap() error {
	return e.err
}

func isNotFound(err error) bool {
	httpErr, ok := err.(*connectorGroupHTTPError)
	return ok && httpErr.statusCode == http.StatusNotFound
}

func resourceIDsFromSet(ctx context.Context, values types.Set, diagnostics *diag.Diagnostics) []int64 {
	var ids []int64
	diagnostics.Append(values.ElementsAs(ctx, &ids, false)...)
	return ids
}

func unionResourceIDs(left, right []int64) []int64 {
	ids := make(map[int64]struct{}, len(left)+len(right))
	for _, id := range append(append([]int64{}, left...), right...) {
		ids[id] = struct{}{}
	}
	return sortedResourceIDs(ids)
}

func intersectResourceIDs(left, right []int64) []int64 {
	rightSet := make(map[int64]struct{}, len(right))
	for _, id := range right {
		rightSet[id] = struct{}{}
	}

	ids := make(map[int64]struct{})
	for _, id := range left {
		if _, ok := rightSet[id]; ok {
			ids[id] = struct{}{}
		}
	}
	return sortedResourceIDs(ids)
}

func subtractResourceIDs(left, right []int64) []int64 {
	remove := make(map[int64]struct{}, len(right))
	for _, id := range right {
		remove[id] = struct{}{}
	}

	ids := make(map[int64]struct{})
	for _, id := range left {
		if _, ok := remove[id]; !ok {
			ids[id] = struct{}{}
		}
	}
	return sortedResourceIDs(ids)
}

func sortedResourceIDs(ids map[int64]struct{}) []int64 {
	result := make([]int64, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func formatResourceIDs(ids []int64) string {
	formatted := make([]string, 0, len(ids))
	for _, id := range ids {
		formatted = append(formatted, strconv.FormatInt(id, 10))
	}
	return strings.Join(formatted, ",")
}

func sameResourceIDs(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := make(map[int64]struct{}, len(left))
	for _, id := range left {
		leftSet[id] = struct{}{}
	}
	if len(leftSet) != len(left) {
		return false
	}
	rightSet := make(map[int64]struct{}, len(right))
	for _, id := range right {
		rightSet[id] = struct{}{}
	}
	if len(rightSet) != len(right) {
		return false
	}
	for id := range leftSet {
		if _, ok := rightSet[id]; !ok {
			return false
		}
	}
	return true
}
