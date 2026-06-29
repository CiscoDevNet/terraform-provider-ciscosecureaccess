// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &applicationListResource{}
	_ resource.ResourceWithConfigure   = &applicationListResource{}
	_ resource.ResourceWithImportState = &applicationListResource{}
)

const (
	applicationListReadAttempts = 5
	applicationListReadDelay    = 2 * time.Second
)

type applicationListResource struct {
	client       rules.APIClient
	readAttempts int
	readDelay    time.Duration
}

type applicationListResourceModel struct {
	ID                     types.Int64  `tfsdk:"id"`
	OrganizationID         types.Int64  `tfsdk:"organization_id"`
	Name                   types.String `tfsdk:"name"`
	ApplicationIDs         types.Set    `tfsdk:"application_ids"`
	ApplicationCategoryIDs types.Set    `tfsdk:"application_category_ids"`
	IsDefault              types.Bool   `tfsdk:"is_default"`
	CreatedAt              types.String `tfsdk:"created_at"`
	ModifiedAt             types.String `tfsdk:"modified_at"`
}

func NewApplicationListResource() resource.Resource {
	return &applicationListResource{
		readAttempts: applicationListReadAttempts,
		readDelay:    applicationListReadDelay,
	}
}

func (r *applicationListResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application_list"
}

func (r *applicationListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = *factory.GetRulesClient(ctx)
}

func (r *applicationListResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptyInt64Set := types.SetValueMust(types.Int64Type, []attr.Value{})
	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access application list.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of the application list.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"organization_id": schema.Int64Attribute{
				Description: "Organization ID returned by the application-list API, when available.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Application list display name. Names must be unique within the organization.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"application_ids": schema.SetAttribute{
				Description: "Application IDs included in the list.",
				Optional:    true,
				Computed:    true,
				ElementType: types.Int64Type,
				Default:     setdefault.StaticValue(emptyInt64Set),
				Validators: []validator.Set{
					setvalidator.ValueInt64sAre(int64validator.AtLeast(1)),
				},
			},
			"application_category_ids": schema.SetAttribute{
				Description: "Application category IDs included in the list.",
				Optional:    true,
				Computed:    true,
				ElementType: types.Int64Type,
				Default:     setdefault.StaticValue(emptyInt64Set),
				Validators: []validator.Set{
					setvalidator.ValueInt64sAre(int64validator.AtLeast(1)),
				},
			},
			"is_default": schema.BoolAttribute{
				Description: "Whether this is a Cisco-managed default list. Default lists cannot be changed by this resource.",
				Computed:    true,
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

func (r *applicationListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan applicationListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	matches, status, err := r.findApplicationListsByExactName(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Error checking application list name", applicationListErrorDetail("list application lists", 0, status, err))
		return
	}
	if len(matches) != 0 {
		resp.Diagnostics.AddError(
			"Application list name already exists",
			fmt.Sprintf("Found %d existing application list(s) with exact name %q. Import the intended list or choose a unique name.", len(matches), name),
		)
		return
	}

	payload, diags := expandApplicationListRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, httpResponse, createErr := r.client.ApplicationListsAPI.CreateApplicationList(ctx).ApplicationListRequest(payload).Execute()
	status = applicationListResponseStatus(httpResponse)
	responseID := applicationListIDFromCreateResponse(created, httpResponse)
	closeApplicationListResponse(httpResponse)
	if createErr != nil && !applicationListSuccessfulStatus(status) && status != 0 && status < http.StatusInternalServerError {
		resp.Diagnostics.AddError("Error creating application list", applicationListErrorDetail("create application list", 0, status, createErr))
		return
	}

	resolved, summary, err := r.resolveCreatedApplicationList(ctx, payload, responseID)
	if err != nil {
		detail := err.Error()
		if createErr != nil {
			detail = fmt.Sprintf("Create returned %v; reconciliation failed: %s", createErr, detail)
		}
		resp.Diagnostics.AddError("Unable to resolve created application list", detail)
		return
	}

	plan.ID = types.Int64Value(summary.GetApplicationListId())
	plan.OrganizationID = applicationListOrganizationID(summary.AdditionalProperties)
	plan.IsDefault = types.BoolValue(false)
	plan.CreatedAt = types.StringNull()
	plan.ModifiedAt = types.StringNull()
	resp.Diagnostics.Append(flattenApplicationListResponse(ctx, resolved, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created application list", map[string]interface{}{"application_list_id": plan.ID.ValueInt64()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *applicationListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state applicationListResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	applicationList, status, err := r.getApplicationList(ctx, state.ID.ValueInt64())
	if err != nil {
		if status == http.StatusNotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading application list", applicationListErrorDetail("read application list", state.ID.ValueInt64(), status, err))
		return
	}

	resp.Diagnostics.Append(flattenApplicationListResponse(ctx, applicationList, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.OrganizationID.IsNull() || state.OrganizationID.IsUnknown() {
		summary, summaryStatus, summaryErr := r.findApplicationListByID(ctx, state.ID.ValueInt64())
		if summaryErr != nil {
			resp.Diagnostics.AddError("Error reading application-list organization", applicationListErrorDetail("list application lists", state.ID.ValueInt64(), summaryStatus, summaryErr))
			return
		}
		state.OrganizationID = applicationListOrganizationID(summary.AdditionalProperties)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *applicationListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state applicationListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.IsDefault.ValueBool() {
		resp.Diagnostics.AddError("Cannot update default application list", "Cisco-managed default application lists cannot be updated by this resource.")
		return
	}

	plan.ID = state.ID
	plan.OrganizationID = state.OrganizationID
	matches, status, err := r.findApplicationListsByExactName(ctx, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error checking application list name", applicationListErrorDetail("list application lists", plan.ID.ValueInt64(), status, err))
		return
	}
	for _, match := range matches {
		if match.ApplicationListId == nil || match.GetApplicationListId() != plan.ID.ValueInt64() {
			resp.Diagnostics.AddError("Application list name already exists", fmt.Sprintf("Another application list already uses exact name %q.", plan.Name.ValueString()))
			return
		}
	}

	payload, diags := expandApplicationListRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, httpResponse, err := r.client.ApplicationListsAPI.PutApplicationList(ctx, plan.ID.ValueInt64()).ApplicationListRequest(payload).Execute()
	status = applicationListResponseStatus(httpResponse)
	closeApplicationListResponse(httpResponse)
	if err != nil && !applicationListSuccessfulStatus(status) {
		resp.Diagnostics.AddError("Error updating application list", applicationListErrorDetail("update application list", plan.ID.ValueInt64(), status, err))
		return
	}

	refreshed, err := r.readApplicationListAfterMutation(ctx, plan.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Error reading application list after update", err.Error())
		return
	}
	plan.CreatedAt = state.CreatedAt
	plan.ModifiedAt = state.ModifiedAt
	resp.Diagnostics.Append(flattenApplicationListResponse(ctx, refreshed, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated application list", map[string]interface{}{"application_list_id": plan.ID.ValueInt64()})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *applicationListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state applicationListResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.IsDefault.ValueBool() {
		resp.Diagnostics.AddError("Cannot delete default application list", "Cisco-managed default application lists cannot be deleted by this resource.")
		return
	}

	_, httpResponse, err := r.client.ApplicationListsAPI.DeleteApplicationList(ctx, state.ID.ValueInt64()).Execute()
	status := applicationListResponseStatus(httpResponse)
	closeApplicationListResponse(httpResponse)
	if err == nil || status == http.StatusNotFound || applicationListSuccessfulStatus(status) {
		return
	}

	detail := applicationListErrorDetail("delete application list", state.ID.ValueInt64(), status, err)
	if status == http.StatusBadRequest || status == http.StatusConflict {
		detail += " Remove access-policy references before deleting the list; the provider will not cascade deletion."
	}
	resp.Diagnostics.AddError("Error deleting application list", detail)
}

func (r *applicationListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := parseApplicationListID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func expandApplicationListRequest(ctx context.Context, model *applicationListResourceModel) (rules.ApplicationListRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	applicationIDs := make([]int64, 0)
	applicationCategoryIDs := make([]int64, 0)
	if !model.ApplicationIDs.IsNull() && !model.ApplicationIDs.IsUnknown() {
		diags.Append(model.ApplicationIDs.ElementsAs(ctx, &applicationIDs, false)...)
	}
	if !model.ApplicationCategoryIDs.IsNull() && !model.ApplicationCategoryIDs.IsUnknown() {
		diags.Append(model.ApplicationCategoryIDs.ElementsAs(ctx, &applicationCategoryIDs, false)...)
	}
	if diags.HasError() {
		return rules.ApplicationListRequest{}, diags
	}

	sort.Slice(applicationIDs, func(i, j int) bool { return applicationIDs[i] < applicationIDs[j] })
	sort.Slice(applicationCategoryIDs, func(i, j int) bool { return applicationCategoryIDs[i] < applicationCategoryIDs[j] })
	payload := rules.NewApplicationListRequest(model.Name.ValueString(), false, applicationIDs)
	payload.SetApplicationCategoryIds(applicationCategoryIDs)
	return *payload, diags
}

func flattenApplicationListResponse(ctx context.Context, applicationList *rules.ApplicationList, model *applicationListResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if applicationList == nil {
		diags.AddError("Invalid application list response", "The API returned an empty application list response.")
		return diags
	}
	if model.ID.IsNull() || model.ID.IsUnknown() || model.ID.ValueInt64() <= 0 {
		diags.AddError("Invalid application list state", "Application list state does not include a valid ID.")
	}
	if applicationList.ApplicationListName == nil {
		diags.AddError("Invalid application list response", "The API response did not include applicationListName.")
	} else {
		model.Name = types.StringValue(applicationList.GetApplicationListName())
	}
	if applicationList.IsDefault == nil {
		diags.AddError("Invalid application list response", "The API response did not include isDefault.")
	} else {
		model.IsDefault = types.BoolValue(applicationList.GetIsDefault())
	}

	applicationIDs := applicationList.ApplicationIds
	if applicationIDs == nil {
		applicationIDs = []int64{}
	}
	applicationCategoryIDs := applicationList.ApplicationCategoryIds
	if applicationCategoryIDs == nil {
		applicationCategoryIDs = []int64{}
	}
	var setDiags diag.Diagnostics
	model.ApplicationIDs, setDiags = types.SetValueFrom(ctx, types.Int64Type, applicationIDs)
	diags.Append(setDiags...)
	model.ApplicationCategoryIDs, setDiags = types.SetValueFrom(ctx, types.Int64Type, applicationCategoryIDs)
	diags.Append(setDiags...)

	if organizationID := applicationListOrganizationID(applicationList.AdditionalProperties); !organizationID.IsNull() {
		model.OrganizationID = organizationID
	} else if model.OrganizationID.IsUnknown() {
		model.OrganizationID = types.Int64Null()
	}
	if applicationList.CreatedAt != nil {
		model.CreatedAt = types.StringValue(applicationList.GetCreatedAt())
	} else if model.CreatedAt.IsUnknown() {
		model.CreatedAt = types.StringNull()
	}
	if applicationList.ModifiedAt != nil {
		model.ModifiedAt = types.StringValue(applicationList.GetModifiedAt())
	} else {
		model.ModifiedAt = types.StringNull()
	}

	return diags
}

func (r *applicationListResource) findApplicationListsByExactName(ctx context.Context, name string) ([]rules.ApplicationListsResultInner, int, error) {
	applicationLists, status, err := r.listApplicationLists(ctx)
	if err != nil {
		return nil, status, err
	}

	matches := make([]rules.ApplicationListsResultInner, 0, 1)
	for _, applicationList := range applicationLists.Results {
		if applicationList.ApplicationListName != nil && applicationList.GetApplicationListName() == name {
			matches = append(matches, applicationList)
		}
	}
	return matches, status, nil
}

func (r *applicationListResource) findApplicationListByID(ctx context.Context, id int64) (rules.ApplicationListsResultInner, int, error) {
	applicationLists, status, err := r.listApplicationLists(ctx)
	if err != nil {
		return rules.ApplicationListsResultInner{}, status, err
	}
	for _, applicationList := range applicationLists.Results {
		if applicationList.ApplicationListId != nil && applicationList.GetApplicationListId() == id {
			return applicationList, status, nil
		}
	}
	return rules.ApplicationListsResultInner{}, status, fmt.Errorf("application list %d was not present in the collection", id)
}

func (r *applicationListResource) listApplicationLists(ctx context.Context) (*rules.ApplicationLists, int, error) {
	applicationLists, httpResponse, err := r.client.ApplicationListsAPI.GetApplicationLists(ctx).Execute()
	status := applicationListResponseStatus(httpResponse)
	closeApplicationListResponse(httpResponse)
	if err != nil {
		return nil, status, err
	}
	if applicationLists == nil {
		return nil, status, fmt.Errorf("the API returned an empty application-list collection")
	}
	return applicationLists, status, nil
}

func (r *applicationListResource) getApplicationList(ctx context.Context, id int64) (*rules.ApplicationList, int, error) {
	applicationList, httpResponse, err := r.client.ApplicationListsAPI.GetApplicationList(ctx, id).Execute()
	status := applicationListResponseStatus(httpResponse)
	closeApplicationListResponse(httpResponse)
	return applicationList, status, err
}

func (r *applicationListResource) resolveCreatedApplicationList(ctx context.Context, payload rules.ApplicationListRequest, responseID int64) (*rules.ApplicationList, rules.ApplicationListsResultInner, error) {
	var lastErr error
	for attempt := 1; attempt <= r.attempts(); attempt++ {
		matches, status, err := r.findApplicationListsByExactName(ctx, payload.ApplicationListName)
		if err != nil {
			lastErr = fmt.Errorf("list application lists failed (HTTP %d): %w", status, err)
		} else if len(matches) > 1 {
			return nil, rules.ApplicationListsResultInner{}, fmt.Errorf("found %d application lists with exact name %q after create; refusing ambiguous adoption", len(matches), payload.ApplicationListName)
		} else if len(matches) == 1 {
			summary := matches[0]
			if summary.ApplicationListId == nil || summary.GetApplicationListId() <= 0 {
				return nil, rules.ApplicationListsResultInner{}, fmt.Errorf("the created application-list summary did not include a valid ID")
			}
			if responseID > 0 && responseID != summary.GetApplicationListId() {
				return nil, rules.ApplicationListsResultInner{}, fmt.Errorf("create response ID %d does not match exact-name result ID %d", responseID, summary.GetApplicationListId())
			}

			applicationList, getStatus, getErr := r.getApplicationList(ctx, summary.GetApplicationListId())
			if getErr == nil && applicationListMatchesRequest(applicationList, payload) {
				return applicationList, summary, nil
			}
			if getErr != nil {
				lastErr = fmt.Errorf("read candidate application list %d failed (HTTP %d): %w", summary.GetApplicationListId(), getStatus, getErr)
			} else {
				lastErr = fmt.Errorf("application list %d does not yet match the create request", summary.GetApplicationListId())
			}
		} else {
			lastErr = fmt.Errorf("application list %q is not yet visible", payload.ApplicationListName)
		}

		if attempt < r.attempts() {
			if err := waitForApplicationListRetry(ctx, r.readDelay); err != nil {
				return nil, rules.ApplicationListsResultInner{}, err
			}
		}
	}
	return nil, rules.ApplicationListsResultInner{}, lastErr
}

func (r *applicationListResource) readApplicationListAfterMutation(ctx context.Context, id int64) (*rules.ApplicationList, error) {
	var lastErr error
	for attempt := 1; attempt <= r.attempts(); attempt++ {
		applicationList, status, err := r.getApplicationList(ctx, id)
		if err == nil {
			return applicationList, nil
		}
		lastErr = fmt.Errorf("read application list %d failed (HTTP %d): %w", id, status, err)
		if status != http.StatusNotFound || attempt == r.attempts() {
			break
		}
		if err := waitForApplicationListRetry(ctx, r.readDelay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (r *applicationListResource) attempts() int {
	if r.readAttempts <= 0 {
		return 1
	}
	return r.readAttempts
}

func waitForApplicationListRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func applicationListMatchesRequest(applicationList *rules.ApplicationList, payload rules.ApplicationListRequest) bool {
	if applicationList == nil || applicationList.ApplicationListName == nil || applicationList.GetApplicationListName() != payload.ApplicationListName {
		return false
	}
	return equalInt64Sets(applicationList.ApplicationIds, payload.ApplicationIds) &&
		equalInt64Sets(applicationList.ApplicationCategoryIds, payload.ApplicationCategoryIds)
}

func equalInt64Sets(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]int64(nil), left...)
	rightCopy := append([]int64(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func applicationListIDFromCreateResponse(applicationList *rules.ApplicationList, response *http.Response) int64 {
	if applicationList != nil {
		if id, ok := applicationListAdditionalInt64(applicationList.AdditionalProperties, "applicationListId"); ok && id > 0 {
			return id
		}
	}
	if response == nil {
		return 0
	}
	location := strings.TrimSuffix(response.Header.Get("Location"), "/")
	if location == "" {
		return 0
	}
	segment := location[strings.LastIndex(location, "/")+1:]
	id, err := strconv.ParseInt(segment, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

func applicationListOrganizationID(properties map[string]interface{}) types.Int64 {
	organizationID, ok := applicationListAdditionalInt64(properties, "organizationId")
	if !ok || organizationID <= 0 {
		return types.Int64Null()
	}
	return types.Int64Value(organizationID)
}

func applicationListAdditionalInt64(properties map[string]interface{}, key string) (int64, bool) {
	if properties == nil {
		return 0, false
	}
	value, ok := properties[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		if typed != float64(int64(typed)) {
			return 0, false
		}
		return int64(typed), true
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	case string:
		number, err := strconv.ParseInt(typed, 10, 64)
		return number, err == nil
	default:
		return 0, false
	}
}

func parseApplicationListID(value string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("expected a positive numeric application list ID, got %q", value)
	}
	return id, nil
}

func applicationListResponseStatus(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func applicationListSuccessfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func closeApplicationListResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func applicationListErrorDetail(action string, id int64, status int, err error) string {
	resourceID := ""
	if id > 0 {
		resourceID = fmt.Sprintf(" %d", id)
	}
	if status > 0 {
		return fmt.Sprintf("Failed to %s%s (HTTP %d): %v", action, resourceID, status, err)
	}
	return fmt.Sprintf("Failed to %s%s: %v", action, resourceID, err)
}
