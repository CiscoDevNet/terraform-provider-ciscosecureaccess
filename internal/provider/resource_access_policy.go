// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
)

const (
	DIRECTORY_USERS_TYPE_ID int64  = 7
	DIRECTORY_USERS         string = "directory_users"
	PRIVATE_APPS_SCHEMA     string = "private_apps"
	PRIVATE_APPS_TYPE       string = "apps"
	NETWORKS                string = "networks"
	NETWORKS_TYPE_ID        int64  = 40
	PUBLIC_INTERNET_SCHEMA  string = "internet"
	PUBLIC_INTERNET_TYPE_ID int64  = 15
)

var (
	_ resource.Resource                   = &accessPolicyResource{}
	_ resource.ResourceWithConfigure      = &accessPolicyResource{}
	_ resource.ResourceWithImportState    = &accessPolicyResource{}
	_ resource.ResourceWithValidateConfig = &accessPolicyResource{}
)

func NewAccessPolicyResource() resource.Resource {
	return &accessPolicyResource{}
}

type accessPolicyResource struct {
	client              rules.APIClient
	createRetryDelay    time.Duration
	createRetryAttempts uint
}

type accessPolicyResourceModel struct {
	ID                          types.Int64  `tfsdk:"id"`
	Name                        types.String `tfsdk:"name"`
	Action                      types.String `tfsdk:"action"`
	Description                 types.String `tfsdk:"description"`
	Enabled                     types.Bool   `tfsdk:"enabled"`
	Priority                    types.Int64  `tfsdk:"priority"`
	SourceAll                   types.Bool   `tfsdk:"source_all"`
	SourceIds                   types.Set    `tfsdk:"source_ids"`
	SourceTypes                 types.Set    `tfsdk:"source_types"`
	SourceIdentityTypeIds       types.Set    `tfsdk:"source_identity_type_ids"`
	PrivateResourceIds          types.Set    `tfsdk:"private_resource_ids"`
	PrivateResourceGroupIds     types.Set    `tfsdk:"private_resource_group_ids"`
	DestinationListIds          types.Set    `tfsdk:"destination_list_ids"`
	ApplicationIds              types.Set    `tfsdk:"application_ids"`
	ApplicationListIds          types.Set    `tfsdk:"application_list_ids"`
	CategoryIds                 types.Set    `tfsdk:"category_ids"`
	ContentCategoryListIds      types.Set    `tfsdk:"content_category_list_ids"`
	InlineDestinations          types.Set    `tfsdk:"inline_destinations"`
	PrivateDestinationTypes     types.Set    `tfsdk:"private_destination_types"`
	PublicDestinationTypes      types.Set    `tfsdk:"public_destination_types"`
	LogLevel                    types.String `tfsdk:"log_level"`
	TrafficType                 types.String `tfsdk:"traffic_type"`
	AllowPasswordProtectedFiles types.Bool   `tfsdk:"allow_password_protected_files"`
	AdvancedApplicationIds      types.Set    `tfsdk:"advanced_application_ids"`
	ClientPostureProfileId      types.Int64  `tfsdk:"client_posture_profile_id"`
	WebProfileId                types.Int64  `tfsdk:"web_profile_id"`
	IpsProfileId                types.Int64  `tfsdk:"ips_profile_id"`
	PrivateSecurityProfileId    types.Int64  `tfsdk:"private_security_profile_id"`
	TenantControlProfileId      types.Int64  `tfsdk:"tenant_control_profile_id"`
}

type accessPolicyInlineDestinationModel struct {
	IPAddresses types.Set    `tfsdk:"ip_addresses"`
	Ports       types.Set    `tfsdk:"ports"`
	Protocol    types.String `tfsdk:"protocol"`
}

func (accessPolicyInlineDestinationModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ip_addresses": types.SetType{ElemType: types.StringType},
		"ports":        types.SetType{ElemType: types.StringType},
		"protocol":     types.StringType,
	}
}

func (accessPolicyResourceModel) TrafficTypes() []string {
	return []string{"PUBLIC_INTERNET", "PRIVATE_NETWORK"}
}

func (accessPolicyResourceModel) ValidSourceTypes() []string {
	return []string{DIRECTORY_USERS, NETWORKS}
}

func (accessPolicyResourceModel) ValidPrivateDestinationTypes() []string {
	return []string{PRIVATE_APPS_SCHEMA}
}

func (accessPolicyResourceModel) ValidPublicDestinationTypes() []string {
	return []string{PUBLIC_INTERNET_SCHEMA}
}

func (accessPolicyResourceModel) Actions() []string {
	return []string{"allow", "block", "warn"}
}

func (accessPolicyResourceModel) LogLevels() []string {
	return []string{"LOG_ALL", "LOG_SECURITY", "LOG_NONE"}
}

func (r *accessPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_policy"
}

func (r *accessPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type", fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = *factory.GetRulesClient(ctx)
}

func (r *accessPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Access policy rule for private and public traffic.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of the access policy.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the access policy.",
				Required:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action taken on matching traffic: allow, block, or warn.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("block"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.Actions()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the access policy.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the access policy is enabled.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"priority": schema.Int64Attribute{
				Description: "Policy evaluation priority.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"source_all": schema.BoolAttribute{
				Description: "Match all sources.",
				Optional:    true,
			},
			"source_ids": int64SetAttribute("Source identity IDs."),
			"source_identity_type_ids": schema.SetAttribute{
				Description: "Raw source identity type IDs. Use this for identity types not represented by source_types.",
				ElementType: types.Int64Type,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(path.MatchRoot("source_types")),
				},
			},
			"source_types": schema.SetAttribute{
				Description: "Friendly source type names.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidSourceTypes()...)),
					setvalidator.ConflictsWith(path.MatchRoot("source_identity_type_ids")),
				},
			},
			"private_resource_ids":       int64SetAttribute("Private resource IDs."),
			"private_resource_group_ids": int64SetAttribute("Private resource group IDs."),
			"destination_list_ids":       int64SetAttribute("Destination list IDs."),
			"application_ids":            int64SetAttribute("Application IDs."),
			"application_list_ids":       int64SetAttribute("Application list IDs."),
			"category_ids":               int64SetAttribute("Content category IDs."),
			"content_category_list_ids":  int64SetAttribute("Content category list IDs."),
			"inline_destinations": schema.SetNestedAttribute{
				Description: "Inline IP, port, and protocol destinations.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"ip_addresses": schema.SetAttribute{
							Description: "IP addresses or CIDR prefixes.",
							ElementType: types.StringType,
							Required:    true,
						},
						"ports": schema.SetAttribute{
							Description: "Ports or inclusive port ranges.",
							ElementType: types.StringType,
							Required:    true,
						},
						"protocol": schema.StringAttribute{
							Description: "Network protocol.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.OneOf("ANY", "ICMP", "TCP", "UDP"),
							},
						},
					},
				},
			},
			"private_destination_types": schema.SetAttribute{
				Description: "Friendly private destination types.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidPrivateDestinationTypes()...)),
				},
			},
			"public_destination_types": schema.SetAttribute{
				Description: "Friendly public destination types.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidPublicDestinationTypes()...)),
				},
			},
			"log_level": schema.StringAttribute{
				Description: "Logging level for matching traffic.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("LOG_ALL"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.LogLevels()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"traffic_type": schema.StringAttribute{
				Description: "Traffic scope: PRIVATE_NETWORK or PUBLIC_INTERNET.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("PRIVATE_NETWORK"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.TrafficTypes()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"allow_password_protected_files": schema.BoolAttribute{
				Description: "Allow password-protected files.",
				Optional:    true,
			},
			"advanced_application_ids":    int64SetAttribute("Advanced application IDs."),
			"client_posture_profile_id":   optionalInt64Attribute("Client-based posture profile ID."),
			"web_profile_id":              optionalInt64Attribute("Web security profile ID."),
			"ips_profile_id":              optionalInt64Attribute("IPS profile ID. Omit to use the service default IPS behavior."),
			"private_security_profile_id": optionalInt64Attribute("Private security profile ID."),
			"tenant_control_profile_id":   optionalInt64Attribute("Tenant control profile ID."),
		},
	}
}

func int64SetAttribute(description string) schema.SetAttribute {
	return schema.SetAttribute{Description: description, ElementType: types.Int64Type, Optional: true}
}

func optionalInt64Attribute(description string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: description,
		Optional:    true,
		PlanModifiers: []planmodifier.Int64{
			int64planmodifier.UseStateForUnknown(),
		},
	}
}

func (r *accessPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config accessPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !hasConfiguredSource(config) {
		resp.Diagnostics.AddAttributeError(path.Root("source_ids"), "Missing source condition", "Configure source_all, source_ids, source_types, or source_identity_type_ids.")
	}
	if !hasConfiguredDestination(config) {
		resp.Diagnostics.AddAttributeError(path.Root("private_resource_ids"), "Missing destination condition", "Configure at least one destination condition.")
	}
	if !config.SourceAll.IsNull() && !config.SourceAll.IsUnknown() && (setHasValues(config.SourceIds) || setHasValues(config.SourceTypes) || setHasValues(config.SourceIdentityTypeIds)) {
		resp.Diagnostics.AddAttributeError(path.Root("source_all"), "Conflicting source conditions", "source_all cannot be combined with source IDs or source types.")
	}

	if config.InlineDestinations.IsNull() || config.InlineDestinations.IsUnknown() {
		return
	}
	var destinations []accessPolicyInlineDestinationModel
	resp.Diagnostics.Append(config.InlineDestinations.ElementsAs(ctx, &destinations, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for i, destination := range destinations {
		var addresses, ports []string
		resp.Diagnostics.Append(destination.IPAddresses.ElementsAs(ctx, &addresses, false)...)
		resp.Diagnostics.Append(destination.Ports.ElementsAs(ctx, &ports, false)...)
		for _, address := range addresses {
			if net.ParseIP(address) == nil {
				if _, _, err := net.ParseCIDR(address); err != nil {
					resp.Diagnostics.AddAttributeError(path.Root("inline_destinations"), "Invalid inline destination address", fmt.Sprintf("Element %d contains %q, which is not an IP address or CIDR prefix.", i+1, address))
				}
			}
		}
		for _, port := range ports {
			if !validAccessPolicyPort(port) {
				resp.Diagnostics.AddAttributeError(path.Root("inline_destinations"), "Invalid inline destination port", fmt.Sprintf("Element %d contains %q; use a port from 0 to 65535 or an inclusive range such as 8000-8080.", i+1, port))
			}
		}
	}
}

func hasConfiguredSource(model accessPolicyResourceModel) bool {
	if model.SourceAll.IsUnknown() || model.SourceIds.IsUnknown() || model.SourceTypes.IsUnknown() || model.SourceIdentityTypeIds.IsUnknown() {
		return true
	}
	return !model.SourceAll.IsNull() || setHasValues(model.SourceIds) || setHasValues(model.SourceTypes) || setHasValues(model.SourceIdentityTypeIds)
}

func hasConfiguredDestination(model accessPolicyResourceModel) bool {
	sets := []types.Set{
		model.PrivateResourceIds, model.PrivateResourceGroupIds, model.DestinationListIds,
		model.ApplicationIds, model.ApplicationListIds, model.CategoryIds,
		model.ContentCategoryListIds, model.InlineDestinations,
		model.PrivateDestinationTypes, model.PublicDestinationTypes,
	}
	for _, set := range sets {
		if set.IsUnknown() || setHasValues(set) {
			return true
		}
	}
	return false
}

func setHasValues(value types.Set) bool {
	return !value.IsNull() && !value.IsUnknown() && len(value.Elements()) > 0
}

func validAccessPolicyPort(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	parsed := make([]int, len(parts))
	for i, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port < 0 || port > 65535 {
			return false
		}
		parsed[i] = port
	}
	return len(parsed) == 1 || parsed[0] <= parsed[1]
}

func (r *accessPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan accessPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, diags := formatCreateAccessPolicyRequest(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, _, err := r.createAccessPolicy(ctx, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating access policy", err.Error())
		return
	}
	if created == nil || created.GetRuleId() <= 0 {
		resp.Diagnostics.AddError("Invalid create response", "The API did not return a valid access policy ID.")
		return
	}

	plan.ID = types.Int64Value(created.GetRuleId())
	plan.Priority = types.Int64Value(created.GetRulePriority())
	readRule, httpRes, readErr := r.client.AccessRulesAPI.GetRule(ctx, created.GetRuleId()).Execute()
	if httpRes != nil {
		httpRes.Body.Close()
	}
	if readErr != nil {
		tflog.Warn(ctx, "Could not read access policy after create", map[string]interface{}{"id": created.GetRuleId(), "error": readErr.Error()})
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	resp.Diagnostics.Append(flattenAccessPolicyResponse(ctx, readRule, &plan)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *accessPolicyResource) createAccessPolicy(ctx context.Context, payload rules.AddRuleRequest) (*rules.Rule, int, error) {
	var created *rules.Rule
	status := 0
	delay := r.createRetryDelay
	if delay <= 0 {
		delay = 10 * time.Second
	}
	attempts := r.createRetryAttempts
	if attempts == 0 {
		attempts = 6
	}

	err := retry.Do(func() error {
		result, httpRes, apiErr := r.client.AccessRulesAPI.AddRule(ctx).AddRuleRequest(payload).Execute()
		status = 0
		if httpRes != nil {
			status = httpRes.StatusCode
		}
		if apiErr != nil {
			if httpRes == nil {
				return retry.Unrecoverable(apiErr)
			}
			bodyBytes, _ := io.ReadAll(httpRes.Body)
			httpRes.Body.Close()
			body := string(bodyBytes)
			if httpRes.StatusCode == http.StatusConflict || (httpRes.StatusCode == http.StatusBadRequest && strings.Contains(body, "invalid data passed. the ID's provided for")) {
				return fmt.Errorf("retryable HTTP %s: %s", httpRes.Status, body)
			}
			return retry.Unrecoverable(fmt.Errorf("HTTP %s: %s", httpRes.Status, body))
		}
		if httpRes != nil {
			httpRes.Body.Close()
		}
		created = result
		return nil
	}, retry.Delay(delay), retry.Attempts(attempts), retry.Context(ctx))
	return created, status, err
}

func (r *accessPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state accessPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, httpRes, err := r.client.AccessRulesAPI.GetRule(ctx, state.ID.ValueInt64()).Execute()
	status := 0
	if httpRes != nil {
		status = httpRes.StatusCode
		httpRes.Body.Close()
	}
	if err != nil {
		if status == http.StatusNotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading access policy", fmt.Sprintf("Cannot read access policy ID %d: %s", state.ID.ValueInt64(), err))
		return
	}

	resp.Diagnostics.Append(flattenAccessPolicyResponse(ctx, rule, &state)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *accessPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state accessPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if hasChanges(&plan, &state) {
		payload, diags := formatPutAccessPolicyRequest(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updated, httpRes, err := r.client.AccessRulesAPI.PutRule(ctx, plan.ID.ValueInt64()).PutRuleRequest(payload).Execute()
		if httpRes != nil {
			httpRes.Body.Close()
		}
		if err != nil {
			resp.Diagnostics.AddError("Error updating access policy", fmt.Sprintf("Could not update access policy ID %d: %v", plan.ID.ValueInt64(), err))
			return
		}
		if updateBytes, err := json.Marshal(updated); err == nil {
			tflog.Debug(ctx, "Updated access policy", map[string]interface{}{"id": plan.ID.ValueInt64(), "response": string(updateBytes)})
		}
	}

	rule, httpRes, err := r.client.AccessRulesAPI.GetRule(ctx, plan.ID.ValueInt64()).Execute()
	if httpRes != nil {
		httpRes.Body.Close()
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading access policy after update", fmt.Sprintf("Cannot read access policy ID %d: %s", plan.ID.ValueInt64(), err))
		return
	}
	resp.Diagnostics.Append(flattenAccessPolicyResponse(ctx, rule, &plan)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *accessPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state accessPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := retry.Do(func() error {
		httpRes, err := r.client.AccessRulesAPI.DeleteRule(ctx, state.ID.ValueInt64()).Execute()
		status := 0
		if httpRes != nil {
			status = httpRes.StatusCode
			httpRes.Body.Close()
		}
		if err == nil || status == http.StatusNotFound {
			return nil
		}
		if status == http.StatusConflict {
			if disableErr := r.disableAccessPolicyBeforeDelete(ctx, &state); disableErr != nil {
				tflog.Warn(ctx, "Best-effort disable before delete failed", map[string]interface{}{"id": state.ID.ValueInt64(), "error": disableErr.Error()})
			}
			return fmt.Errorf("conflict deleting access policy: HTTP %d", status)
		}
		return retry.Unrecoverable(fmt.Errorf("failed to delete access policy: %w", err))
	}, retry.Delay(10*time.Second), retry.Attempts(12), retry.Context(ctx))
	if err != nil {
		resp.Diagnostics.AddError("Error deleting access policy", fmt.Sprintf("Could not delete access policy ID %d: %s", state.ID.ValueInt64(), err))
	}
}

func (r *accessPolicyResource) disableAccessPolicyBeforeDelete(ctx context.Context, state *accessPolicyResourceModel) error {
	disabled := *state
	disabled.Enabled = types.BoolValue(false)
	payload, diags := formatPutAccessPolicyRequest(ctx, &disabled)
	if diags.HasError() {
		return fmt.Errorf("format disable request: %v", diags)
	}
	return retry.Do(func() error {
		_, httpRes, err := r.client.AccessRulesAPI.PutRule(ctx, state.ID.ValueInt64()).PutRuleRequest(payload).Execute()
		status := 0
		if httpRes != nil {
			status = httpRes.StatusCode
			httpRes.Body.Close()
		}
		if err == nil || status == http.StatusNotFound {
			return nil
		}
		if status == http.StatusConflict {
			return fmt.Errorf("conflict disabling access policy: HTTP %d", status)
		}
		return retry.Unrecoverable(fmt.Errorf("failed to disable access policy: %w", err))
	}, retry.Delay(10*time.Second), retry.Attempts(6), retry.Context(ctx))
}

func (r *accessPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := parseAccessPolicyID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func parseAccessPolicyID(value string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("access policy import ID must be a positive integer, got %q", value)
	}
	return id, nil
}

// atoi64 is retained for older acceptance-test helpers that build numeric IDs.
func atoi64(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func hasChanges(plan, state *accessPolicyResourceModel) bool {
	return !plan.ID.Equal(state.ID) ||
		!plan.Name.Equal(state.Name) ||
		!plan.Action.Equal(state.Action) ||
		!plan.Description.Equal(state.Description) ||
		!plan.Enabled.Equal(state.Enabled) ||
		!plan.Priority.Equal(state.Priority) ||
		!plan.SourceAll.Equal(state.SourceAll) ||
		!plan.SourceIds.Equal(state.SourceIds) ||
		!plan.SourceTypes.Equal(state.SourceTypes) ||
		!plan.SourceIdentityTypeIds.Equal(state.SourceIdentityTypeIds) ||
		!plan.PrivateResourceIds.Equal(state.PrivateResourceIds) ||
		!plan.PrivateResourceGroupIds.Equal(state.PrivateResourceGroupIds) ||
		!plan.DestinationListIds.Equal(state.DestinationListIds) ||
		!plan.ApplicationIds.Equal(state.ApplicationIds) ||
		!plan.ApplicationListIds.Equal(state.ApplicationListIds) ||
		!plan.CategoryIds.Equal(state.CategoryIds) ||
		!plan.ContentCategoryListIds.Equal(state.ContentCategoryListIds) ||
		!plan.InlineDestinations.Equal(state.InlineDestinations) ||
		!plan.PrivateDestinationTypes.Equal(state.PrivateDestinationTypes) ||
		!plan.PublicDestinationTypes.Equal(state.PublicDestinationTypes) ||
		!plan.LogLevel.Equal(state.LogLevel) ||
		!plan.TrafficType.Equal(state.TrafficType) ||
		!plan.AllowPasswordProtectedFiles.Equal(state.AllowPasswordProtectedFiles) ||
		!plan.AdvancedApplicationIds.Equal(state.AdvancedApplicationIds) ||
		!plan.ClientPostureProfileId.Equal(state.ClientPostureProfileId) ||
		!plan.WebProfileId.Equal(state.WebProfileId) ||
		!plan.IpsProfileId.Equal(state.IpsProfileId) ||
		!plan.PrivateSecurityProfileId.Equal(state.PrivateSecurityProfileId) ||
		!plan.TenantControlProfileId.Equal(state.TenantControlProfileId)
}
