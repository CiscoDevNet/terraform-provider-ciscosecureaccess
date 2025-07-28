// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &accessPolicyResource{}
	_ resource.ResourceWithConfigure = &accessPolicyResource{}
)

// NewAccessPolicyResource is a helper function to simplify the provider implementation.
func NewAccessPolicyResource() resource.Resource {
	return &accessPolicyResource{}
}

// accessPolicyResource is the resource implementation.
type accessPolicyResource struct {
	client rules.APIClient
}

// accessPolicyResourceModel maps the data schema data.
type accessPolicyResourceModel struct {
	ID                      types.Int64  `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	Action                  types.String `tfsdk:"action"`
	PrivateResourceIds      types.Set    `tfsdk:"private_resource_ids"`
	DestinationListIds      types.Set    `tfsdk:"destination_list_ids"`
	Description             types.String `tfsdk:"description"`
	Enabled                 types.Bool   `tfsdk:"enabled"`
	LogLevel                types.String `tfsdk:"log_level"`
	Priority                types.Int64  `tfsdk:"priority"`
	ClientPostureProfileId  types.Int64  `tfsdk:"client_posture_profile_id"`
	SourceIds               types.Set    `tfsdk:"source_ids"`
	SourceTypes             types.Set    `tfsdk:"source_types"`
	PrivateDestinationTypes types.Set    `tfsdk:"private_destination_types"`
	PublicDestinationTypes  types.Set    `tfsdk:"public_destination_types"`
	TrafficType             types.String `tfsdk:"traffic_type"`
}

func (m accessPolicyResourceModel) TrafficTypes() []string {
	return []string{"PUBLIC_INTERNET", "PRIVATE_NETWORK"}
}

func (m accessPolicyResourceModel) ValidSourceTypes() []string {
	return []string{DIRECTORY_USERS, NETWORKS}
}

func (m accessPolicyResourceModel) ValidPrivateDestinationTypes() []string {
	return []string{PRIVATE_APPS_SCHEMA}
}

func (m accessPolicyResourceModel) ValidPublicDestinationTypes() []string {
	return []string{PUBLIC_INTERNET_SCHEMA}
}

func (m accessPolicyResourceModel) Actions() []string {
	return []string{"allow", "block"}
}

func (m accessPolicyResourceModel) LogLevels() []string {
	return []string{"LOG_ALL", "LOG_SECURITY", "LOG_NONE"}
}

// Metadata returns the resource type name.
func (r *accessPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_policy"
}

// Configure adds the provider configured client to the resource.
func (r *accessPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetRulesClient(ctx)
}

// Schema defines the schema for the resource.
func (r *accessPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// TODO: Implement Internet rules
		Description: "Access Policy rule, currently support private access rules only",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of access policy",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of access policy",
				Required:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action taken on matched traffic ('allow' or 'block'). Defaults to 'block'",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString("block"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.Actions()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"private_resource_ids": schema.SetAttribute{
				Description: "Secure Access IDs of matching private resource",
				ElementType: types.Int64Type,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.AtLeastOneOf(path.MatchRoot("private_resource_ids"), path.MatchRoot("destination_list_ids"), path.MatchRoot("private_destination_types"), path.MatchRoot("public_destination_types")),
					setvalidator.ConflictsWith(path.MatchRoot("destination_list_ids")),
				},
			},
			"destination_list_ids": schema.SetAttribute{
				Description: "Secure Access IDs of matching destination list",
				ElementType: types.Int64Type,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.AtLeastOneOf(path.MatchRoot("private_resource_ids"), path.MatchRoot("destination_list_ids"), path.MatchRoot("private_destination_types"), path.MatchRoot("public_destination_types")),
					setvalidator.ConflictsWith(path.MatchRoot("private_resource_ids")),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description for access policy",
				Optional:    true,
			},
			"traffic_type": schema.StringAttribute{
				Description: "Traffic type to define rule scope ('PRIVATE_NETWORK' or 'PUBLIC_INTERNET'). Defaults to 'PRIVATE_NETWORK'",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString("PRIVATE_NETWORK"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.TrafficTypes()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether or not to enable access policy. Defaults to false",
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"log_level": schema.StringAttribute{
				Description: "Level of logging to perform on traffic matching access policy",
				Computed:    true,
				Optional:    true,
				Default:     stringdefault.StaticString("LOG_ALL"),
				Validators: []validator.String{
					stringvalidator.OneOf(accessPolicyResourceModel{}.LogLevels()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"priority": schema.Int64Attribute{
				Description: "Priority at which to create rule (ascending)",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"client_posture_profile_id": schema.Int64Attribute{
				Description: "ID of posture profile for client-based access",
				Optional:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"source_ids": schema.SetAttribute{
				Description: "Source Secure Access IDs of matching resource",
				ElementType: types.Int64Type,
				Optional:    true,
			},
			"source_types": schema.SetAttribute{
				Description: "Wildcard source types allowing access to resource (eg. [\"directory_users\", \"networks\"])",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidSourceTypes()...)),
					setvalidator.AtLeastOneOf(path.MatchRoot("source_types"), path.MatchRoot("source_ids")),
				},
			},
			"private_destination_types": schema.SetAttribute{
				Description: "Wildcard destination types allowing access to resources (eg. [\"private_apps\"]",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidPrivateDestinationTypes()...)),
					setvalidator.AtLeastOneOf(path.MatchRoot("private_destination_types"), path.MatchRoot("destination_list_ids"), path.MatchRoot("private_resource_ids"), path.MatchRoot("public_destination_types")),
					setvalidator.ConflictsWith(path.MatchRoot("destination_list_ids"), path.MatchRoot("public_destination_types")),
				},
			},
			"public_destination_types": schema.SetAttribute{
				Description: "Wildcard destination types allowing access to public destinations (eg. [\"internet\"]",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(accessPolicyResourceModel{}.ValidPublicDestinationTypes()...)),
					setvalidator.AtLeastOneOf(path.MatchRoot("private_destination_types"), path.MatchRoot("destination_list_ids"), path.MatchRoot("private_resource_ids"), path.MatchRoot("public_destination_types")),
					setvalidator.ConflictsWith(path.MatchRoot("private_resource_ids"), path.MatchRoot("private_destination_types")),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *accessPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Access Policy")
	// Retrieve values from plan
	var plan accessPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleDefinition := formatCreateAccessPolicyRequest(ctx, &plan)

	err := retry.Do(
		func() error {
			createResp, httpRes, err := r.client.AccessRulesAPI.AddRule(context.Background()).AddRuleRequest(*ruleDefinition).Execute()
			if httpRes != nil {
				defer httpRes.Body.Close()
			}
			if err != nil {
				if httpRes != nil {
					bodyBytes, _ := io.ReadAll(httpRes.Body)
					bodyStr := string(bodyBytes)

					// Retryable errors
					if httpRes.StatusCode == 400 && strings.Contains(bodyStr, "invalid data passed. the ID's provided for") || httpRes.StatusCode == 409 {
						return fmt.Errorf("retryable error: %v - %s", err, bodyStr)
					}

					// Non-retryable errors
					log.Printf("[ERROR] error creating access policy: %v: %s\n", httpRes.Status, bodyStr)
					resp.Diagnostics.AddError("Error creating access policy", fmt.Sprintf("HTTP %s: %s", httpRes.Status, bodyStr))
					return retry.Unrecoverable(err)
				}
				// Unknown error without response
				resp.Diagnostics.AddError("Error creating access policy", err.Error())
				return retry.Unrecoverable(err)
			}

			respString, _ := json.Marshal(createResp)
			log.Printf("[DEBUG] Created access policy: %s", respString)

			plan.Priority = types.Int64Value(createResp.GetRulePriority())
			plan.ID = types.Int64Value(createResp.GetRuleId())

			// Set state to fully populated data
			diags := resp.State.Set(ctx, plan)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return retry.Unrecoverable(fmt.Errorf("failed to set state"))
			}
			return nil
		},
		retry.Delay(time.Second*10), // More reasonable delay
		retry.Attempts(6),
	)

	if err != nil {
		// Only add error if not already added in the retry function
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Error creating access policy", err.Error())
		}
	}
}

func formatCreateAccessPolicyRequest(ctx context.Context, plan *accessPolicyResourceModel) *rules.AddRuleRequest {
	// Build rule conditions
	var ruleConditionsList []rules.RuleConditionsInner

	// Add source conditions
	sourceConditions := buildSourceConditions(ctx, plan)
	ruleConditionsList = append(ruleConditionsList, sourceConditions...)

	// Add destination conditions
	destinationConditions := buildDestinationConditions(ctx, plan)
	ruleConditionsList = append(ruleConditionsList, destinationConditions...)

	// Log the conditions for debugging
	if len(ruleConditionsList) > 0 {
		conditionString, _ := json.Marshal(ruleConditionsList)
		log.Printf("[DEBUG] Rule conditions: %s", conditionString)
	}

	// Create rule definition
	ruleDefinition := rules.NewAddRuleRequest(
		plan.Name.ValueString(),
		rules.RuleAction(plan.Action.ValueString()),
		ruleConditionsList,
		buildRuleSettings(plan),
	)

	// Set optional fields
	ruleDefinition.SetRuleDescription(plan.Description.ValueString())
	ruleDefinition.SetRuleIsEnabled(plan.Enabled.ValueBool())

	// Set priority if specified
	if plan.Priority.ValueInt64() != 0 {
		ruleDefinition.SetRulePriority(plan.Priority.ValueInt64())
		log.Printf("[DEBUG] Request set priority: %v", ruleDefinition.GetRulePriority())
	}

	// Log the final request for debugging
	ruleString, _ := ruleDefinition.MarshalJSON()
	log.Printf("[DEBUG] Request definition: %s", ruleString)

	return ruleDefinition
}

func (r *accessPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state accessPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	if resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resourceId := state.ID.ValueInt64()
	tflog.Debug(ctx, "Retrieving access policy", map[string]interface{}{"id": resourceId})

	readResp, httpRes, err := r.client.AccessRulesAPI.GetRule(ctx, resourceId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Access policy not found, removing from state", map[string]interface{}{"id": resourceId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading access policy",
			fmt.Sprintf("Cannot read access policy ID %d: %s", resourceId, err.Error()),
		)
		return
	}

	// Parse rule conditions from API response
	for _, condition := range readResp.RuleConditions {
		switch {
		case condition.AttributeName.AttributeNameDestination != nil:
			switch string(*condition.AttributeName.AttributeNameDestination) {
			case "umbrella.destination.private_resource_ids":
				state.PrivateResourceIds, _ = types.SetValueFrom(ctx, types.Int64Type, condition.AttributeValue.ArrayOfInt64)
			case "umbrella.destination.destination_list_ids":
				state.DestinationListIds, _ = types.SetValueFrom(ctx, types.Int64Type, condition.AttributeValue.ArrayOfInt64)
			case "umbrella.destination.private_resource_types":
				var typeNames []string
				for _, typeId := range *condition.AttributeValue.ArrayOfString {
					if typeId == PRIVATE_APPS_TYPE {
						typeNames = append(typeNames, PRIVATE_APPS_SCHEMA)
					}
				}
				state.PrivateDestinationTypes, _ = types.SetValueFrom(ctx, types.StringType, typeNames)
			case "umbrella.destination.all":
				if condition.AttributeValue.Bool != nil && *condition.AttributeValue.Bool {
					publicTypes := []string{PUBLIC_INTERNET_SCHEMA}
					state.PublicDestinationTypes, _ = types.SetValueFrom(ctx, types.StringType, publicTypes)
				}
			}
		case condition.AttributeName.AttributeNameSource != nil:
			switch string(*condition.AttributeName.AttributeNameSource) {
			case "umbrella.source.identity_type_ids":
				var typeNames []string
				for _, typeId := range *condition.AttributeValue.ArrayOfInt64 {
					if typeId == DIRECTORY_USERS_TYPE_ID {
						typeNames = append(typeNames, DIRECTORY_USERS)
					} else if typeId == NETWORKS_TYPE_ID {
						typeNames = append(typeNames, NETWORKS)
					}
				}
				state.SourceTypes, _ = types.SetValueFrom(ctx, types.StringType, typeNames)
			case "umbrella.source.identity_ids":
				state.SourceIds, _ = types.SetValueFrom(ctx, types.Int64Type, condition.AttributeValue.ArrayOfInt64)
			}
		}
	}
	// Parse rule settings from API response
	for _, setting := range readResp.RuleSettings {
		if setting.SettingName != nil {
			switch string(*setting.SettingName) {
			case string(rules.SETTINGNAME_UMBRELLA_LOG_LEVEL):
				if setting.SettingValue.String != nil {
					state.LogLevel = types.StringValue(*setting.SettingValue.String)
				}
			case string(rules.SETTINGNAME_UMBRELLA_POSTURE_PROFILE_ID_CLIENTBASED):
				if setting.SettingValue.Int64 != nil {
					state.ClientPostureProfileId = types.Int64Value(*setting.SettingValue.Int64)
				}
			case string(rules.SETTINGNAME_UMBRELLA_DEFAULT_TRAFFIC):
				if setting.SettingValue.String != nil {
					state.TrafficType = types.StringValue(*setting.SettingValue.String)
				}
			}
		}
	}
	state.Name = types.StringValue(readResp.GetRuleName())
	state.Action = types.StringValue(string(*readResp.RuleAction))
	state.Description = types.StringValue(readResp.GetRuleDescription())
	state.Enabled = types.BoolValue(readResp.GetRuleIsEnabled())
	state.Priority = types.Int64Value(readResp.GetRulePriority())

	tflog.Debug(ctx, "Successfully parsed access policy state", map[string]interface{}{
		"id":   state.ID.ValueInt64(),
		"name": state.Name.ValueString(),
	})

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

}

// Update updates the resource and sets the updated Terraform state on success.
func (r *accessPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating access policy")

	// Retrieve values from plan and state
	var plan, state accessPolicyResourceModel
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

	// Only update if there are actual changes
	if hasChanges(&plan, &state) {
		baseline := formatCreateAccessPolicyRequest(ctx, &plan)
		payload := rules.NewPutRuleRequest(
			baseline.RuleName,
			baseline.RuleAction,
			*baseline.RulePriority,
			baseline.RuleConditions,
			baseline.RuleSettings,
		)

		updateRule, _, err := r.client.AccessRulesAPI.PutRule(ctx, plan.ID.ValueInt64()).PutRuleRequest(*payload).Execute()
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating access policy",
				fmt.Sprintf("Could not update access policy ID %s: %s", plan.ID.String(), err.Error()),
			)
			return
		}

		updateString, _ := json.Marshal(updateRule)
		log.Printf("[DEBUG] Update response for access policy ID %s: %s", plan.ID.String(), updateString)
	}

	// Set the updated state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *accessPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state accessPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing access policy with retry logic
	err := retry.Do(
		func() error {
			httpRes, err := r.client.AccessRulesAPI.DeleteRule(ctx, state.ID.ValueInt64()).Execute()
			if httpRes != nil && httpRes.StatusCode == 404 {
				// Resource already deleted
				return nil
			}
			if err != nil && httpRes != nil && httpRes.StatusCode == 409 {
				// Conflict - retry
				return fmt.Errorf("conflict deleting access policy: %v", httpRes.StatusCode)
			}
			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("failed to delete access policy: %w", err))
			}
			return nil
		},
		retry.Delay(time.Second*5),
		retry.Attempts(3),
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting access policy",
			fmt.Sprintf("Could not delete access policy ID %s: %s", state.ID.String(), err.Error()),
		)
	}
}

// Helper functions for building rule conditions

func buildSourceConditions(ctx context.Context, plan *accessPolicyResourceModel) []rules.RuleConditionsInner {
	var conditions []rules.RuleConditionsInner

	// Source IDs condition
	var sourceIds []int64
	plan.SourceIds.ElementsAs(ctx, &sourceIds, true)
	if len(sourceIds) > 0 {
		condition := rules.NewRuleConditionsInner()
		ruleName := rules.AttributeNameSource("umbrella.source.identity_ids")
		condition.SetAttributeName(rules.AttributeName{AttributeNameSource: &ruleName})
		condition.SetAttributeValue(rules.ArrayOfInt64AsAttributeValue(&sourceIds))
		condition.SetAttributeOperator("INTERSECT")
		conditions = append(conditions, *condition)
	}

	// Source types condition
	var sourceTypeNames []string
	var sourceTypes []int64
	plan.SourceTypes.ElementsAs(ctx, &sourceTypeNames, true)
	for _, sourceType := range sourceTypeNames {
		switch sourceType {
		case DIRECTORY_USERS:
			sourceTypes = append(sourceTypes, DIRECTORY_USERS_TYPE_ID)
		case NETWORKS:
			sourceTypes = append(sourceTypes, NETWORKS_TYPE_ID)
		}
	}
	if len(sourceTypes) > 0 {
		condition := rules.NewRuleConditionsInner()
		ruleName := rules.AttributeNameSource("umbrella.source.identity_type_ids")
		condition.SetAttributeName(rules.AttributeName{AttributeNameSource: &ruleName})
		condition.SetAttributeValue(rules.ArrayOfInt64AsAttributeValue(&sourceTypes))
		condition.SetAttributeOperator("INTERSECT")
		conditions = append(conditions, *condition)
	}

	return conditions
}

func buildDestinationConditions(ctx context.Context, plan *accessPolicyResourceModel) []rules.RuleConditionsInner {
	var conditions []rules.RuleConditionsInner

	// Private resource IDs condition
	var privateResourceIds []int64
	plan.PrivateResourceIds.ElementsAs(ctx, &privateResourceIds, true)
	if len(privateResourceIds) > 0 {
		condition := rules.NewRuleConditionsInner()
		destinationName := rules.AttributeNameDestination("umbrella.destination.private_resource_ids")
		condition.SetAttributeName(rules.AttributeName{AttributeNameDestination: &destinationName})
		condition.SetAttributeValue(rules.ArrayOfInt64AsAttributeValue(&privateResourceIds))
		condition.SetAttributeOperator("IN")
		conditions = append(conditions, *condition)
	}

	// Destination list IDs condition
	var destinationListIds []int64
	plan.DestinationListIds.ElementsAs(ctx, &destinationListIds, true)
	if len(destinationListIds) > 0 {
		condition := rules.NewRuleConditionsInner()
		destinationName := rules.AttributeNameDestination("umbrella.destination.destination_list_ids")
		condition.SetAttributeName(rules.AttributeName{AttributeNameDestination: &destinationName})
		condition.SetAttributeValue(rules.ArrayOfInt64AsAttributeValue(&destinationListIds))
		condition.SetAttributeOperator("INTERSECT")
		conditions = append(conditions, *condition)
	}

	// Private destination types condition
	var privateTypeNames []string
	var privateTypes []string
	plan.PrivateDestinationTypes.ElementsAs(ctx, &privateTypeNames, true)
	for _, destinationType := range privateTypeNames {
		if destinationType == PRIVATE_APPS_SCHEMA {
			privateTypes = append(privateTypes, PRIVATE_APPS_TYPE)
		}
	}
	if len(privateTypes) > 0 {
		condition := rules.NewRuleConditionsInner()
		destinationName := rules.AttributeNameDestination("umbrella.destination.private_resource_types")
		condition.SetAttributeName(rules.AttributeName{AttributeNameDestination: &destinationName})
		condition.SetAttributeValue(rules.ArrayOfStringAsAttributeValue(&privateTypes))
		condition.SetAttributeOperator("INTERSECT")
		conditions = append(conditions, *condition)
	}

	// Public destination types condition
	var publicTypeNames []string
	plan.PublicDestinationTypes.ElementsAs(ctx, &publicTypeNames, true)
	for _, publicType := range publicTypeNames {
		if publicType == PUBLIC_INTERNET_SCHEMA {
			condition := rules.NewRuleConditionsInner()
			destinationName := rules.AttributeNameDestination("umbrella.destination.all")
			publicTypesValue := true
			condition.SetAttributeName(rules.AttributeName{AttributeNameDestination: &destinationName})
			condition.SetAttributeValue(rules.BoolAsAttributeValue(&publicTypesValue))
			condition.SetAttributeOperator("=")
			conditions = append(conditions, *condition)
			break // Only need one condition for public internet
		}
	}

	return conditions
}

func buildRuleSettings(plan *accessPolicyResourceModel) []rules.RuleSettingsInner {
	var settings []rules.RuleSettingsInner

	// Log level setting
	logLevelString := plan.LogLevel.ValueString()
	logLevelSetting := rules.RuleSettingsInner{SettingValue: &rules.SettingValue{String: &logLevelString}}
	logLevelSetting.SetSettingName(rules.SETTINGNAME_UMBRELLA_LOG_LEVEL)
	settings = append(settings, logLevelSetting)

	// Client posture profile setting
	if !plan.ClientPostureProfileId.IsNull() {
		clientPostureId := plan.ClientPostureProfileId.ValueInt64()
		clientPostureSetting := rules.RuleSettingsInner{SettingValue: &rules.SettingValue{Int64: &clientPostureId}}
		clientPostureSetting.SetSettingName(rules.SETTINGNAME_UMBRELLA_POSTURE_PROFILE_ID_CLIENTBASED)
		settings = append(settings, clientPostureSetting)
	}

	// Traffic type setting
	trafficString := plan.TrafficType.ValueString()
	trafficSetting := rules.NewRuleSettingsInner()
	trafficSetting.SetSettingName(rules.SETTINGNAME_UMBRELLA_DEFAULT_TRAFFIC)
	trafficSetting.SetSettingValue(rules.SettingValue{String: &trafficString})
	settings = append(settings, *trafficSetting)

	return settings
}

// Utility functions for string/int64 conversion
func atoi64(a string) int64 {
	i, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		log.Printf("[WARN] Failed to convert string %s to int64: %v", a, err)
		return 0
	}
	return i
}

// hasChanges checks if there are any changes between plan and state
func hasChanges(plan, state *accessPolicyResourceModel) bool {
	return !plan.Name.Equal(state.Name) ||
		!plan.Description.Equal(state.Description) ||
		!plan.Enabled.Equal(state.Enabled) ||
		!plan.Priority.Equal(state.Priority) ||
		!plan.SourceIds.Equal(state.SourceIds) ||
		!plan.SourceTypes.Equal(state.SourceTypes) ||
		!plan.PrivateDestinationTypes.Equal(state.PrivateDestinationTypes) ||
		!plan.PublicDestinationTypes.Equal(state.PublicDestinationTypes) ||
		!plan.PrivateResourceIds.Equal(state.PrivateResourceIds) ||
		!plan.DestinationListIds.Equal(state.DestinationListIds) ||
		!plan.LogLevel.Equal(state.LogLevel) ||
		!plan.ClientPostureProfileId.Equal(state.ClientPostureProfileId) ||
		!plan.TrafficType.Equal(state.TrafficType)
}
