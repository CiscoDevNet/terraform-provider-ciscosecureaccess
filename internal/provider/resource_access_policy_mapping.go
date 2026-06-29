// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
)

const (
	conditionDestinationAll                 = "umbrella.destination.all"
	conditionDestinationApplicationIDs      = "umbrella.destination.application_ids"
	conditionDestinationApplicationListIDs  = "umbrella.destination.application_list_ids"
	conditionDestinationCategoryIDs         = "umbrella.destination.category_ids"
	conditionDestinationCategoryListIDs     = "umbrella.destination.category_list_ids"
	conditionDestinationCompositeInlineIP   = "umbrella.destination.composite_inline_ip"
	conditionDestinationListIDs             = "umbrella.destination.destination_list_ids"
	conditionDestinationPrivateResourceIDs  = "umbrella.destination.private_resource_ids"
	conditionDestinationPrivateGroupIDs     = "umbrella.destination.private_resource_group_ids"
	conditionDestinationPrivateResourceType = "umbrella.destination.private_resource_types"
	conditionSourceAll                      = "umbrella.source.all"
	conditionSourceIdentityIDs              = "umbrella.source.identity_ids"
	conditionSourceIdentityTypeIDs          = "umbrella.source.identity_type_ids"
)

func formatCreateAccessPolicyRequest(ctx context.Context, model *accessPolicyResourceModel) (rules.AddRuleRequest, diag.Diagnostics) {
	conditions, diags := expandAccessPolicyConditions(ctx, model)
	settings, settingDiags := expandAccessPolicySettings(ctx, model)
	diags.Append(settingDiags...)

	payload := rules.NewAddRuleRequest(
		model.Name.ValueString(),
		rules.RuleAction(model.Action.ValueString()),
		conditions,
		settings,
	)
	if !model.Description.IsNull() && !model.Description.IsUnknown() {
		payload.SetRuleDescription(model.Description.ValueString())
	}
	if !model.Enabled.IsUnknown() {
		payload.SetRuleIsEnabled(model.Enabled.ValueBool())
	}
	if !model.Priority.IsNull() && !model.Priority.IsUnknown() && model.Priority.ValueInt64() > 0 {
		payload.SetRulePriority(model.Priority.ValueInt64())
	}
	return *payload, diags
}

func formatPutAccessPolicyRequest(ctx context.Context, model *accessPolicyResourceModel) (rules.PutRuleRequest, diag.Diagnostics) {
	baseline, diags := formatCreateAccessPolicyRequest(ctx, model)
	payload := rules.NewPutRuleRequest(
		baseline.RuleName,
		baseline.RuleAction,
		model.Priority.ValueInt64(),
		baseline.RuleConditions,
		baseline.RuleSettings,
	)
	if baseline.RuleDescription != nil {
		payload.SetRuleDescription(*baseline.RuleDescription)
	}
	if baseline.RuleIsEnabled != nil {
		payload.SetRuleIsEnabled(*baseline.RuleIsEnabled)
	}
	return *payload, diags
}

func expandAccessPolicyConditions(ctx context.Context, model *accessPolicyResourceModel) ([]rules.RuleConditionsInner, diag.Diagnostics) {
	var diags diag.Diagnostics
	conditions := make([]rules.RuleConditionsInner, 0, 13)

	if !model.SourceAll.IsNull() && !model.SourceAll.IsUnknown() {
		value := model.SourceAll.ValueBool()
		conditions = append(conditions, sourceCondition(conditionSourceAll, rules.ATTRIBUTEOPERATOR_EQUAL, rules.BoolAsAttributeValue(&value)))
	}

	sourceIDs := int64SetValues(ctx, model.SourceIds, &diags)
	if len(sourceIDs) > 0 {
		conditions = append(conditions, sourceCondition(conditionSourceIdentityIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, rules.ArrayOfInt64AsAttributeValue(&sourceIDs)))
	}

	sourceTypeIDs := int64SetValues(ctx, model.SourceIdentityTypeIds, &diags)
	if len(sourceTypeIDs) == 0 {
		var sourceTypes []string
		if !model.SourceTypes.IsNull() && !model.SourceTypes.IsUnknown() {
			diags.Append(model.SourceTypes.ElementsAs(ctx, &sourceTypes, false)...)
		}
		for _, sourceType := range sourceTypes {
			switch sourceType {
			case DIRECTORY_USERS:
				sourceTypeIDs = append(sourceTypeIDs, DIRECTORY_USERS_TYPE_ID)
			case NETWORKS:
				sourceTypeIDs = append(sourceTypeIDs, NETWORKS_TYPE_ID)
			}
		}
		sort.Slice(sourceTypeIDs, func(i, j int) bool { return sourceTypeIDs[i] < sourceTypeIDs[j] })
	}
	if len(sourceTypeIDs) > 0 {
		conditions = append(conditions, sourceCondition(conditionSourceIdentityTypeIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, rules.ArrayOfInt64AsAttributeValue(&sourceTypeIDs)))
	}

	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationPrivateResourceIDs, rules.ATTRIBUTEOPERATOR_IN, model.PrivateResourceIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationPrivateGroupIDs, rules.ATTRIBUTEOPERATOR_IN, model.PrivateResourceGroupIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationListIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, model.DestinationListIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationApplicationIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, model.ApplicationIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationApplicationListIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, model.ApplicationListIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationCategoryIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, model.CategoryIds, &diags)
	appendInt64DestinationCondition(ctx, &conditions, conditionDestinationCategoryListIDs, rules.ATTRIBUTEOPERATOR_INTERSECT, model.ContentCategoryListIds, &diags)

	if !model.InlineDestinations.IsNull() && !model.InlineDestinations.IsUnknown() {
		var inlineModels []accessPolicyInlineDestinationModel
		diags.Append(model.InlineDestinations.ElementsAs(ctx, &inlineModels, false)...)
		inline := make([]rules.CompositeInlineDestination, 0, len(inlineModels))
		for _, destination := range inlineModels {
			var addresses, ports []string
			diags.Append(destination.IPAddresses.ElementsAs(ctx, &addresses, false)...)
			diags.Append(destination.Ports.ElementsAs(ctx, &ports, false)...)
			sort.Strings(addresses)
			sort.Strings(ports)
			inline = append(inline, *rules.NewCompositeInlineDestination(addresses, ports, rules.CompositeInlineDestinationProtocol(destination.Protocol.ValueString())))
		}
		sort.Slice(inline, func(i, j int) bool {
			return strings.Join(inline[i].Ip, ",")+"|"+strings.Join(inline[i].Port, ",")+"|"+string(inline[i].Protocol) <
				strings.Join(inline[j].Ip, ",")+"|"+strings.Join(inline[j].Port, ",")+"|"+string(inline[j].Protocol)
		})
		if len(inline) > 0 {
			conditions = append(conditions, destinationCondition(conditionDestinationCompositeInlineIP, rules.ATTRIBUTEOPERATOR_IN, rules.ArrayOfCompositeInlineDestinationAsAttributeValue(&inline)))
		}
	}

	if setHasValues(model.PrivateDestinationTypes) {
		privateTypes := []string{PRIVATE_APPS_TYPE}
		// The SDK currently classifies this wire name in AttributeNameSource.
		conditions = append(conditions, sourceCondition(conditionDestinationPrivateResourceType, rules.ATTRIBUTEOPERATOR_INTERSECT, rules.ArrayOfStringAsAttributeValue(&privateTypes)))
	}
	if setHasValues(model.PublicDestinationTypes) {
		value := true
		conditions = append(conditions, destinationCondition(conditionDestinationAll, rules.ATTRIBUTEOPERATOR_EQUAL, rules.BoolAsAttributeValue(&value)))
	}

	return conditions, diags
}

func appendInt64DestinationCondition(ctx context.Context, conditions *[]rules.RuleConditionsInner, name string, operator rules.AttributeOperator, set types.Set, diags *diag.Diagnostics) {
	values := int64SetValues(ctx, set, diags)
	if len(values) > 0 {
		*conditions = append(*conditions, destinationCondition(name, operator, rules.ArrayOfInt64AsAttributeValue(&values)))
	}
}

func int64SetValues(ctx context.Context, set types.Set, diags *diag.Diagnostics) []int64 {
	values := make([]int64, 0)
	if set.IsNull() || set.IsUnknown() {
		return values
	}
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values
}

func destinationCondition(name string, operator rules.AttributeOperator, value rules.AttributeValue) rules.RuleConditionsInner {
	condition := rules.NewRuleConditionsInner()
	attributeName := rules.AttributeNameDestination(name)
	condition.SetAttributeName(rules.AttributeName{AttributeNameDestination: &attributeName})
	condition.SetAttributeValue(value)
	condition.SetAttributeOperator(operator)
	return *condition
}

func sourceCondition(name string, operator rules.AttributeOperator, value rules.AttributeValue) rules.RuleConditionsInner {
	condition := rules.NewRuleConditionsInner()
	attributeName := rules.AttributeNameSource(name)
	condition.SetAttributeName(rules.AttributeName{AttributeNameSource: &attributeName})
	condition.SetAttributeValue(value)
	condition.SetAttributeOperator(operator)
	return *condition
}

func expandAccessPolicySettings(ctx context.Context, model *accessPolicyResourceModel) ([]rules.RuleSettingsInner, diag.Diagnostics) {
	var diags diag.Diagnostics
	settings := make([]rules.RuleSettingsInner, 0, 9)

	if !model.LogLevel.IsNull() && !model.LogLevel.IsUnknown() {
		settings = append(settings, stringRuleSetting("umbrella.logLevel", model.LogLevel.ValueString()))
	}
	if !model.TrafficType.IsNull() && !model.TrafficType.IsUnknown() {
		settings = append(settings, stringRuleSetting("umbrella.default.traffic", model.TrafficType.ValueString()))
	}
	if !model.AllowPasswordProtectedFiles.IsNull() && !model.AllowPasswordProtectedFiles.IsUnknown() {
		settings = append(settings, boolRuleSetting("umbrella.AllowPasswordProtectedFiles", model.AllowPasswordProtectedFiles.ValueBool()))
	}
	advancedApplicationIDs := int64SetValues(ctx, model.AdvancedApplicationIds, &diags)
	if len(advancedApplicationIDs) > 0 {
		settings = append(settings, int64ArrayRuleSetting("umbrella.advancedApplicationIds", advancedApplicationIDs))
	}
	appendOptionalInt64Setting(&settings, "umbrella.posture.profileIdClientbased", model.ClientPostureProfileId)
	appendOptionalInt64Setting(&settings, "umbrella.posture.webProfileId", model.WebProfileId)
	appendOptionalInt64Setting(&settings, "umbrella.posture.ipsProfileId", model.IpsProfileId)
	appendOptionalInt64Setting(&settings, "umbrella.posture.privateSecurityProfileId", model.PrivateSecurityProfileId)
	appendOptionalInt64Setting(&settings, "sse.tenantControlProfileId", model.TenantControlProfileId)
	return settings, diags
}

func stringRuleSetting(name, value string) rules.RuleSettingsInner {
	setting := rules.NewRuleSettingsInner()
	setting.SetSettingName(rules.SettingName(name))
	setting.SetSettingValue(rules.StringAsSettingValue(&value))
	return *setting
}

func boolRuleSetting(name string, value bool) rules.RuleSettingsInner {
	setting := rules.NewRuleSettingsInner()
	setting.SetSettingName(rules.SettingName(name))
	setting.SetSettingValue(rules.BoolAsSettingValue(&value))
	return *setting
}

func int64ArrayRuleSetting(name string, value []int64) rules.RuleSettingsInner {
	setting := rules.NewRuleSettingsInner()
	setting.SetSettingName(rules.SettingName(name))
	setting.SetSettingValue(rules.ArrayOfInt64AsSettingValue(&value))
	return *setting
}

func appendOptionalInt64Setting(settings *[]rules.RuleSettingsInner, name string, value types.Int64) {
	if value.IsNull() || value.IsUnknown() {
		return
	}
	settingValue := value.ValueInt64()
	setting := rules.NewRuleSettingsInner()
	setting.SetSettingName(rules.SettingName(name))
	setting.SetSettingValue(rules.Int64AsSettingValue(&settingValue))
	*settings = append(*settings, *setting)
}

func flattenAccessPolicyResponse(ctx context.Context, rule *rules.Rule, model *accessPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if rule == nil {
		diags.AddError("Invalid access policy response", "The API returned an empty access policy response.")
		return diags
	}
	if rule.RuleId != nil {
		model.ID = types.Int64Value(rule.GetRuleId())
	} else if model.ID.IsNull() || model.ID.IsUnknown() || model.ID.ValueInt64() <= 0 {
		diags.AddError("Invalid access policy response", "The API response did not include ruleId.")
	}
	if rule.RuleName == nil {
		diags.AddError("Invalid access policy response", "The API response did not include ruleName.")
	} else {
		model.Name = types.StringValue(rule.GetRuleName())
	}
	if rule.RuleAction == nil {
		diags.AddError("Invalid access policy response", "The API response did not include ruleAction.")
	} else {
		model.Action = types.StringValue(string(rule.GetRuleAction()))
	}
	if rule.RuleDescription == nil {
		model.Description = types.StringNull()
	} else {
		model.Description = types.StringValue(rule.GetRuleDescription())
	}
	if rule.RuleIsEnabled == nil {
		diags.AddError("Invalid access policy response", "The API response did not include ruleIsEnabled.")
	} else {
		model.Enabled = types.BoolValue(rule.GetRuleIsEnabled())
	}
	if rule.RulePriority == nil {
		diags.AddError("Invalid access policy response", "The API response did not include rulePriority.")
	} else {
		model.Priority = types.Int64Value(rule.GetRulePriority())
	}

	diags.Append(flattenAccessPolicyConditions(ctx, rule.RuleConditions, model)...)
	diags.Append(flattenAccessPolicySettings(ctx, rule.RuleSettings, model)...)
	return diags
}

func flattenAccessPolicyConditions(ctx context.Context, conditions []rules.RuleConditionsInner, model *accessPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	preferRawSourceTypes := !model.SourceIdentityTypeIds.IsNull() && !model.SourceIdentityTypeIds.IsUnknown()
	resetAccessPolicyConditionState(model)

	for _, condition := range conditions {
		if condition.AttributeName == nil || condition.AttributeValue == nil {
			diags.AddError("Invalid access policy condition", "A condition is missing attributeName or attributeValue.")
			continue
		}
		if condition.AttributeName.AttributeNameDestination != nil {
			name := string(*condition.AttributeName.AttributeNameDestination)
			diags.Append(flattenDestinationCondition(ctx, name, condition, model)...)
			continue
		}
		if condition.AttributeName.AttributeNameSource != nil {
			name := string(*condition.AttributeName.AttributeNameSource)
			diags.Append(flattenSourceCondition(ctx, name, condition, model, preferRawSourceTypes)...)
			continue
		}
		diags.AddError("Unsupported access policy condition", "The API returned a composite condition name that this provider cannot preserve.")
	}
	return diags
}

func resetAccessPolicyConditionState(model *accessPolicyResourceModel) {
	model.SourceAll = types.BoolNull()
	model.SourceIds = types.SetNull(types.Int64Type)
	model.SourceTypes = types.SetNull(types.StringType)
	model.SourceIdentityTypeIds = types.SetNull(types.Int64Type)
	model.PrivateResourceIds = types.SetNull(types.Int64Type)
	model.PrivateResourceGroupIds = types.SetNull(types.Int64Type)
	model.DestinationListIds = types.SetNull(types.Int64Type)
	model.ApplicationIds = types.SetNull(types.Int64Type)
	model.ApplicationListIds = types.SetNull(types.Int64Type)
	model.CategoryIds = types.SetNull(types.Int64Type)
	model.ContentCategoryListIds = types.SetNull(types.Int64Type)
	model.InlineDestinations = types.SetNull(types.ObjectType{AttrTypes: accessPolicyInlineDestinationModel{}.AttrTypes()})
	model.PrivateDestinationTypes = types.SetNull(types.StringType)
	model.PublicDestinationTypes = types.SetNull(types.StringType)
}

func flattenDestinationCondition(ctx context.Context, name string, condition rules.RuleConditionsInner, model *accessPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	switch name {
	case conditionDestinationAll:
		diags.Append(requireConditionOperator(condition, rules.ATTRIBUTEOPERATOR_EQUAL, name)...)
		if condition.AttributeValue.Bool == nil || !*condition.AttributeValue.Bool {
			diags.AddError("Invalid access policy condition", fmt.Sprintf("%s must contain boolean true.", name))
			break
		}
		var setDiags diag.Diagnostics
		model.PublicDestinationTypes, setDiags = types.SetValueFrom(ctx, types.StringType, []string{PUBLIC_INTERNET_SCHEMA})
		diags.Append(setDiags...)
	case conditionDestinationApplicationIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.ApplicationIds)...)
	case conditionDestinationApplicationListIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.ApplicationListIds)...)
	case conditionDestinationCategoryIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.CategoryIds)...)
	case conditionDestinationCategoryListIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.ContentCategoryListIds)...)
	case conditionDestinationListIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.DestinationListIds)...)
	case conditionDestinationPrivateResourceIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_IN, name, &model.PrivateResourceIds)...)
	case conditionDestinationPrivateGroupIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_IN, name, &model.PrivateResourceGroupIds)...)
	case conditionDestinationCompositeInlineIP:
		diags.Append(requireConditionOperator(condition, rules.ATTRIBUTEOPERATOR_IN, name)...)
		if condition.AttributeValue.ArrayOfCompositeInlineDestination == nil {
			diags.AddError("Invalid access policy condition", fmt.Sprintf("%s does not contain composite inline destinations.", name))
			break
		}
		models := make([]accessPolicyInlineDestinationModel, 0, len(*condition.AttributeValue.ArrayOfCompositeInlineDestination))
		for _, destination := range *condition.AttributeValue.ArrayOfCompositeInlineDestination {
			ipSet, ipDiags := types.SetValueFrom(ctx, types.StringType, destination.Ip)
			portSet, portDiags := types.SetValueFrom(ctx, types.StringType, destination.Port)
			diags.Append(ipDiags...)
			diags.Append(portDiags...)
			models = append(models, accessPolicyInlineDestinationModel{
				IPAddresses: ipSet,
				Ports:       portSet,
				Protocol:    types.StringValue(string(destination.Protocol)),
			})
		}
		set, setDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: accessPolicyInlineDestinationModel{}.AttrTypes()}, models)
		diags.Append(setDiags...)
		model.InlineDestinations = set
	default:
		diags.AddError("Unsupported access policy destination condition", fmt.Sprintf("The API returned %q, which this provider cannot preserve.", name))
	}
	return diags
}

func flattenSourceCondition(ctx context.Context, name string, condition rules.RuleConditionsInner, model *accessPolicyResourceModel, preferRawSourceTypes bool) diag.Diagnostics {
	var diags diag.Diagnostics
	switch name {
	case conditionSourceAll:
		diags.Append(requireConditionOperator(condition, rules.ATTRIBUTEOPERATOR_EQUAL, name)...)
		if condition.AttributeValue.Bool == nil {
			diags.AddError("Invalid access policy condition", fmt.Sprintf("%s does not contain a boolean.", name))
		} else {
			model.SourceAll = types.BoolValue(*condition.AttributeValue.Bool)
		}
	case conditionSourceIdentityIDs:
		diags.Append(flattenInt64Condition(ctx, condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name, &model.SourceIds)...)
	case conditionSourceIdentityTypeIDs:
		diags.Append(requireConditionOperator(condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name)...)
		if condition.AttributeValue.ArrayOfInt64 == nil {
			diags.AddError("Invalid access policy condition", fmt.Sprintf("%s does not contain integer IDs.", name))
			break
		}
		ids := *condition.AttributeValue.ArrayOfInt64
		typeNames := make([]string, 0, len(ids))
		allKnown := true
		for _, id := range ids {
			switch id {
			case DIRECTORY_USERS_TYPE_ID:
				typeNames = append(typeNames, DIRECTORY_USERS)
			case NETWORKS_TYPE_ID:
				typeNames = append(typeNames, NETWORKS)
			default:
				allKnown = false
			}
		}
		if allKnown && !preferRawSourceTypes {
			var setDiags diag.Diagnostics
			model.SourceTypes, setDiags = types.SetValueFrom(ctx, types.StringType, typeNames)
			diags.Append(setDiags...)
		} else {
			var setDiags diag.Diagnostics
			model.SourceIdentityTypeIds, setDiags = types.SetValueFrom(ctx, types.Int64Type, ids)
			diags.Append(setDiags...)
		}
	case conditionDestinationPrivateResourceType:
		diags.Append(requireConditionOperator(condition, rules.ATTRIBUTEOPERATOR_INTERSECT, name)...)
		if condition.AttributeValue.ArrayOfString == nil {
			diags.AddError("Invalid access policy condition", fmt.Sprintf("%s does not contain private resource types.", name))
			break
		}
		for _, value := range *condition.AttributeValue.ArrayOfString {
			if value != PRIVATE_APPS_TYPE {
				diags.AddError("Unsupported private destination type", fmt.Sprintf("The API returned %q, which this provider cannot preserve.", value))
				continue
			}
			var setDiags diag.Diagnostics
			model.PrivateDestinationTypes, setDiags = types.SetValueFrom(ctx, types.StringType, []string{PRIVATE_APPS_SCHEMA})
			diags.Append(setDiags...)
		}
	default:
		diags.AddError("Unsupported access policy source condition", fmt.Sprintf("The API returned %q, which this provider cannot preserve.", name))
	}
	return diags
}

func flattenInt64Condition(ctx context.Context, condition rules.RuleConditionsInner, operator rules.AttributeOperator, name string, target *types.Set) diag.Diagnostics {
	var diags diag.Diagnostics
	diags.Append(requireConditionOperator(condition, operator, name)...)
	if condition.AttributeValue.ArrayOfInt64 == nil {
		diags.AddError("Invalid access policy condition", fmt.Sprintf("%s does not contain integer IDs.", name))
		return diags
	}
	set, setDiags := types.SetValueFrom(ctx, types.Int64Type, *condition.AttributeValue.ArrayOfInt64)
	diags.Append(setDiags...)
	*target = set
	return diags
}

func requireConditionOperator(condition rules.RuleConditionsInner, expected rules.AttributeOperator, name string) diag.Diagnostics {
	var diags diag.Diagnostics
	if condition.AttributeOperator == nil || *condition.AttributeOperator != expected {
		actual := "<missing>"
		if condition.AttributeOperator != nil {
			actual = string(*condition.AttributeOperator)
		}
		diags.AddError("Unsupported access policy condition operator", fmt.Sprintf("Condition %q uses %q; expected %q.", name, actual, expected))
	}
	return diags
}

func flattenAccessPolicySettings(ctx context.Context, settings []rules.SettingResponseInner, model *accessPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	resetAccessPolicySettingState(model)
	for _, setting := range settings {
		if setting.SettingName == nil || setting.SettingValue == nil {
			diags.AddError("Invalid access policy setting", "A rule setting is missing settingName or settingValue.")
			continue
		}
		name := string(*setting.SettingName)
		value := setting.SettingValue
		switch name {
		case "umbrella.logLevel":
			if value.String == nil {
				diags.AddError("Invalid access policy setting", fmt.Sprintf("%s does not contain a string.", name))
			} else {
				model.LogLevel = types.StringValue(*value.String)
			}
		case "umbrella.default.traffic":
			if value.String == nil {
				diags.AddError("Invalid access policy setting", fmt.Sprintf("%s does not contain a string.", name))
			} else {
				model.TrafficType = types.StringValue(*value.String)
			}
		case "umbrella.AllowPasswordProtectedFiles":
			if value.Bool == nil {
				diags.AddError("Invalid access policy setting", fmt.Sprintf("%s does not contain a boolean.", name))
			} else {
				model.AllowPasswordProtectedFiles = types.BoolValue(*value.Bool)
			}
		case "umbrella.advancedApplicationIds":
			if value.ArrayOfInt64 == nil {
				diags.AddError("Invalid access policy setting", fmt.Sprintf("%s does not contain integer IDs.", name))
			} else {
				var setDiags diag.Diagnostics
				model.AdvancedApplicationIds, setDiags = types.SetValueFrom(ctx, types.Int64Type, *value.ArrayOfInt64)
				diags.Append(setDiags...)
			}
		case "umbrella.posture.profileIdClientbased":
			diags.Append(flattenInt64Setting(name, value, &model.ClientPostureProfileId)...)
		case "umbrella.posture.webProfileId":
			diags.Append(flattenInt64Setting(name, value, &model.WebProfileId)...)
		case "umbrella.posture.ipsProfileId":
			diags.Append(flattenInt64Setting(name, value, &model.IpsProfileId)...)
		case "umbrella.posture.privateSecurityProfileId":
			diags.Append(flattenInt64Setting(name, value, &model.PrivateSecurityProfileId)...)
		case "sse.tenantControlProfileId":
			diags.Append(flattenInt64Setting(name, value, &model.TenantControlProfileId)...)
		default:
			diags.AddError("Unsupported access policy setting", fmt.Sprintf("The API returned %q, which this provider cannot preserve.", name))
		}
	}
	return diags
}

func resetAccessPolicySettingState(model *accessPolicyResourceModel) {
	model.LogLevel = types.StringNull()
	model.TrafficType = types.StringNull()
	model.AllowPasswordProtectedFiles = types.BoolNull()
	model.AdvancedApplicationIds = types.SetNull(types.Int64Type)
	model.ClientPostureProfileId = types.Int64Null()
	model.WebProfileId = types.Int64Null()
	model.IpsProfileId = types.Int64Null()
	model.PrivateSecurityProfileId = types.Int64Null()
	model.TenantControlProfileId = types.Int64Null()
}

func flattenInt64Setting(name string, value *rules.SettingValue, target *types.Int64) diag.Diagnostics {
	var diags diag.Diagnostics
	if value.Int64 == nil {
		diags.AddError("Invalid access policy setting", fmt.Sprintf("%s does not contain an integer ID.", name))
		return diags
	}
	*target = types.Int64Value(*value.Int64)
	return diags
}
