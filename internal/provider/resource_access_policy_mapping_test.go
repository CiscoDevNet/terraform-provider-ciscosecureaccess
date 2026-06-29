// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
)

func TestAccessPolicyMigrationContractRoundTrip(t *testing.T) {
	ctx := context.Background()
	inline := accessPolicyInlineDestinationModel{
		IPAddresses: mustStringSet(t, ctx, "10.0.0.0/24", "192.0.2.10"),
		Ports:       mustStringSet(t, ctx, "443", "8000-8080"),
		Protocol:    types.StringValue("TCP"),
	}
	inlineSet, inlineDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: accessPolicyInlineDestinationModel{}.AttrTypes()}, []accessPolicyInlineDestinationModel{inline})
	require.False(t, inlineDiags.HasError(), "building inline destination set: %v", inlineDiags)

	model := accessPolicyResourceModel{
		ID:                          types.Int64Value(77),
		Name:                        types.StringValue("tfAcc-migration-contract"),
		Action:                      types.StringValue("warn"),
		Description:                 types.StringValue("migration contract"),
		Enabled:                     types.BoolValue(false),
		Priority:                    types.Int64Value(123),
		SourceAll:                   types.BoolValue(true),
		SourceIds:                   mustInt64Set(t, ctx, 1001, 1002),
		SourceIdentityTypeIds:       mustInt64Set(t, ctx, 9, 34),
		SourceTypes:                 types.SetNull(types.StringType),
		PrivateResourceIds:          mustInt64Set(t, ctx, 2001),
		PrivateResourceGroupIds:     mustInt64Set(t, ctx, 2002),
		DestinationListIds:          mustInt64Set(t, ctx, 3001),
		ApplicationIds:              mustInt64Set(t, ctx, 4001),
		ApplicationListIds:          mustInt64Set(t, ctx, 4002),
		CategoryIds:                 mustInt64Set(t, ctx, 5001),
		ContentCategoryListIds:      mustInt64Set(t, ctx, 5002),
		InlineDestinations:          inlineSet,
		PrivateDestinationTypes:     types.SetNull(types.StringType),
		PublicDestinationTypes:      mustStringSet(t, ctx, PUBLIC_INTERNET_SCHEMA),
		LogLevel:                    types.StringValue("LOG_SECURITY"),
		TrafficType:                 types.StringValue("PUBLIC_INTERNET"),
		AllowPasswordProtectedFiles: types.BoolValue(true),
		AdvancedApplicationIds:      mustInt64Set(t, ctx, 6001, 6002),
		ClientPostureProfileId:      types.Int64Value(7001),
		WebProfileId:                types.Int64Value(7002),
		IpsProfileId:                types.Int64Value(7003),
		PrivateSecurityProfileId:    types.Int64Value(7004),
		TenantControlProfileId:      types.Int64Value(7005),
	}

	payload, diags := formatCreateAccessPolicyRequest(ctx, &model)
	require.False(t, diags.HasError(), "expanding access policy: %v", diags)
	require.Equal(t, rules.RuleAction("warn"), payload.RuleAction)

	conditionOperators := map[string]rules.AttributeOperator{}
	for _, condition := range payload.RuleConditions {
		name := accessPolicyConditionName(t, condition)
		require.NotNil(t, condition.AttributeOperator, name)
		conditionOperators[name] = *condition.AttributeOperator
	}
	require.Equal(t, map[string]rules.AttributeOperator{
		conditionDestinationAll:                rules.ATTRIBUTEOPERATOR_EQUAL,
		conditionDestinationApplicationIDs:     rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionDestinationApplicationListIDs: rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionDestinationCategoryIDs:        rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionDestinationCategoryListIDs:    rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionDestinationCompositeInlineIP:  rules.ATTRIBUTEOPERATOR_IN,
		conditionDestinationListIDs:            rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionDestinationPrivateGroupIDs:    rules.ATTRIBUTEOPERATOR_IN,
		conditionDestinationPrivateResourceIDs: rules.ATTRIBUTEOPERATOR_IN,
		conditionSourceAll:                     rules.ATTRIBUTEOPERATOR_EQUAL,
		conditionSourceIdentityIDs:             rules.ATTRIBUTEOPERATOR_INTERSECT,
		conditionSourceIdentityTypeIDs:         rules.ATTRIBUTEOPERATOR_INTERSECT,
	}, conditionOperators)

	settingNames := make(map[string]struct{}, len(payload.RuleSettings))
	responseSettings := make([]rules.SettingResponseInner, 0, len(payload.RuleSettings))
	for _, setting := range payload.RuleSettings {
		require.NotNil(t, setting.SettingName)
		settingNames[string(*setting.SettingName)] = struct{}{}
		responseSettings = append(responseSettings, rules.SettingResponseInner{
			SettingName:  setting.SettingName,
			SettingValue: setting.SettingValue,
		})
	}
	require.Equal(t, map[string]struct{}{
		"sse.tenantControlProfileId":                {},
		"umbrella.AllowPasswordProtectedFiles":      {},
		"umbrella.advancedApplicationIds":           {},
		"umbrella.default.traffic":                  {},
		"umbrella.logLevel":                         {},
		"umbrella.posture.ipsProfileId":             {},
		"umbrella.posture.privateSecurityProfileId": {},
		"umbrella.posture.profileIdClientbased":     {},
		"umbrella.posture.webProfileId":             {},
	}, settingNames)

	id := model.ID.ValueInt64()
	name := model.Name.ValueString()
	description := model.Description.ValueString()
	action := rules.RuleAction(model.Action.ValueString())
	priority := model.Priority.ValueInt64()
	enabled := model.Enabled.ValueBool()
	apiRule := &rules.Rule{
		RuleId:          &id,
		RuleName:        &name,
		RuleDescription: &description,
		RuleAction:      &action,
		RulePriority:    &priority,
		RuleIsEnabled:   &enabled,
		RuleConditions:  payload.RuleConditions,
		RuleSettings:    responseSettings,
	}
	flattened := model
	flattenDiags := flattenAccessPolicyResponse(ctx, apiRule, &flattened)
	require.False(t, flattenDiags.HasError(), "flattening access policy: %v", flattenDiags)
	require.False(t, hasChanges(&model, &flattened), "expanded and flattened model should be identical\nwant: %#v\ngot: %#v", model, flattened)
}

func TestAccessPolicySDKLifecycle(t *testing.T) {
	ctx := context.Background()
	inline := accessPolicyInlineDestinationModel{
		IPAddresses: mustStringSet(t, ctx, "0.0.0.0/0"),
		Ports:       mustStringSet(t, ctx, "443"),
		Protocol:    types.StringValue("TCP"),
	}
	inlineSet, inlineDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: accessPolicyInlineDestinationModel{}.AttrTypes()}, []accessPolicyInlineDestinationModel{inline})
	require.False(t, inlineDiags.HasError(), "%v", inlineDiags)
	model := accessPolicyResourceModel{
		Name:                        types.StringValue("tfAcc-mock-policy"),
		Action:                      types.StringValue("allow"),
		Description:                 types.StringValue("mock lifecycle"),
		Enabled:                     types.BoolValue(false),
		SourceAll:                   types.BoolValue(true),
		SourceIds:                   types.SetNull(types.Int64Type),
		SourceTypes:                 types.SetNull(types.StringType),
		SourceIdentityTypeIds:       types.SetNull(types.Int64Type),
		PrivateResourceIds:          types.SetNull(types.Int64Type),
		PrivateResourceGroupIds:     types.SetNull(types.Int64Type),
		DestinationListIds:          types.SetNull(types.Int64Type),
		ApplicationIds:              types.SetNull(types.Int64Type),
		ApplicationListIds:          types.SetNull(types.Int64Type),
		CategoryIds:                 types.SetNull(types.Int64Type),
		ContentCategoryListIds:      types.SetNull(types.Int64Type),
		InlineDestinations:          inlineSet,
		PrivateDestinationTypes:     types.SetNull(types.StringType),
		PublicDestinationTypes:      types.SetNull(types.StringType),
		LogLevel:                    types.StringValue("LOG_ALL"),
		TrafficType:                 types.StringValue("PRIVATE_NETWORK"),
		AdvancedApplicationIds:      types.SetNull(types.Int64Type),
		AllowPasswordProtectedFiles: types.BoolNull(),
		ClientPostureProfileId:      types.Int64Null(),
		WebProfileId:                types.Int64Null(),
		IpsProfileId:                types.Int64Null(),
		PrivateSecurityProfileId:    types.Int64Null(),
		TenantControlProfileId:      types.Int64Null(),
	}

	var stored *rules.Rule
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/rules":
			var payload rules.AddRuleRequest
			require.NoError(t, json.NewDecoder(request.Body).Decode(&payload))
			require.Equal(t, rules.RuleAction("allow"), payload.RuleAction)
			require.Len(t, payload.RuleConditions, 2)
			stored = mockRuleFromRequest(901, 10, payload.RuleName, payload.RuleDescription, payload.RuleAction, payload.RuleIsEnabled, payload.RuleConditions, payload.RuleSettings)
			writer.WriteHeader(http.StatusCreated)
			require.NoError(t, json.NewEncoder(writer).Encode(stored))

		case request.Method == http.MethodGet && request.URL.Path == "/rules/901":
			if stored == nil {
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte(`{"statusCode":404,"error":"Not Found"}`))
				return
			}
			require.NoError(t, json.NewEncoder(writer).Encode(stored))

		case request.Method == http.MethodPut && request.URL.Path == "/rules/901":
			var payload rules.PutRuleRequest
			require.NoError(t, json.NewDecoder(request.Body).Decode(&payload))
			require.Equal(t, rules.RuleAction("block"), payload.RuleAction)
			stored = mockRuleFromRequest(901, payload.RulePriority, payload.RuleName, payload.RuleDescription, payload.RuleAction, payload.RuleIsEnabled, payload.RuleConditions, payload.RuleSettings)
			require.NoError(t, json.NewEncoder(writer).Encode(stored))

		case request.Method == http.MethodDelete && request.URL.Path == "/rules/901":
			stored = nil
			writer.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	apiClient := testRulesAPIClient(server)
	createPayload, createDiags := formatCreateAccessPolicyRequest(ctx, &model)
	require.False(t, createDiags.HasError(), "%v", createDiags)
	created, response, err := apiClient.AccessRulesAPI.AddRule(ctx).AddRuleRequest(createPayload).Execute()
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, response.StatusCode)
	_ = response.Body.Close()
	model.ID = types.Int64Value(created.GetRuleId())
	model.Priority = types.Int64Value(created.GetRulePriority())

	read, response, err := apiClient.AccessRulesAPI.GetRule(ctx, model.ID.ValueInt64()).Execute()
	require.NoError(t, err)
	_ = response.Body.Close()
	state := model
	readDiags := flattenAccessPolicyResponse(ctx, read, &state)
	require.False(t, readDiags.HasError(), "%v", readDiags)
	require.False(t, hasChanges(&model, &state))

	model.Action = types.StringValue("block")
	model.Description = types.StringValue("updated mock lifecycle")
	putPayload, putDiags := formatPutAccessPolicyRequest(ctx, &model)
	require.False(t, putDiags.HasError(), "%v", putDiags)
	_, response, err = apiClient.AccessRulesAPI.PutRule(ctx, model.ID.ValueInt64()).PutRuleRequest(putPayload).Execute()
	require.NoError(t, err)
	_ = response.Body.Close()

	read, response, err = apiClient.AccessRulesAPI.GetRule(ctx, model.ID.ValueInt64()).Execute()
	require.NoError(t, err)
	_ = response.Body.Close()
	readDiags = flattenAccessPolicyResponse(ctx, read, &state)
	require.False(t, readDiags.HasError(), "%v", readDiags)
	require.False(t, hasChanges(&model, &state))

	response, err = apiClient.AccessRulesAPI.DeleteRule(ctx, model.ID.ValueInt64()).Execute()
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	_ = response.Body.Close()
	require.Equal(t, 5, requestCount)
}

func TestAccessPolicyCreateRetryAndErrors(t *testing.T) {
	payload := *rules.NewAddRuleRequest("tfAcc-mock-retry", rules.RULEACTION_ALLOW, []rules.RuleConditionsInner{}, []rules.RuleSettingsInner{})

	t.Run("conflict then success", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			attempts++
			writer.Header().Set("Content-Type", "application/json")
			if attempts == 1 {
				writer.WriteHeader(http.StatusConflict)
				_, _ = writer.Write([]byte(`{"statusCode":409,"error":"Conflict","message":"priority changed"}`))
				return
			}
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"ruleId":901,"ruleName":"tfAcc-mock-retry","ruleAction":"allow","rulePriority":10,"ruleIsEnabled":false}`))
		}))
		defer server.Close()

		providerResource := accessPolicyResource{
			client:              *testRulesAPIClient(server),
			createRetryDelay:    time.Millisecond,
			createRetryAttempts: 2,
		}
		created, status, err := providerResource.createAccessPolicy(context.Background(), payload)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, status)
		require.Equal(t, int64(901), created.GetRuleId())
		require.Equal(t, 2, attempts)
	})

	tests := []struct {
		name       string
		status     int
		body       string
		wantStatus int
	}{
		{name: "authorization", status: http.StatusUnauthorized, body: `{"statusCode":401,"error":"Unauthorized","message":"denied"}`, wantStatus: http.StatusUnauthorized},
		{name: "malformed success", status: http.StatusCreated, body: `{"ruleId":`, wantStatus: http.StatusCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				attempts++
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			providerResource := accessPolicyResource{
				client:              *testRulesAPIClient(server),
				createRetryDelay:    time.Millisecond,
				createRetryAttempts: 2,
			}
			created, status, err := providerResource.createAccessPolicy(context.Background(), payload)
			require.Error(t, err)
			require.Nil(t, created)
			require.Equal(t, test.wantStatus, status)
			require.Equal(t, 1, attempts)
		})
	}
}

func TestAccessPolicySDKErrorStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(`{"statusCode":404,"error":"Not Found","message":"missing"}`))
		case http.MethodPut:
			writer.WriteHeader(http.StatusConflict)
			_, _ = writer.Write([]byte(`{"statusCode":409,"error":"Conflict","message":"priority changed"}`))
		case http.MethodDelete:
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write([]byte(`{"statusCode":500,"error":"Internal Server Error","message":"failed"}`))
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	apiClient := testRulesAPIClient(server)
	_, response, err := apiClient.AccessRulesAPI.GetRule(context.Background(), 404).Execute()
	require.Error(t, err)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	_ = response.Body.Close()

	putPayload := *rules.NewPutRuleRequest("mock", rules.RULEACTION_ALLOW, 1, []rules.RuleConditionsInner{}, []rules.RuleSettingsInner{})
	_, response, err = apiClient.AccessRulesAPI.PutRule(context.Background(), 901).PutRuleRequest(putPayload).Execute()
	require.Error(t, err)
	require.Equal(t, http.StatusConflict, response.StatusCode)
	_ = response.Body.Close()

	response, err = apiClient.AccessRulesAPI.DeleteRule(context.Background(), 901).Execute()
	require.Error(t, err)
	require.Equal(t, http.StatusInternalServerError, response.StatusCode)
	_ = response.Body.Close()
}

func mockRuleFromRequest(id, priority int64, name string, description *string, action rules.RuleAction, enabled *bool, conditions []rules.RuleConditionsInner, settings []rules.RuleSettingsInner) *rules.Rule {
	responseSettings := make([]rules.SettingResponseInner, 0, len(settings))
	for _, setting := range settings {
		responseSettings = append(responseSettings, rules.SettingResponseInner{
			SettingName:  setting.SettingName,
			SettingValue: setting.SettingValue,
		})
	}
	return &rules.Rule{
		RuleId:          &id,
		RuleName:        &name,
		RuleDescription: description,
		RuleAction:      &action,
		RulePriority:    &priority,
		RuleIsEnabled:   enabled,
		RuleConditions:  conditions,
		RuleSettings:    responseSettings,
	}
}

func TestFlattenAccessPolicyRejectsUnsupportedFields(t *testing.T) {
	ctx := context.Background()
	name := rules.AttributeNameDestination("umbrella.destination.networkObjectIds")
	ids := []int64{1}
	operator := rules.ATTRIBUTEOPERATOR_INTERSECT
	conditions := []rules.RuleConditionsInner{{
		AttributeName:     &rules.AttributeName{AttributeNameDestination: &name},
		AttributeValue:    pointerAttributeValue(rules.ArrayOfInt64AsAttributeValue(&ids)),
		AttributeOperator: &operator,
	}}
	var model accessPolicyResourceModel
	diags := flattenAccessPolicyConditions(ctx, conditions, &model)
	require.True(t, diags.HasError())
	require.Contains(t, diags.Errors()[0].Summary(), "Unsupported access policy destination condition")
}

func TestParseAccessPolicyID(t *testing.T) {
	id, err := parseAccessPolicyID(" 12345 ")
	require.NoError(t, err)
	require.Equal(t, int64(12345), id)

	for _, value := range []string{"", "0", "-1", "abc"} {
		_, err := parseAccessPolicyID(value)
		require.Error(t, err, value)
	}
}

func TestAccessPolicySchemaIncludesMigrationAttributes(t *testing.T) {
	var response fwresource.SchemaResponse
	(&accessPolicyResource{}).Schema(context.Background(), fwresource.SchemaRequest{}, &response)
	require.False(t, response.Diagnostics.HasError(), "%v", response.Diagnostics)

	for _, name := range []string{
		"source_all", "source_identity_type_ids", "application_ids", "application_list_ids",
		"category_ids", "private_resource_group_ids", "inline_destinations",
		"allow_password_protected_files", "advanced_application_ids", "web_profile_id",
		"ips_profile_id", "private_security_profile_id", "tenant_control_profile_id",
	} {
		require.Contains(t, response.Schema.Attributes, name)
	}
}

func TestValidAccessPolicyPort(t *testing.T) {
	for _, value := range []string{"0", "53", "65535", "0-65535", "33434-33598"} {
		require.True(t, validAccessPolicyPort(value), value)
	}
	for _, value := range []string{"", "-1", "65536", "80-1", "one", "1-2-3"} {
		require.False(t, validAccessPolicyPort(value), value)
	}
}

func accessPolicyConditionName(t *testing.T, condition rules.RuleConditionsInner) string {
	t.Helper()
	require.NotNil(t, condition.AttributeName)
	if condition.AttributeName.AttributeNameDestination != nil {
		return string(*condition.AttributeName.AttributeNameDestination)
	}
	if condition.AttributeName.AttributeNameSource != nil {
		return string(*condition.AttributeName.AttributeNameSource)
	}
	t.Fatal("condition does not contain a supported attribute name")
	return ""
}

func mustInt64Set(t *testing.T, ctx context.Context, values ...int64) types.Set {
	t.Helper()
	set, diags := types.SetValueFrom(ctx, types.Int64Type, values)
	require.False(t, diags.HasError(), "building int64 set: %v", diags)
	return set
}

func pointerAttributeValue(value rules.AttributeValue) *rules.AttributeValue {
	return &value
}
