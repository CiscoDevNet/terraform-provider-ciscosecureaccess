// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandApplicationListRequest(t *testing.T) {
	model := applicationListResourceModel{
		Name:                   types.StringValue("Engineering Apps"),
		ApplicationIDs:         types.SetValueMust(types.Int64Type, []attr.Value{types.Int64Value(40), types.Int64Value(12)}),
		ApplicationCategoryIDs: types.SetValueMust(types.Int64Type, []attr.Value{types.Int64Value(33), types.Int64Value(9)}),
	}

	payload, diags := expandApplicationListRequest(context.Background(), &model)
	require.False(t, diags.HasError(), diags.Errors())
	assert.Equal(t, "Engineering Apps", payload.ApplicationListName)
	assert.False(t, payload.IsDefault)
	assert.Equal(t, []int64{12, 40}, payload.ApplicationIds)
	assert.Equal(t, []int64{9, 33}, payload.ApplicationCategoryIds)
}

func TestExpandApplicationListRequestNullSets(t *testing.T) {
	model := applicationListResourceModel{
		Name:                   types.StringValue("Empty"),
		ApplicationIDs:         types.SetNull(types.Int64Type),
		ApplicationCategoryIDs: types.SetNull(types.Int64Type),
	}

	payload, diags := expandApplicationListRequest(context.Background(), &model)
	require.False(t, diags.HasError(), diags.Errors())
	assert.Empty(t, payload.ApplicationIds)
	assert.Empty(t, payload.ApplicationCategoryIds)
}

func TestFlattenApplicationListResponse(t *testing.T) {
	name := "Engineering Apps"
	isDefault := false
	createdAt := "2026-06-28T18:00:00Z"
	modifiedAt := "2026-06-28T19:00:00Z"
	model := applicationListResourceModel{
		ID:             types.Int64Value(501),
		OrganizationID: types.Int64Null(),
		CreatedAt:      types.StringUnknown(),
	}
	response := &rules.ApplicationList{
		ApplicationListName:    &name,
		IsDefault:              &isDefault,
		ApplicationIds:         []int64{40, 12},
		ApplicationCategoryIds: nil,
		CreatedAt:              &createdAt,
		ModifiedAt:             &modifiedAt,
		AdditionalProperties: map[string]interface{}{
			"organizationId": float64(8376136),
		},
	}

	diags := flattenApplicationListResponse(context.Background(), response, &model)
	require.False(t, diags.HasError(), diags.Errors())
	assert.Equal(t, int64(8376136), model.OrganizationID.ValueInt64())
	assert.Equal(t, createdAt, model.CreatedAt.ValueString())
	assert.Equal(t, modifiedAt, model.ModifiedAt.ValueString())
	assert.Equal(t, 2, len(model.ApplicationIDs.Elements()))
	assert.Empty(t, model.ApplicationCategoryIDs.Elements())
}

func TestFlattenApplicationListResponseValidation(t *testing.T) {
	model := applicationListResourceModel{ID: types.Int64Null()}
	diags := flattenApplicationListResponse(context.Background(), &rules.ApplicationList{}, &model)
	assert.True(t, diags.HasError())
	assert.Len(t, diags.Errors(), 3)

	diags = flattenApplicationListResponse(context.Background(), nil, &model)
	assert.True(t, diags.HasError())
}

func TestApplicationListIDFromCreateResponse(t *testing.T) {
	applicationList := &rules.ApplicationList{AdditionalProperties: map[string]interface{}{"applicationListId": "901"}}
	assert.Equal(t, int64(901), applicationListIDFromCreateResponse(applicationList, nil))

	response := &http.Response{Header: http.Header{"Location": []string{"https://api.sse.cisco.com/policies/v2/applicationLists/902"}}}
	assert.Equal(t, int64(902), applicationListIDFromCreateResponse(&rules.ApplicationList{}, response))
	assert.Zero(t, applicationListIDFromCreateResponse(&rules.ApplicationList{}, nil))
}

func TestApplicationListAdditionalInt64(t *testing.T) {
	tests := map[string]struct {
		value interface{}
		want  int64
		ok    bool
	}{
		"integer":  {value: int64(10), want: 10, ok: true},
		"float":    {value: float64(11), want: 11, ok: true},
		"string":   {value: "12", want: 12, ok: true},
		"fraction": {value: 1.5, ok: false},
		"invalid":  {value: "abc", ok: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			value, ok := applicationListAdditionalInt64(map[string]interface{}{"id": test.value}, "id")
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, value)
		})
	}
}

func TestParseApplicationListID(t *testing.T) {
	id, err := parseApplicationListID("123")
	require.NoError(t, err)
	assert.Equal(t, int64(123), id)

	for _, value := range []string{"", "abc", "0", "-1"} {
		_, err := parseApplicationListID(value)
		assert.Error(t, err)
	}
}

func TestApplicationListMatchesRequest(t *testing.T) {
	name := "Engineering Apps"
	applicationList := &rules.ApplicationList{
		ApplicationListName:    &name,
		ApplicationIds:         []int64{40, 12},
		ApplicationCategoryIds: []int64{33, 9},
	}
	payload := *rules.NewApplicationListRequest(name, false, []int64{12, 40})
	payload.SetApplicationCategoryIds([]int64{9, 33})
	assert.True(t, applicationListMatchesRequest(applicationList, payload))

	payload.ApplicationIds = []int64{12}
	assert.False(t, applicationListMatchesRequest(applicationList, payload))
}

func TestResolveCreatedApplicationList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/applicationLists":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{
  "count": 1,
  "results": [{
    "applicationListId": 501,
    "applicationListName": "Engineering Apps",
    "organizationId": 8376136,
    "isDefault": false
  }]
}`))
		case "/applicationLists/501":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{
  "applicationListName": "Engineering Apps",
  "isDefault": false,
  "applicationIds": [40, 12],
  "applicationCategoryIds": [33]
}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	apiClient := testRulesAPIClient(server)
	resource := &applicationListResource{client: *apiClient, readAttempts: 1}
	payload := *rules.NewApplicationListRequest("Engineering Apps", false, []int64{12, 40})
	payload.SetApplicationCategoryIds([]int64{33})

	applicationList, summary, err := resource.resolveCreatedApplicationList(context.Background(), payload, 501)
	require.NoError(t, err)
	assert.Equal(t, int64(501), summary.GetApplicationListId())
	assert.Equal(t, "Engineering Apps", applicationList.GetApplicationListName())
	assert.Equal(t, int64(8376136), applicationListOrganizationID(summary.AdditionalProperties).ValueInt64())

	_, _, err = resource.resolveCreatedApplicationList(context.Background(), payload, 999)
	assert.ErrorContains(t, err, "does not match exact-name result")
}

func testRulesAPIClient(server *httptest.Server) *rules.APIClient {
	configuration := rules.NewConfiguration()
	configuration.Servers[0].URL = server.URL
	configuration.HTTPClient = server.Client()
	return rules.NewAPIClient(configuration)
}
