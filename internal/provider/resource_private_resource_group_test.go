// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/privateapps"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExpandPrivateResourceGroupRequest(t *testing.T) {
	ctx := context.Background()
	resourceIDs, diags := types.SetValueFrom(ctx, types.Int64Type, []int64{9, 2, 5})
	if diags.HasError() {
		t.Fatalf("failed to create test resource IDs: %v", diags)
	}

	model := privateResourceGroupModel{
		Name:        types.StringValue("Engineering Apps"),
		Description: types.StringValue("Internal applications"),
		ResourceIDs: resourceIDs,
	}

	payload, diags := expandPrivateResourceGroupRequest(ctx, &model)
	if diags.HasError() {
		t.Fatalf("expand returned diagnostics: %v", diags)
	}

	if payload.Name != "Engineering Apps" {
		t.Fatalf("name = %q, want %q", payload.Name, "Engineering Apps")
	}
	if payload.Description == nil || *payload.Description != "Internal applications" {
		t.Fatalf("description = %v, want Internal applications", payload.Description)
	}
	if !reflect.DeepEqual(payload.ResourceIds, []int64{2, 5, 9}) {
		t.Fatalf("resourceIds = %v, want [2 5 9]", payload.ResourceIds)
	}
}

func TestExpandPrivateResourceGroupRequestEmptyMembership(t *testing.T) {
	ctx := context.Background()
	resourceIDs, diags := types.SetValueFrom(ctx, types.Int64Type, []int64{})
	if diags.HasError() {
		t.Fatalf("failed to create empty resource ID set: %v", diags)
	}

	model := privateResourceGroupModel{
		Name:        types.StringValue("Empty Group"),
		Description: types.StringNull(),
		ResourceIDs: resourceIDs,
	}
	payload, diags := expandPrivateResourceGroupRequest(ctx, &model)
	if diags.HasError() {
		t.Fatalf("expand returned diagnostics: %v", diags)
	}
	if payload.Description != nil {
		t.Fatalf("description = %v, want nil", payload.Description)
	}
	if payload.ResourceIds == nil || len(payload.ResourceIds) != 0 {
		t.Fatalf("resourceIds = %#v, want a non-nil empty slice", payload.ResourceIds)
	}
}

func TestFlattenPrivateResourceGroupResponse(t *testing.T) {
	ctx := context.Background()
	id := int64(101)
	name := "Engineering Apps"
	description := "Internal applications"
	createdAt := time.Date(2026, time.June, 1, 10, 30, 0, 0, time.FixedZone("EDT", -4*60*60))
	modifiedAt := createdAt.Add(2 * time.Hour)
	group := &privateapps.PrivateResourceGroupResponse{
		ResourceGroupId: &id,
		Name:            &name,
		Description:     &description,
		ResourceIds:     []int64{9, 2},
		CreatedAt:       &createdAt,
		ModifiedAt:      &modifiedAt,
	}

	var model privateResourceGroupModel
	diags := flattenPrivateResourceGroupResponse(ctx, group, &model)
	if diags.HasError() {
		t.Fatalf("flatten returned diagnostics: %v", diags)
	}

	if model.ID.ValueInt64() != 101 || model.Name.ValueString() != name {
		t.Fatalf("flattened identity = (%d, %q), want (101, %q)", model.ID.ValueInt64(), model.Name.ValueString(), name)
	}
	if model.Description.ValueString() != description {
		t.Fatalf("description = %q, want %q", model.Description.ValueString(), description)
	}
	if model.CreatedAt.ValueString() != "2026-06-01T14:30:00Z" {
		t.Fatalf("created_at = %q, want UTC RFC3339", model.CreatedAt.ValueString())
	}
	if model.ModifiedAt.ValueString() != "2026-06-01T16:30:00Z" {
		t.Fatalf("modified_at = %q, want UTC RFC3339", model.ModifiedAt.ValueString())
	}

	var gotResourceIDs []int64
	diags = model.ResourceIDs.ElementsAs(ctx, &gotResourceIDs, false)
	if diags.HasError() {
		t.Fatalf("failed to read resource IDs from state: %v", diags)
	}
	sort.Slice(gotResourceIDs, func(i, j int) bool { return gotResourceIDs[i] < gotResourceIDs[j] })
	if !reflect.DeepEqual(gotResourceIDs, []int64{2, 9}) {
		t.Fatalf("resource_ids = %v, want [2 9]", gotResourceIDs)
	}
}

func TestFlattenPrivateResourceGroupResponseEmptyMembership(t *testing.T) {
	ctx := context.Background()
	id := int64(102)
	name := "Empty Group"
	group := &privateapps.PrivateResourceGroupResponse{ResourceGroupId: &id, Name: &name, ResourceIds: []int64{}}

	var model privateResourceGroupModel
	diags := flattenPrivateResourceGroupResponse(ctx, group, &model)
	if diags.HasError() {
		t.Fatalf("flatten returned diagnostics: %v", diags)
	}
	if model.ResourceIDs.IsNull() || model.ResourceIDs.IsUnknown() || len(model.ResourceIDs.Elements()) != 0 {
		t.Fatalf("resource_ids = %v, want a known empty set", model.ResourceIDs)
	}
	if !model.Description.IsNull() || !model.CreatedAt.IsNull() || !model.ModifiedAt.IsNull() {
		t.Fatal("omitted optional response fields must flatten to null")
	}
}

func TestParsePrivateResourceGroupID(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int64
		wantErr bool
	}{
		{name: "valid", value: "123", want: 123},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "not numeric", value: "group-name", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePrivateResourceGroupID(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePrivateResourceGroupID(%q) returned no error", tt.value)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("parsePrivateResourceGroupID(%q) = (%d, %v), want (%d, nil)", tt.value, got, err, tt.want)
			}
		})
	}
}

func TestPrivateResourceGroupSDKLifecycle(t *testing.T) {
	ctx := context.Background()
	group := privateapps.PrivateResourceGroupResponse{}
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")

		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/privateResourceGroups":
			var payload privateapps.PrivateResourceGroupRequest
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Errorf("decode create payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !reflect.DeepEqual(payload.ResourceIds, []int64{2, 9}) {
				t.Errorf("create resourceIds = %v, want [2 9]", payload.ResourceIds)
			}
			id := int64(101)
			name := payload.Name
			group = privateapps.PrivateResourceGroupResponse{ResourceGroupId: &id, Name: &name, Description: payload.Description, ResourceIds: payload.ResourceIds}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]int64{"resourceGroupId": id})

		case req.Method == http.MethodGet && req.URL.Path == "/privateResourceGroups/101":
			_ = json.NewEncoder(w).Encode(group)

		case req.Method == http.MethodPut && req.URL.Path == "/privateResourceGroups/101":
			var payload privateapps.PrivateResourceGroupRequest
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Errorf("decode update payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			group.Name = &payload.Name
			group.Description = payload.Description
			group.ResourceIds = payload.ResourceIds
			w.WriteHeader(http.StatusNoContent)

		case req.Method == http.MethodDelete && req.URL.Path == "/privateResourceGroups/101":
			if req.URL.Query().Get("force") != "false" {
				t.Errorf("delete force = %q, want false", req.URL.Query().Get("force"))
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	configuration := privateapps.NewConfiguration()
	configuration.Servers[0].URL = server.URL
	configuration.HTTPClient = server.Client()
	providerResource := &privateResourceGroupResource{client: *privateapps.NewAPIClient(configuration)}

	description := "Initial description"
	createPayload := *privateapps.NewPrivateResourceGroupRequest("Engineering Apps", []int64{2, 9})
	createPayload.Description = &description
	created, status, err := providerResource.createPrivateResourceGroup(ctx, createPayload)
	if err != nil || status != http.StatusCreated || created.GetResourceGroupId() != 101 {
		t.Fatalf("create = (%v, %d, %v), want ID 101 and HTTP 201", created, status, err)
	}

	read, status, err := providerResource.getPrivateResourceGroup(ctx, 101)
	if err != nil || status != http.StatusOK || read.GetName() != "Engineering Apps" {
		t.Fatalf("read = (%v, %d, %v), want Engineering Apps and HTTP 200", read, status, err)
	}

	updatedDescription := "Updated description"
	updatePayload := *privateapps.NewPrivateResourceGroupRequest("Engineering Group", []int64{})
	updatePayload.Description = &updatedDescription
	_, status, err = providerResource.updatePrivateResourceGroup(ctx, 101, updatePayload)
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("update = (%d, %v), want HTTP 204", status, err)
	}
	updated, status, err := providerResource.getPrivateResourceGroup(ctx, 101)
	if err != nil || status != http.StatusOK || updated.GetName() != "Engineering Group" || len(updated.ResourceIds) != 0 {
		t.Fatalf("updated read = (%v, %d, %v), want updated empty group and HTTP 200", updated, status, err)
	}

	status, err = providerResource.deletePrivateResourceGroup(ctx, 101)
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("delete = (%d, %v), want HTTP 204", status, err)
	}
	if requestCount != 5 {
		t.Fatalf("request count = %d, want 5", requestCount)
	}
}

func TestPrivateResourceGroupSDKErrorStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		case http.MethodDelete:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "group is referenced"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	configuration := privateapps.NewConfiguration()
	configuration.Servers[0].URL = server.URL
	configuration.HTTPClient = server.Client()
	providerResource := &privateResourceGroupResource{client: *privateapps.NewAPIClient(configuration)}

	_, status, err := providerResource.getPrivateResourceGroup(context.Background(), 404)
	if err == nil || status != http.StatusNotFound {
		t.Fatalf("get error = (%d, %v), want HTTP 404 error", status, err)
	}

	status, err = providerResource.deletePrivateResourceGroup(context.Background(), 101)
	if err == nil || status != http.StatusBadRequest {
		t.Fatalf("delete error = (%d, %v), want HTTP 400 error", status, err)
	}
}
