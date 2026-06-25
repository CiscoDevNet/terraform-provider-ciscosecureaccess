// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExpandStringList_null(t *testing.T) {
	result := expandStringList(context.Background(), types.ListNull(types.StringType))
	if result != nil {
		t.Errorf("expected nil for null list, got %v", result)
	}
}

func TestExpandStringList_unknown(t *testing.T) {
	result := expandStringList(context.Background(), types.ListUnknown(types.StringType))
	if result != nil {
		t.Errorf("expected nil for unknown list, got %v", result)
	}
}

func TestExpandStringList_empty(t *testing.T) {
	list, _ := types.ListValue(types.StringType, []attr.Value{})
	result := expandStringList(context.Background(), list)
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestExpandStringList_values(t *testing.T) {
	list, _ := types.ListValue(types.StringType, []attr.Value{
		types.StringValue("10.0.0.1"),
		types.StringValue("10.0.0.2"),
		types.StringValue("10.0.0.3"),
	})
	result := expandStringList(context.Background(), list)
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, want := range expected {
		if result[i] != want {
			t.Errorf("index %d: got %q, want %q", i, result[i], want)
		}
	}
}

func TestFlattenStringList_nil(t *testing.T) {
	result := flattenStringList(nil)
	if result.IsNull() {
		t.Error("expected non-null list (empty)")
	}
	if len(result.Elements()) != 0 {
		t.Errorf("expected 0 elements, got %d", len(result.Elements()))
	}
}

func TestFlattenStringList_empty(t *testing.T) {
	result := flattenStringList([]string{})
	if len(result.Elements()) != 0 {
		t.Errorf("expected 0 elements, got %d", len(result.Elements()))
	}
}

func TestFlattenStringList_values(t *testing.T) {
	result := flattenStringList([]string{"a", "b", "c"})
	elems := result.Elements()
	if len(elems) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(elems))
	}
	for i, want := range []string{"a", "b", "c"} {
		sv, ok := elems[i].(types.String)
		if !ok {
			t.Fatalf("element %d is not types.String", i)
		}
		if sv.ValueString() != want {
			t.Errorf("element %d: got %q, want %q", i, sv.ValueString(), want)
		}
	}
}
