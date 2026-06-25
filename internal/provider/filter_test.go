// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestBuildQueryFilters_producesValidJSON(t *testing.T) {
	f := &Filter{
		Name:  types.StringValue("name"),
		Query: types.StringValue("test-value"),
	}

	result, err := f.BuildQueryFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{"name":"test-value"}`
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}

func TestBuildQueryFilters_specialCharacters(t *testing.T) {
	f := &Filter{
		Name:  types.StringValue("filter_key"),
		Query: types.StringValue("value with spaces & special <chars>"),
	}

	result, err := f.BuildQueryFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == "" {
		t.Fatal("expected non-empty result")
	}
	if result[0] != '{' || result[len(result)-1] != '}' {
		t.Fatalf("expected JSON object, got %s", result)
	}
}

func TestBuildQueryFilters_emptyValues(t *testing.T) {
	f := &Filter{
		Name:  types.StringValue(""),
		Query: types.StringValue(""),
	}

	result, err := f.BuildQueryFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{"":""}`
	if result != expected {
		t.Fatalf("expected %s, got %s", expected, result)
	}
}
