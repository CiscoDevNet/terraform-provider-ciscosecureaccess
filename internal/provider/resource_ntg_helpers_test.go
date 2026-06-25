// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestCompareStringSlicesAsSets_equal(t *testing.T) {
	tests := []struct {
		name string
		a    []basetypes.StringValue
		b    []basetypes.StringValue
		want bool
	}{
		{
			name: "both empty",
			a:    []basetypes.StringValue{},
			b:    []basetypes.StringValue{},
			want: true,
		},
		{
			name: "same order",
			a:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			b:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			want: true,
		},
		{
			name: "different order",
			a:    []basetypes.StringValue{types.StringValue("10.0.1.0/24"), types.StringValue("10.0.0.0/24")},
			b:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			want: true,
		},
		{
			name: "different lengths",
			a:    []basetypes.StringValue{types.StringValue("10.0.0.0/24")},
			b:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			want: false,
		},
		{
			name: "same length different values",
			a:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			b:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.2.0/24")},
			want: false,
		},
		{
			name: "duplicates in a",
			a:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.0.0/24")},
			b:    []basetypes.StringValue{types.StringValue("10.0.0.0/24"), types.StringValue("10.0.1.0/24")},
			want: false,
		},
		{
			name: "single element equal",
			a:    []basetypes.StringValue{types.StringValue("192.168.0.0/16")},
			b:    []basetypes.StringValue{types.StringValue("192.168.0.0/16")},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareStringSlicesAsSets(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareStringSlicesAsSets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertNetworkCidrsToStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []types.String
		want  []string
	}{
		{
			name:  "empty slice",
			input: []types.String{},
			want:  []string{},
		},
		{
			name:  "single cidr",
			input: []types.String{types.StringValue("10.0.0.0/24")},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "multiple cidrs",
			input: []types.String{types.StringValue("10.0.0.0/24"), types.StringValue("172.16.0.0/12"), types.StringValue("192.168.0.0/16")},
			want:  []string{"10.0.0.0/24", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertNetworkCidrsToStrings(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestConvertStringsToNetworkCidrs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty slice",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "single cidr",
			input: []string{"10.0.0.0/24"},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "multiple cidrs",
			input: []string{"10.0.0.0/24", "172.16.0.0/12"},
			want:  []string{"10.0.0.0/24", "172.16.0.0/12"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertStringsToNetworkCidrs(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].ValueString() != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i].ValueString(), tt.want[i])
				}
			}
		})
	}
}
