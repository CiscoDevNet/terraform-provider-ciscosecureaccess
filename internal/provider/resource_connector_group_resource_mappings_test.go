// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"reflect"
	"testing"
)

func TestResourceIDSetOperations(t *testing.T) {
	tests := []struct {
		name string
		got  []int64
		want []int64
	}{
		{
			name: "union preserves unmanaged mappings and removes duplicates",
			got:  unionResourceIDs([]int64{4, 1, 2}, []int64{3, 2}),
			want: []int64{1, 2, 3, 4},
		},
		{
			name: "intersection reports only managed mappings still present",
			got:  intersectResourceIDs([]int64{4, 2, 3}, []int64{1, 2, 4}),
			want: []int64{2, 4},
		},
		{
			name: "subtraction removes only managed mappings",
			got:  subtractResourceIDs([]int64{4, 1, 2, 3}, []int64{2, 4}),
			want: []int64{1, 3},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(test.got, test.want) {
				t.Fatalf("got %v, want %v", test.got, test.want)
			}
		})
	}
}

func TestFormatResourceIDs(t *testing.T) {
	if got, want := formatResourceIDs([]int64{1, 22, 333}), "1,22,333"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSameResourceIDs(t *testing.T) {
	if !sameResourceIDs([]int64{3, 1, 2}, []int64{1, 2, 3}) {
		t.Fatal("expected differently ordered ID lists to match")
	}
	if sameResourceIDs([]int64{1, 2}, []int64{1, 3}) {
		t.Fatal("expected different ID lists not to match")
	}
	if sameResourceIDs([]int64{1, 1}, []int64{1, 1}) {
		t.Fatal("expected duplicate ID lists not to match a set")
	}
	if sameResourceIDs([]int64{1, 2}, []int64{1, 1}) {
		t.Fatal("expected duplicate IDs on the right not to match a set")
	}
}
