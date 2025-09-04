// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type Filter struct {
	Name  types.String `tfsdk:"name"`
	Query types.String `tfsdk:"query"`
}

func FilterSchema() schema.NestedAttributeObject {
	return schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
			},
			"query": schema.StringAttribute{
				Required: true,
			},
		},
	}
}

func (f *Filter) BuildQueryFilters() (string, error) {
	filterMap := map[string]string{f.Name.String(): f.Query.String()}
	filterObject, err := json.Marshal(filterMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal filter map for query '%s': %w", f.Query.String(), err)
	}
	return string(filterObject), nil
}
