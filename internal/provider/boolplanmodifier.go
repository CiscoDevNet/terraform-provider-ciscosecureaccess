package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// DefaultValue return a bool plan modifier that sets the specified value if the planned value is Null.
func DefaultValue(s bool) planmodifier.Bool {
	return defaultValue{
		val: s,
	}
}

// defaultValue holds our default value and allows us to implement the `planmodifier.Bool` interface
type defaultValue struct {
	val bool
}

// Description implements the `planmodifier.Bool` interface
func (m defaultValue) Description(context.Context) string {
	return fmt.Sprintf("If value is not configured, defaults to %v", m.val)
}

// MarkdownDescription implements the `planmodifier.Bool` interface
func (m defaultValue) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx) // reuse our plaintext Description
}

// PlanModifyBool implements the `planmodifier.Bool` interface
func (m defaultValue) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// If the attribute configuration is not null it is explicit; we should apply the planned value.
	if !req.ConfigValue.IsNull() {
		return
	}

	// Otherwise, the configuration is null, so apply the default value to the response.
	resp.PlanValue = types.BoolValue(m.val)
}
