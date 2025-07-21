package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// DefaultValue return a string plan modifier that sets the specified value if the planned value is Null.
func StringDefaultValue(s string) planmodifier.String {
	return stringDefaultValue{
		val: s,
	}
}

// stringDefaultValue holds our default value and allows us to implement the `planmodifier.String` interface
type stringDefaultValue struct {
	val string
}

// Description implements the `planmodifier.String` interface
func (m stringDefaultValue) Description(context.Context) string {
	return fmt.Sprintf("If value is not configured, defaults to %s", m.val)
}

// MarkdownDescription implements the `planmodifier.String` interface
func (m stringDefaultValue) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx) // reuse our plaintext Description
}

// PlanModifyString implements the `planmodifier.String` interface
func (m stringDefaultValue) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the attribute configuration is not null it is explicit; we should apply the planned value.
	if !req.ConfigValue.IsNull() {
		return
	}

	// Otherwise, the configuration is null, so apply the default value to the response.
	resp.PlanValue = types.StringValue(m.val)
}
