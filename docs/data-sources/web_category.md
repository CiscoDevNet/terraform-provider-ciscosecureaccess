---
page_title: "ciscosecureaccess_web_category Data Source - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Looks up a web content category in the Cisco Secure Access reporting catalog by exact name.
---

# ciscosecureaccess_web_category (Data Source)

Looks up a web content category by exact name. Set `type` when the same name appears under multiple category types. The `deprecated` field allows migration tooling to reject obsolete categories before generating policy HCL.

## Example Usage

```terraform
data "ciscosecureaccess_web_category" "social_networking" {
  name = "Social Networking"
  type = "content"
}

output "social_networking_web_category_id" {
  value = data.ciscosecureaccess_web_category.social_networking.id
}
```

## Schema

### Required

- `name` (String) Exact web category name.

### Optional

- `type` (String) Category type. Set this when the name is not unique across types.

### Read-Only

- `deprecated` (Boolean) Whether this legacy category is deprecated.
- `id` (Number) Web category ID.
- `integration` (Boolean) Whether this category represents an integration.
- `legacy_id` (Number) Legacy web category ID.
