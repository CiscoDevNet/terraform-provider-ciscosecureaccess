---
page_title: "ciscosecureaccess_application_category Data Source - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Looks up an application category in the Cisco Secure Access application catalog by exact name.
---

# ciscosecureaccess_application_category (Data Source)

Looks up an application category by exact name. Application categories are separate from web content categories.

## Example Usage

```terraform
data "ciscosecureaccess_application_category" "social_networking" {
  name = "Social Networking"
}

output "social_networking_application_category_id" {
  value = data.ciscosecureaccess_application_category.social_networking.id
}
```

## Schema

### Required

- `name` (String) Exact application category name.

### Read-Only

- `id` (Number) Application category ID.
