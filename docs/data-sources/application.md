---
page_title: "ciscosecureaccess_application Data Source - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Looks up an application in the Cisco Secure Access application catalog by exact name and type.
---

# ciscosecureaccess_application (Data Source)

Looks up an application by exact name and type. Application IDs can overlap between the AVC and NBAR catalogs, so use `catalog_key` when a type-qualified identifier is required.

## Example Usage

```terraform
data "ciscosecureaccess_application" "slack" {
  name = "Slack"
  type = "AVC"
}

output "slack_application_key" {
  value = data.ciscosecureaccess_application.slack.catalog_key
}
```

## Schema

### Required

- `name` (String) Exact application name.
- `type` (String) Application catalog type. Valid values are `AVC` and `NBAR`.

### Read-Only

- `catalog_key` (String) Stable provider key composed as `type:id`.
- `category_id` (Number) Application category ID, when supplied by the API.
- `category_name` (String) Application category name, when supplied by the API.
- `id` (Number) Application ID. IDs are unique only within an application type.
