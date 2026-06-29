---
page_title: "ciscosecureaccess_access_policy Resource - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Manages a Cisco Secure Access unified access-policy rule.
---

# ciscosecureaccess_access_policy (Resource)

Manages a private or public unified access-policy rule. Rules can be created with `allow`, `block`, or `warn` actions.

Use catalog data sources and managed dependency resources to resolve target-organization IDs. `source_identity_type_ids` is available for identity types not represented by the friendly `source_types` values; do not copy source-organization identity IDs without validating their target equivalents.

Omitting `ips_profile_id` preserves the service's default IPS behavior. This resource does not manage IPS signatures or signature catalogs.

Rule priorities are organization-wide and the API shifts neighboring rules when a rule is inserted or moved. For generated policy sets, omit `priority` and use an explicit Terraform dependency chain in source-policy order; the API then assigns stable contiguous priorities before the default rules. Configure `priority` only when intentionally reordering a rule, and update every affected managed rule in the same reviewed change.

## Example Usage

```terraform
data "ciscosecureaccess_application" "slack" {
  name = "Slack"
  type = "AVC"
}

resource "ciscosecureaccess_access_policy" "warn_slack" {
  name         = "Warn for Slack access"
  description  = "Disabled example public access rule"
  action       = "warn"
  enabled      = false
  log_level    = "LOG_ALL"
  traffic_type = "PUBLIC_INTERNET"

  source_all      = true
  application_ids = [data.ciscosecureaccess_application.slack.id]
}

resource "ciscosecureaccess_access_policy" "dns" {
  name         = "Allow approved DNS resolvers"
  action       = "allow"
  enabled      = false
  traffic_type = "PUBLIC_INTERNET"

  source_types = ["networks"]

  inline_destinations = [{
    ip_addresses = ["8.8.8.8", "8.8.4.4"]
    ports        = ["53"]
    protocol     = "UDP"
  }]
}
```

## Schema

### Required

- `name` (String) Name of the access policy.

### Optional

- `action` (String) Action taken on matching traffic: `allow`, `block`, or `warn`. Defaults to `block`.
- `advanced_application_ids` (Set of Number) Advanced application IDs.
- `allow_password_protected_files` (Boolean) Whether password-protected files are allowed.
- `application_ids` (Set of Number) Application IDs.
- `application_list_ids` (Set of Number) Application-list IDs.
- `category_ids` (Set of Number) Web/content category IDs.
- `client_posture_profile_id` (Number) Client-based posture profile ID.
- `content_category_list_ids` (Set of Number) Content-category-list IDs.
- `description` (String) Description of the access policy.
- `destination_list_ids` (Set of Number) Destination-list IDs.
- `enabled` (Boolean) Whether the rule is enabled. Defaults to `false`.
- `inline_destinations` (Set of Object) Inline IP, port, and protocol destinations. See nested schema below.
- `ips_profile_id` (Number) IPS profile ID. Omit this attribute to use the service default IPS behavior.
- `log_level` (String) Logging level: `LOG_ALL`, `LOG_SECURITY`, or `LOG_NONE`.
- `priority` (Number) Policy evaluation priority.
- `private_destination_types` (Set of String) Friendly private destination types. Currently supports `private_apps`.
- `private_resource_group_ids` (Set of Number) Private-resource-group IDs.
- `private_resource_ids` (Set of Number) Private-resource IDs.
- `private_security_profile_id` (Number) Private security profile ID.
- `public_destination_types` (Set of String) Friendly public destination types. Currently supports `internet`.
- `source_all` (Boolean) Match all sources. Do not combine with other source attributes.
- `source_identity_type_ids` (Set of Number) Raw identity-type IDs for types not represented by `source_types`.
- `source_ids` (Set of Number) Source identity IDs.
- `source_types` (Set of String) Friendly source types: `directory_users` or `networks`.
- `tenant_control_profile_id` (Number) Tenant-control profile ID.
- `traffic_type` (String) Traffic scope: `PRIVATE_NETWORK` or `PUBLIC_INTERNET`.
- `web_profile_id` (Number) Web security profile ID.

### Read-Only

- `id` (Number) Unique ID of the access policy.

### Nested Schema for `inline_destinations`

Required:

- `ip_addresses` (Set of String) IP addresses or CIDR prefixes.
- `ports` (Set of String) Ports or inclusive ranges from `0` through `65535`.
- `protocol` (String) `ANY`, `ICMP`, `TCP`, or `UDP`.

## Import

Import an access policy with its numeric rule ID:

```shell
terraform import ciscosecureaccess_access_policy.example 12345
```
