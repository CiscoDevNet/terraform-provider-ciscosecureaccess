# Look up content category lists by partial name match
data "ciscosecureaccess_content_category_list" "restrictive" {
  filter = "Restrictive"
}

output "restrictive_content_category_ids" {
  value = [for c in data.ciscosecureaccess_content_category_list.restrictive.content_category_lists : c.id]
}

# Attach a content category list to an access policy
resource "ciscosecureaccess_access_policy" "internal_block" {
  name         = "internal_block"
  action       = "block"
  enabled      = true
  priority     = 4
  log_level    = "LOG_ALL"
  traffic_type = "PUBLIC_INTERNET"
  source_types = ["networks"]
  source_ids   = []
  content_category_list_ids = [
    for c in data.ciscosecureaccess_content_category_list.restrictive.content_category_lists : c.id
  ]
  description = "Block restrictive content categories"
}
