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
