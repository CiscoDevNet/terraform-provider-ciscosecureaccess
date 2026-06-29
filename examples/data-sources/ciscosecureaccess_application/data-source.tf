data "ciscosecureaccess_application" "slack" {
  name = "Slack"
  type = "AVC"
}

output "slack_application_key" {
  value = data.ciscosecureaccess_application.slack.catalog_key
}
