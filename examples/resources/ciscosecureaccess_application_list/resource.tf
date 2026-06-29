data "ciscosecureaccess_application" "slack" {
  name = "Slack"
  type = "AVC"
}

data "ciscosecureaccess_application_category" "collaboration" {
  name = "Collaboration"
}

resource "ciscosecureaccess_application_list" "collaboration" {
  name = "Engineering Collaboration Applications"

  application_ids = [
    data.ciscosecureaccess_application.slack.id,
  ]
  application_category_ids = [
    data.ciscosecureaccess_application_category.collaboration.id,
  ]
}
