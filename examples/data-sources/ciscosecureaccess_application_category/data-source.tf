data "ciscosecureaccess_application_category" "social_networking" {
  name = "Social Networking"
}

output "social_networking_application_category_id" {
  value = data.ciscosecureaccess_application_category.social_networking.id
}
