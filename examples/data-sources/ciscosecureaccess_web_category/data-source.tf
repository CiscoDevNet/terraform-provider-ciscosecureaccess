data "ciscosecureaccess_web_category" "social_networking" {
  name = "Social Networking"
  type = "content"
}

output "social_networking_web_category_id" {
  value = data.ciscosecureaccess_web_category.social_networking.id
}
