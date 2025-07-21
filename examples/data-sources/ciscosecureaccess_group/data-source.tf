# A list of identities that match the string "devengineer"
data "ciscosecureaccess_group" "test_groups" {
  filter = "TestGroup1"
}

output "group_out" {
  value = [for s in data.ciscosecureaccess_group.test_groups.groups : s.label]
}
