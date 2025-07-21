resource "ciscosecureaccess_resource_connector_agent" "aws_rca" {
    instance_id = "i-0123456789abdef1" # Instance ID of resource connector in AWS
    confirmed = true
    enabled = true
}
