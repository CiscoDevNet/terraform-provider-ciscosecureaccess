terraform {
  required_version = "~> 1.1"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.67.0"
    }
    ciscosecureaccess = {
      source  = "github.com/cisco/ciscosecureaccess"
      version = "~> 0.0.1"
    }
  }
}

provider "ciscosecureaccess" {
}

data "ciscosecureaccess_resource_connector" "groups" {
    filter =  {
        name = "name"
        query = "CONNECTOR_GROUP_NAME" //replace with the name of your resource connector group
    }
    lifecycle {
      postcondition {
        condition = timecmp(self.resource_connector_groups[0].key_expires_at, plantimestamp()) > 0
        error_message = "Connector Group has an expired provisioning key"
      }

      postcondition {
        condition = length(self.resource_connector_groups) != 0
        error_message = "Connector Group could not be found, or matched multiple groups"
      }
    }
}


data "aws_ami" "image" {
  owners      = "679593333241"
  most_recent = true

  filter {
    name   = "name"
    values = ["resource-connector-uefi_sb*"]
  }
}

data "aws_subnet" "aca_public" {
  tags = {
    Name = "connector_agent_subnet" // Replace with the name of your subnet
  }
}

# Create an Resource Connector Instance
resource "aws_instance" "ResourceConnector" {
  ami      = data.aws_ami.image.id  # Cisco Secure Access Resource Connector image
  instance_type = "c5.xlarge"
  subnet_id = var.subnet
  vpc_security_group_ids =  [resource.aws_security_group.rca_ssh_sg.id]
  associate_public_ip_address = true

  user_data = base64encode(<<-EOF
              KEY=${data.ciscosecureaccess_resource_connector.groups.resource_connector_groups[0].provisioning_key}
              EOF
  )
  key_name               = "SSH_KEY_NAME" // replace with the name of the SSH Key in AWS
}

data "aws_vpc" "target" {
  filter {
    name   = "tag:Name"
    values = ["VPC_NAME"]  // replace with the name of your VPC
  }}


resource "aws_security_group" "rca_ssh_sg" {
  name        = "Resource_connector_acces"
  description = "SSH Access"
  vpc_id      = data.aws_vpc.target[0].id

  egress {
    cidr_blocks = ["0.0.0.0/0"]
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
  }

}

resource "ciscosecureaccess_resource_connector_agent" "aws_rca" {
    instance_id = resource.aws_instance.ResourceConnector.id
    confirmed = true
    enabled = true
}
