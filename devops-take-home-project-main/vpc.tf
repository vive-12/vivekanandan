module "label_vpc" {
  source     = "cloudposse/label/null"
  version    = "0.25.0"
  context    = module.base_label.context
  name       = "vpc"
  attributes = ["main"]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = module.label_vpc.tags
}


module "label_public_subnet" {
  source     = "cloudposse/label/null"
  version    = "0.25.0"
  context    = module.label_vpc.context
  name       = "public_subnet"
  attributes = ["main"]
}

module "label_private_subnet" {
  source     = "cloudposse/label/null"
  version    = "0.25.0"
  context    = module.label_vpc.context
  name       = "private_subnet"
  attributes = ["main"]
}



# =========================
# Create your subnets here
# =========================

resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 0) # Generates a /24 subnet
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = module.label_public_subnet.tags
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 1) # Generates a /24 subnet
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = module.label_private_subnet.tags
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = module.label_vpc.tags
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = module.label_vpc.tags
}

resource "aws_route_table_association" "public_route_table_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

data "aws_availability_zones" "available" {
  state = "available"
}
