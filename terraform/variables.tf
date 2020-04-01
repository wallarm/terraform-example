
variable "aws_region" {
  type    = string
  default = "us-west-1"
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

variable "az_a" {
  type    = string
  default = "us-west-1a"
}

variable "subnet_a_cidr_block" {
  type    = string
  default = "10.0.0.0/24"
}

variable "az_b" {
  type    = string
  default = "us-west-1b"
}

variable "subnet_b_cidr_block" {
  type    = string
  default = "10.0.1.0/24"
}

variable "wordpress_ami_id" {
  type    = string
  default = "ami-01fdd34f40bd2aa03"
}

variable "wordpress_instance_type" {
  type    = string
  default = "t2.micro"
}

variable "wallarm_node_ami_id" {
  type    = string
  default = "ami-014f1ebb1ec68b935"
}

variable "waf_node_instance_type" {
  type    = string
  default = "t2.micro"
}

variable "deploy_username" {
  type = string
}

variable "deploy_password" {
  type = string
}

variable "wallarm_api_domain" {
  type    = string
  default = "us1.api.wallarm.com"
}

variable "key_pair" {
  type    = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8atMagzg7zjItkZj0BuJi8xj4fuoNF9FWbP/XjBb/RCHrvgwXhtMp1b6cLtsyeeVwPJw/GCpDlQp46h0Da/PfGKefrCGHvaDtOqj56LlyR7bYYki4FoGDRyaKi+5DysFgL9e4hnjSaqNTvnneui/hQpvCK2O1FcSZBGMZuoPOEvQy/vw3FgRTTUarX03wWWn8f1v6+D4+lB+yXH0HzL3QzlHe/LXwIlbs5S2pXd5r9ZLzCe2SGP46hTxMv3eQk22UgRkxHkJ6dT/MmmNamvRNyrQP7p38RJ5TlJuW+Bu2hrdIdXIlOCXp25A4HjKCuCx0BQlkI6PA9OodX9uQxqLv demo@wallarm.com"
}

