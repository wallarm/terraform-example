
provider "aws" {
  region = var.aws_region
}

#
# Define a Key Pair to be used for both WP and WAF instances.
#
resource "aws_key_pair" "mykey" {
  key_name   = "tf-wallarm-demo-key"
  public_key = var.key_pair
}

#
# Configure VPC, subnets, routing table and Internet Gateway resources.
#
resource "aws_vpc" "my_vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true
  tags = {
    Name = "tf-wallarm-demo"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = "${aws_vpc.my_vpc.id}"
  cidr_block              = var.subnet_a_cidr_block
  availability_zone       = var.az_a
  map_public_ip_on_launch = true
  tags = {
    Name = "tf-wallarm-demo-subnet-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = "${aws_vpc.my_vpc.id}"
  cidr_block              = var.subnet_b_cidr_block
  availability_zone       = var.az_b
  map_public_ip_on_launch = true
  tags = {
    Name = "tf-wallarm-demo-subnet-b"
  }
}

resource "aws_internet_gateway" "my_vpc_igw" {
  vpc_id = "${aws_vpc.my_vpc.id}"
  tags = {
    Name = "tf-wallarm-demo"
  }
}

resource "aws_route_table" "my_vpc_public" {
  vpc_id = "${aws_vpc.my_vpc.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.my_vpc_igw.id}"
  }
  tags = {
    Name = "tf-wallarm-demo"
  }
}

resource "aws_route_table_association" "my_vpc_a_public" {
  subnet_id      = "${aws_subnet.public_a.id}"
  route_table_id = "${aws_route_table.my_vpc_public.id}"
}

resource "aws_route_table_association" "my_vpc_b_public" {
  subnet_id      = "${aws_subnet.public_b.id}"
  route_table_id = "${aws_route_table.my_vpc_public.id}"
}

#
# Configure SG for Wordpress instances.
#
resource "aws_security_group" "wp_sg" {
  name   = "tf-wallarm-demo-wp"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure SG for Wallarm WAF nodes.
#
resource "aws_security_group" "wallarm_asg_sg" {
  name   = "tf-wallarm-demo-waf-asg"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure SG for Wallarm LB instance.
#
resource "aws_security_group" "wallarm_elb_sg" {
  name   = "tf-wallarm-demo-waf-nlb"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure ELB instance for Wordpress instances.
#
resource "aws_elb" "wp_elb" {
  name = "tf-wallarm-demo-wp"
  security_groups = [
    "${aws_security_group.wp_sg.id}"
  ]
  subnets = [
    "${aws_subnet.public_a.id}",
    "${aws_subnet.public_b.id}"
  ]

  cross_zone_load_balancing = true
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
    target              = "HTTP:80/"
  }
  listener {
    lb_port           = 80
    lb_protocol       = "http"
    instance_port     = "80"
    instance_protocol = "http"
  }
}

#
# Configure NLB instance for WAF nodes.
#
resource "aws_lb" "wallarm_asg_nlb" {
  name               = "tf-wallarm-demo-asg-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets = [
    "${aws_subnet.public_a.id}",
    "${aws_subnet.public_b.id}"
  ]

  enable_deletion_protection = false
}

#
# Configure HTTP and HTTPS target groups for the NLB load balancer.
#
resource "aws_lb_target_group" "wallarm_asg_target_http" {
  name     = "tf-wallarm-demo-asg-target-http"
  port     = 80
  protocol = "TCP"
  vpc_id   = "${aws_vpc.my_vpc.id}"
  stickiness {
    enabled = false
    type    = "lb_cookie"
  }
}

resource "aws_lb_target_group" "wallarm_asg_target_https" {
  name     = "tf-wallarm-demo-asg-target-https"
  port     = 443
  protocol = "TCP"
  vpc_id   = "${aws_vpc.my_vpc.id}"
  stickiness {
    enabled = false
    type    = "lb_cookie"
  }
}

#
# Configure HTTP and HTTPS listeners for the NLB load balancer.
#
resource "aws_lb_listener" "wallarm_asg_nlb_http" {
  load_balancer_arn = "${aws_lb.wallarm_asg_nlb.arn}"
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.wallarm_asg_target_http.arn}"
  }
}

resource "aws_lb_listener" "wallarm_asg_nlb_https" {
  load_balancer_arn = "${aws_lb.wallarm_asg_nlb.arn}"
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.wallarm_asg_target_https.arn}"
  }
}

#
# Launch Configuration for Wordpress instances.
#
resource "aws_launch_configuration" "wp_launch_config" {

  image_id        = var.wordpress_ami_id
  instance_type   = var.wordpress_instance_type
  key_name        = "tf-wallarm-demo-key"
  security_groups = ["${aws_security_group.wp_sg.id}"]
}

#
# ASG for Wordpress instances.
#
resource "aws_autoscaling_group" "wp_asg" {
  name                 = "tf-wp_asg-${aws_launch_configuration.wp_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.wp_launch_config.name}"
  min_size             = "1"
  max_size             = "1"
  min_elb_capacity     = "1"
  availability_zones   = [var.az_a, var.az_b]
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}", "${aws_subnet.public_b.id}"]
  load_balancers = [
    "${aws_elb.wp_elb.id}"
  ]
  tag {
    key                 = "Name"
    value               = "tf-wallarm-demo-wp"
    propagate_at_launch = true
  }
}

#
# Launch Configuration for Wallarm WAF nodes.
#
resource "aws_launch_configuration" "wallarm_launch_config" {
  lifecycle { create_before_destroy = true }

  image_id        = var.wallarm_node_ami_id
  instance_type   = var.waf_node_instance_type
  key_name        = "tf-wallarm-demo-key"
  security_groups = ["${aws_security_group.wallarm_asg_sg.id}"]
  user_data       = <<-EOF
#cloud-config

write_files:
 - path: /etc/nginx/scanner-ips.conf
   owner: root:root
   permissions: '0644'
   content: "${file("scanner-ips.conf")}"
 - path: /etc/nginx/conf.d/wallarm-acl.conf
   owner: root:root
   permissions: '0644'
   content: |
    wallarm_acl_db default {
      wallarm_acl_path /var/cache/nginx/wallarm_acl_default;
      wallarm_acl_mapsize 64m;
    }
    server {
      listen 127.0.0.9:80;
      server_name localhost;
      allow 127.0.0.0/8;
      deny all;
      access_log off;
      location /wallarm-acl {
        wallarm_acl default;
        wallarm_acl_api on;
      }
    }
 - path: /etc/nginx/sites-available/default
   owner: root:root
   permissions: '0644'
   content: |
     limit_req_zone $binary_remote_addr zone=mylimit:10m rate=5r/s;
     map $remote_addr $wallarm_mode_real {
     default block;
       include /etc/nginx/scanner-ips.conf;
     }
     server {
       listen 80 default_server;
       server_name _;
       wallarm_acl default;
       wallarm_mode $wallarm_mode_real;
       # wallarm_instance 1;
       location /healthcheck {
         return 200;
       }
       location / {
         limit_req zone=mylimit burst=10 nodelay;
         # setting the address for request forwarding
         proxy_pass http://${aws_elb.wp_elb.dns_name};
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         set_real_ip_from 172.31.0.0/16;
         real_ip_header X-Forwarded-For;
       }
     }
     server { 
       listen 443 ssl default_server;
       server_name _;
       wallarm_acl default;
       ssl_protocols TLSv1.2;
       ssl_ciphers         HIGH:!aNULL:!MD5;
       ssl_certificate /etc/nginx/cert.pem;
       ssl_certificate_key /etc/nginx/key.pem;
       wallarm_mode block;
       # wallarm_instance 1;
       location /healthcheck {
         return 200;
       }
       location / {
         limit_req zone=mylimit burst=10 nodelay;
         # setting the address for request forwarding
         proxy_pass http://${aws_elb.wp_elb.dns_name};
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
     }
 - path: /etc/nginx/key.pem
   # This is a self-signed SSL certificate
   owner: root:root
   permissions: '0600'
   content: |
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDB6BggatWgySvo
    0M0k5+AzRaTFgSm32AZndx7v7qTbhJy8SaGgrdBz6rRLd/kFY3c3uT/yYtNGsKlb
    watSUHnyHTvwmfiQaZzJ4A97WqYn8bLke/seYRSYe+MYWLzykBlyS8qaauiGDLoF
    QhJ7UYlSJs1PJOqgu3NGIPy5PHVkknk/ykEQPIfjXE7pHftdC6/F+hkzyNlXehfo
    q3GHlDI/8UPexvg+QbluwtOe8ypZXbSqnA29Vpy8gw2Gyl9504El6r62EFL0lM5Y
    U1E7e1sUp1QiMTvqN1HGtuvOcfDS7VjgjgYKkJ+YL1vUKFTeMSq+fA+i1MPPsu/I
    RnbfCnD7AgMBAAECggEAWyKMhF/x+9nRK2FHqbrZov9ui+1DAEcl62cPQVF2Zj4T
    tGMe9ff7ax+6kWXXwnKXS7djmLZd+nF5h8ikjtGIHwUicNjM/ILG0BLg8+cNBOUS
    YVTsF8Ek/u3rNDwwwgh8DT4WATGSC77bhzEgopkV42idQj9ljxnK+gDzBtSlkBh9
    j7iL6C7II8dcnElu4HVY8Iuu67F9dsmNW76NJ7iqXuQZ3wQ4VUZ2FfaThBfHnPlq
    4k1bekCR5x5DuTPe90M4B4GIqxbBVo3yge1zvvVBY/O2dZDNyFgrxOQ2LQ4+4Y2P
    x7rD9QH7eLj03HU+GP0LLDeDWyIbEcZpmy7PvicYYQKBgQDxPof//pQm72FiPfmh
    WTRzuWWdp72159jp6n/y8FP6IJNDhSA8p7FlffJ8cbQl9zpSwNeMg8MOv3ZAYNtz
    /sYL17QKNLikRw1kom6PB2X738LVpVhoiYA5WtIufJoYxYdp665MhQygz480K/F1
    QEyQLBTedpAdF8waeohRDe/SMwKBgQDNxFZSBIU4Sk3MznbJ3gov2WlRpbz4g9V4
    4dRi3NEQrnbx8i0+7NOvzv+iouvXcm+lkXfLcluWCUhaIFW+dUQ3zAgPvWdWRQOO
    WNvikEuwz+LlGmY0KO5hVatvAGPv7HL4iXCB6/4ZQdTzZsWBO8MXhyCiTIUYHd3+
    y9pIFX9uGQKBgESU2UbeUbHL5axvH/NNj8rCTvAFyrnW4mSFZMBksArwjczpIKP9
    rEHFD1VvYZ5VbUAvUFfC8YXUykI9BsYwDI87UBSCrmcNR/Ju9u00VjrHfvULn1mA
    lXI4rn3GsGwQY5GqDY/1VwS0XOqg/3CsyddGoNwpaojKxhxU70HTq3TfAoGADJ5U
    uNTkIo6T9NJYgIqoT0Ti64nha9AR4EbhEmr+OyqnyrCSS8CUPrzP+nZJRj4TULD6
    CrTpnurU0AoZmANy+oT9nZF869JxpGIYoe09Zwtom6ohyGMWM0vgpn78ofL7Hfi3
    uI/zVjMuTvrnc8Rpc2DrBGjy5Ia4XW685RzEYskCgYEArXW5DdZuRQxX9CJmGoWK
    Sjxp1QLXzrHzhSeBTTYKWrP0YHBaDHhM6LBzbI21dAeV4qOKfDIduNWrzqSsxRcp
    PwyquUKmj6Bv0j64TwQKnHmsawVd4wB6FhpMUchNxszIKBhsLXXSdRJjpsL5Hfvt
    PG4rVUW5036CMHgnlP5zZLk=
    -----END PRIVATE KEY-----
 - path: /etc/nginx/cert.pem
   # This is a self-signed SSL certificate
   owner: root:root
   permissions: '0644'
   content: |
    -----BEGIN CERTIFICATE-----
    MIIDVjCCAj4CCQDwQNr36lh8ZjANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJV
    UzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBNYXRlbzEQMA4GA1UECgwHV2Fs
    bGFybTELMAkGA1UECwwCSVQxHjAcBgNVBAMMFSoudmljdG9yLWdhcnR2aWNoLmNv
    bTAeFw0yMDAyMjkwNjQyNDdaFw0yMTAyMjgwNjQyNDdaMG0xCzAJBgNVBAYTAlVT
    MQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU2FuIE1hdGVvMRAwDgYDVQQKDAdXYWxs
    YXJtMQswCQYDVQQLDAJJVDEeMBwGA1UEAwwVKi52aWN0b3ItZ2FydHZpY2guY29t
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwegYIGrVoMkr6NDNJOfg
    M0WkxYEpt9gGZ3ce7+6k24ScvEmhoK3Qc+q0S3f5BWN3N7k/8mLTRrCpW8GrUlB5
    8h078Jn4kGmcyeAPe1qmJ/Gy5Hv7HmEUmHvjGFi88pAZckvKmmrohgy6BUISe1GJ
    UibNTyTqoLtzRiD8uTx1ZJJ5P8pBEDyH41xO6R37XQuvxfoZM8jZV3oX6Ktxh5Qy
    P/FD3sb4PkG5bsLTnvMqWV20qpwNvVacvIMNhspfedOBJeq+thBS9JTOWFNRO3tb
    FKdUIjE76jdRxrbrznHw0u1Y4I4GCpCfmC9b1ChU3jEqvnwPotTDz7LvyEZ23wpw
    +wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAhfJ8OCvF3cMJrKr2RTIpq7impRvjY
    lNaT/hP5S8Y0YHtWXdxP/vMk0tZSD7NAKcd0Zz4ocnezYhNxqeZcL5Vd8EUXqGpE
    hZ7r02pkHwIglprF6iuQY/qRE566zUjcVQieYqTb4rki42fSVAck7lv+LIg+CCOg
    C1dz11284x/8hyy06M1zbtET0oniEnZuDFOtbMTLUqR9jLDtqJsgOgcD7Y3Y+WXI
    9DnIZdXRjK+d45ytY6c9SqV/ienxbvjx2G3DG2kiYGfTPQOUVC+UX8KtqNEDpxOZ
    ooqMBlOXYxLJ2I9UcCu21Wj+CXJAPPbj/UZ79t59nC2yB5OmrniOFsMC
    -----END CERTIFICATE-----
runcmd:
 - /usr/share/wallarm-common/addnode --force -H ${var.wallarm_api_domain} -u ${var.deploy_username} -p ${var.deploy_password} --name `hostname`
 - 'echo "sync_blacklist:" >> /etc/wallarm/node.yaml'
 - 'echo "  nginx_url: http://127.0.0.9/wallarm-acl" >> /etc/wallarm/node.yaml'
 - mkdir /var/cache/nginx/
 - chown www-data /var/cache/nginx/
 - nginx -t
 - service nginx start
 - service nginx reload
 - [ sed, -i, -Ee, 's/^#(.*sync-blacklist.*)/\1/', /etc/cron.d/wallarm-node-nginx ]
EOF
}

#
# ASG configuration for Wallarm WAF nodes.
#
resource "aws_autoscaling_group" "wallarm_waf_asg" {
  lifecycle { create_before_destroy = true }

  name                 = "tf-wallarm-demo-waf-asg-${aws_launch_configuration.wallarm_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.wallarm_launch_config.name}"
  min_size             = "2"
  max_size             = "5"
  min_elb_capacity     = "2"
  availability_zones   = [var.az_a]
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}"]
  target_group_arns = ["${aws_lb_target_group.wallarm_asg_target_http.arn}", "${aws_lb_target_group.wallarm_asg_target_https.arn}"
  ]

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]
  metrics_granularity = "1Minute"

  tag {
    key                 = "Name"
    value               = "tf-wallarm-demo-waf-node"
    propagate_at_launch = true
  }
}

#
# Autoscaling UP and DOWN plicies and CloudWatch alerts for WAF nodes ASG.
#
resource "aws_autoscaling_policy" "wallarm_policy_up" {
  name                   = "tf-wallarm_policy_up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = "${aws_autoscaling_group.wallarm_waf_asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "wallarm_cpu_alarm_up" {
  alarm_name          = "tf-wallarm_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "40"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.wallarm_waf_asg.name}"
  }
  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions     = ["${aws_autoscaling_policy.wallarm_policy_up.arn}"]
}

resource "aws_autoscaling_policy" "wallarm_policy_down" {
  name                   = "tf-wallarm_policy_down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = "${aws_autoscaling_group.wallarm_waf_asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "wallarm_cpu_alarm_down" {
  alarm_name          = "tf-wallarm_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "20"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.wallarm_waf_asg.name}"
  }
  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions     = ["${aws_autoscaling_policy.wallarm_policy_down.arn}"]
}

#
# Print out the DNS name of created NLB instance.
#
output "waf_nlb_dns_name" {
  value = [aws_lb.wallarm_asg_nlb.dns_name]
}
