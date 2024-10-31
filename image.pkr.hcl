packer {
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# Variables
variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "The AWS region where the image will be built"
}

variable "demo_aws_account" {
  type        = string
  description = "The AWS account ID to share the AMI with"
  default     = "982081064063"
}

variable "app_archive" {
  type        = string
  default     = "application.tar.gz"
  description = "The application archive file name"
}

variable "source_ami" {
  type        = string
  default     = "ami-0866a3c8686eaeeba"
  description = "The source AMI ID for Ubuntu 24.04 LTS"
}

variable "instance_type" {
  type        = string
  default     = "t2.micro"
  description = "The instance type to use for building the AMI"
}

variable "ami_name" {
  type        = string
  default     = "csye_assignment04_"
  description = "The base name of the AMI"
}

variable "ssh_username" {
  type        = string
  default     = "ubuntu"
  description = "The SSH username for the instance"
}

variable "vpc_id" {
  type        = string
  default     = "vpc-08265c0e5798301f9"
  description = "The VPC ID where the AMI is being built"
}

variable "subnet_id" {
  type        = string
  default     = "subnet-009e17b983eeea7f7"
  description = "The Subnet ID within the VPC"
}

variable "ssh_keypair_name" {
  type        = string
  default     = "ec2_key"
  description = "The EC2 key pair for SSH access"
}

variable "security_group_id" {
  type        = string
  default     = "sg-0b7654321abcdef"
  description = "The security group ID created for SSH access"
}

variable "DB_USER" {
  type        = string
  description = "The database username"
  default     = "csye6225"
}

variable "DB_PASSWORD" {
  type        = string
  description = "The database password"
  default     = "your_db_password"
}

variable "DB_HOST" {
  type        = string
  description = "The RDS database host"
  default     = "PLACEHOLDER_DB_HOST"
}

variable "DB_NAME" {
  type        = string
  description = "The database name"
  default     = "csye6225"
}

variable "PORT" {
  type        = string
  default     = "3000"
  description = "The port for the application"
}

variable "DEFAULT_PORT" {
  type        = string
  default     = "3000"
  description = "The default port for the application"
}

variable "prefix" {
  type        = string
  description = "pattern for random identifier"
  default = "AKIA6JKEXZR72SAFFOMB"
}

variable "postfix" {
  type        = string
  description = "pattern for random identifier"
  default = "Wtcq19gOk0Ql237gd8urCluDTdi+j0RAvX0BMHzl"
}

source "amazon-ebs" "ubuntu" {
  region                      = var.aws_region
  source_ami                  = var.source_ami
  instance_type               = var.instance_type
  ssh_username                = var.ssh_username
  ami_name                    = "${var.ami_name}${formatdate("YYYYMMDDHHmmss", timestamp())}"
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  associate_public_ip_address = true

  ami_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 25
    encrypted             = false
    delete_on_termination = true
    volume_type           = "gp2"
  }

  ami_users = [var.demo_aws_account]

  tags = {
    Name        = "${var.ami_name}${formatdate("YYYYMMDDHHmmss", timestamp())}"
    Environment = "Dev"
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu"]

  # Install necessary packages and create the application user and group
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y nodejs npm",
      "sudo groupadd csye6225 || true",
      "sudo useradd -r -g csye6225 -s /usr/sbin/nologin csye6225 || true"
    ]
  }

  # Upload the application archive
  provisioner "file" {
    source      = var.app_archive
    destination = "/home/ubuntu/${var.app_archive}"
  }

  # Move application files, extract, and set permissions
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /home/csye6225/app",
      "sudo rm -rf /home/csye6225/app/*",
      "sudo mv /home/ubuntu/${var.app_archive} /home/csye6225/app/",
      "if [ -f '/home/csye6225/app/${var.app_archive}' ]; then echo '${var.app_archive} is a file.'; else echo 'Error: ${var.app_archive} is not a file.'; exit 1; fi",
      "sudo chown -R csye6225:csye6225 /home/csye6225/app",
      "cd /home/csye6225/app && sudo -u csye6225 tar -xzvf ${var.app_archive}",
      "sudo chown -R csye6225:csye6225 /home/csye6225/",
      "cd /home/csye6225/app && sudo -u csye6225 npm install --production",
      # Create the .env file
      "sudo bash -c \"echo 'DB_name=${var.DB_NAME}' > /home/csye6225/app/.env\"",
      "sudo bash -c \"echo 'DB_username=${var.DB_USER}' >> /home/csye6225/app/.env\"",
      "sudo bash -c \"echo 'DB_password=${var.DB_PASSWORD}' >> /home/csye6225/app/.env\"",
      "sudo bash -c \"echo 'DB_host=${var.DB_HOST}' >> /home/csye6225/app/.env\"",
      "sudo bash -c \"echo 'PORT=${var.PORT}' >> /home/csye6225/app/.env\"",
      "sudo bash -c \"echo 'DEFAULT_PORT=${var.DEFAULT_PORT}' >> /home/csye6225/app/.env\"",
      "sudo chown csye6225:csye6225 /home/csye6225/app/.env"
    ]
  }

  # Define systemd service for application and configure logging
  provisioner "shell" {
    inline = [
      # Create the service file
      "sudo bash -c 'cat <<EOF > /etc/systemd/system/myapp.service",
      "[Unit]",
      "Description=My Node.js Application",
      "After=network.target",
      "",
      "[Service]",
      "ExecStart=/usr/bin/node /home/csye6225/app/server.js",
      "WorkingDirectory=/home/csye6225/app",
      "Restart=always",
      "User=csye6225",
      "Environment=PATH=/usr/bin:/usr/local/bin",
      "Environment=NODE_ENV=production",
      "EnvironmentFile=/home/csye6225/app/.env",
      "StandardOutput=file:/home/csye6225/app/app.log",
      "StandardError=file:/home/csye6225/app/app.log",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF'",
      # Create the app.log file and set permissions
      "sudo touch /home/csye6225/app/app.log",
      "sudo chown csye6225:csye6225 /home/csye6225/app/app.log",
      "sudo chmod 644 /home/csye6225/app/app.log",
      # Reload systemd and start the service
      "sudo systemctl daemon-reload",
      "sudo systemctl enable myapp.service",
      "sudo systemctl start myapp.service",
      "sudo systemctl status myapp.service || true"
    ]
  }

  # Install StatsD and configure it to send metrics to CloudWatch
  provisioner "shell" {
    inline = [
      # Install StatsD
      "sudo npm install -g statsd",
      # Install the CloudWatch backend for StatsD
      "sudo npm install -g statsd-cloudwatch-backend",
      # Create StatsD configuration directory
      "sudo mkdir -p /etc/statsd",
      # Create the StatsD configuration file with AWS credentials
      "sudo bash -c 'cat <<EOF > /etc/statsd/localConfig.js",
      "module.exports = {",
      "  backends: [\"statsd-cloudwatch-backend\"],",
      "  cloudwatch: {",
      "    accessKeyId: \"${var.prefix}\",",
      "    secretAccessKey: \"${var.postfix}\",",
      "    region: \"${var.aws_region}\",",
      "    namespace: \"MyApplication\",",
      "    dimensions: {",
      "      InstanceId: \"${var.instance_type}\"",
      "    }",
      "  },",
      "  port: 8125,",
      "  mgmt_port: 8126",
      "};",
      "EOF'",
      # Create a systemd service file for StatsD
      "sudo bash -c 'cat <<EOF > /etc/systemd/system/statsd.service",
      "[Unit]",
      "Description=StatsD",
      "After=network.target",
      "",
      "[Service]",
      "ExecStart=/usr/bin/node /usr/local/lib/node_modules/statsd/stats.js /etc/statsd/localConfig.js",
      "Restart=always",
      "User=root",
      "Group=root",
      "Environment=PATH=/usr/bin:/usr/local/bin",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF'",
      # Reload systemd and enable/start StatsD service
      "sudo systemctl daemon-reload",
      "sudo systemctl enable statsd.service",
      "sudo systemctl start statsd.service",
      "sudo systemctl status statsd.service || true"
    ]
  }

  # Remove the CloudWatch Agent StatsD configuration provisioner
  # (Optional: You can keep the CloudWatch Agent for log collection if needed)
  # If you want to remove the CloudWatch Agent entirely, remove its installation and configuration provisioners.

  # (Optional) Install CloudWatch Agent for log collection
  provisioner "shell" {
    inline = [
      # Install CloudWatch Agent
      "wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb",
      "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",
      "rm ./amazon-cloudwatch-agent.deb",
      # Create CloudWatch Agent configuration file for log collection
      "sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null << 'CONFIG'",
      "{",
      "  \"agent\": {",
      "    \"metrics_collection_interval\": 60,",
      "    \"logfile\": \"/var/log/amazon-cloudwatch-agent/amazon-cloudwatch-agent.log\"",
      "  },",
      "  \"logs\": {",
      "    \"logs_collected\": {",
      "      \"files\": {",
      "        \"collect_list\": [",
      "          {",
      "            \"file_path\": \"/home/csye6225/app/app.log\",",
      "            \"log_group_name\": \"my-log-group\",",
      "            \"log_stream_name\": \"{instance_id}-app-log\",",
      "            \"timestamp_format\": \"%Y-%m-%d %H:%M:%S\"",
      "          }",
      "        ]",
      "      }",
      "    }",
      "  }",
      "}",
      "CONFIG",
      # Start the CloudWatch Agent
      "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s",
      "sudo systemctl restart amazon-cloudwatch-agent"
    ]
  }
}
