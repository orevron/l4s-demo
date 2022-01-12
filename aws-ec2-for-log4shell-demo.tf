provider "aws" {
  region = var.aws_region
}

# ---------- variable definition ----------

variable "aws_region" {
  description = "AWS region (e.g. us-east-2)"
}

variable "flow_log_bucket_name" {
  description = "The name of the S3 bucket used to store VPC flow log (must be unique within an AWS partition)"
}

variable "s3_access_log_bucket_name" {
  description = "The name of the S3 bucket used to store access log (must be unique within an AWS partition)"
}

variable "ssh_allowed_host" {
  type        = string
  description = "CIDR block allowed to ssh to the EC2 VM"
}

variable "ec2_key_pair_name" {
  description = "key pair for connecting to EC2"
}

variable "ec2_ami" {
  description = "AMI used for EC2"
}

variable "ec2_instance_type" {
  description = "Instance type used by EC2 (e.g. t2.micro)"
}

variable "pcc_username" {
  description = "Prisma Cloud username (for SaaS Console, it is the access key ID defined in Setings > Access Keys)"
  sensitive   = "true"
}

variable "pcc_password" {
  description = "Prisma Cloud password (for SaaS Console, it is the secret key defined in Setings > Access Keys)"
  sensitive   = "true"
}

variable "pcc_url" {
  description = "Prisma Cloud Compute Console URL (for SaaS Console, the URL can be found in Compute > Manage > System > Utilities > Path to Console)"
}

variable "pcc_domain_name" {
  description = "Prisma Cloud Compute Console domain name (extracted the domain name from the console URL)"
}

variable "vul_app_image" {
  description = "The name of the image of the vulnerable app"
}

variable "att_svr_image" {
  description = "The name of the image of the attack server"
}

variable "attacker_machine_name" {
  description = "The name of the image of the attacker machine"
}

# ---------- variable definition ends ----------

# Set the default security group without any inbound and outbound rules

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name      = "default SG"
    yor_trace = "9ef770db-a205-453a-86c3-4b0a7312db3f"
  }
}

# Enable VPC flow log

resource "aws_flow_log" "vpc_flow_log" {
  log_destination      = aws_s3_bucket.vpc_flow_log.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.vpc1.id
  tags = {
    yor_trace = "08cd720d-77d7-4a48-8be7-f6a907ad5be8"
  }
}

# Create S3 bucket for storing flow log

resource "aws_s3_bucket" "vpc_flow_log" {
  # checkov:skip=CKV_AWS_144: replication not required
  bucket        = var.flow_log_bucket_name
  force_destroy = "true"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = aws_s3_bucket.s3_access_log.id
    target_prefix = "log/"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  tags = {
    yor_trace = "a84c1f16-5a55-46c1-b52d-33195641a772"
  }
}

# Block public access of the S3 bucket

resource "aws_s3_bucket_public_access_block" "vpc_flow_log" {
  bucket = aws_s3_bucket.vpc_flow_log.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Create S3 bucket for S3 access logging

resource "aws_s3_bucket" "s3_access_log" {
  # checkov:skip=CKV_AWS_144: replication not required
  # checkov:skip=CKV_AWS_18: This bucket is for storing S3 bucket access log
  bucket        = var.s3_access_log_bucket_name
  force_destroy = "true"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  tags = {
    yor_trace = "6d817d75-7e6b-45ae-9795-d8bbd7255469"
  }
}

# Block public access of the S3 bucket

resource "aws_s3_bucket_public_access_block" "s3_access_log" {
  bucket = aws_s3_bucket.s3_access_log.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Create vpc

resource "aws_vpc" "vpc1" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = "true"
  tags = {
    Name      = "VPC1"
    yor_trace = "0f33c275-b6c4-4cd5-88a2-e15503fc82f5"
  }
}

# Create subnet

resource "aws_subnet" "subnet-1" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = format("%sa", var.aws_region)

  tags = {
    Name      = "vpc1-subnet-1"
    yor_trace = "9aa48479-69a9-4c78-a96a-d01a2486cead"
  }
}

# Create Internet GW

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    yor_trace = "a4fb2f34-5eb7-4b4c-ac0b-ef3850adcc4a"
  }
}

# Attach Internet GW to default route table and setup default route

resource "aws_default_route_table" "default_route_table" {
  default_route_table_id = aws_vpc.vpc1.default_route_table_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name      = "default-route-table"
    yor_trace = "f28a1706-3f10-4e81-ba52-b8e6771d66e9"
  }
}

# Create Security Group to allow port 22, 80, 443

resource "aws_security_group" "allow-ssh-web" {
  name        = "allow-ssh-web"
  description = "Allow SSH and Web inbound traffic"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH from specific host"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_allowed_host]
  }

  egress {
    description = "allow all outbound connections"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "allow-ssh-web"
    yor_trace = "edbd47da-88fe-4a77-acb8-b327863ab3dc"
  }
}

# Create Ubuntu EC2

resource "aws_instance" "web-server" {
  # checkov:skip=CKV_AWS_88: public IP required by web server
  # checkov:skip=CKV_AWS_135: EBS optimization not supported by instance type
  ami                         = var.ec2_ami
  instance_type               = var.ec2_instance_type
  key_name                    = var.ec2_key_pair_name
  associate_public_ip_address = "true"
  subnet_id                   = aws_subnet.subnet-1.id
  vpc_security_group_ids      = [aws_security_group.allow-ssh-web.id]

  user_data = <<-EOF
    #!/bin/bash
    set -ex
    # install Docker runtime
    sudo apt update -y
    sudo apt install ca-certificates curl gnupg lsb-release -y
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update -y
    sudo apt install docker-ce docker-ce-cli containerd.io -y
    sudo usermod -aG docker ubuntu
    sudo systemctl enable docker.service
    sudo systemctl enable containerd.service
    # install Defender
    sudo apt install jq -y
    AUTH_DATA="$(printf '{ "username": "%s", "password": "%s" }' "${var.pcc_username}" "${var.pcc_password}")"
    TOKEN=$(curl -sSLk -d "$AUTH_DATA" -H 'content-type: application/json' "${var.pcc_url}/api/v1/authenticate" | jq -r ' .token ')
    curl -sSLk -H "authorization: Bearer $TOKEN" -X POST "${var.pcc_url}/api/v1/scripts/defender.sh" | sudo bash -s -- -c "${var.pcc_domain_name}" -d "none" -m
    # setup environments for Log4Shell demo
    docker network create dirty-net
    docker container run -itd --rm --name vul-app-1 --network dirty-net ${var.vul_app_image}
    docker container run -itd --rm --name vul-app-2 --network dirty-net ${var.vul_app_image}
    docker container run -itd --rm --name att-svr --network dirty-net ${var.att_svr_image}
    docker container run -itd --rm --network dirty-net --name attacker-machine ${var.attacker_machine_name}
    # stop learning for vulnerable app container
    PROFILE_ID=$(curl -k -X GET -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v21.08/profiles/container" | jq -r ' .[] | select(.image == "${var.vul_app_image}") | ._id ')
    curl -k -X POST -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"state": "manualActive"}' "${var.pcc_url}/api/v1/profiles/container/$PROFILE_ID/learn"
    # add collections
    curl -k -X POST -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"Log4Shell demo - vul-app-1","images":["${var.vul_app_image}"],"containers":["vul-app-1"],"hosts":["*"],"namespaces":["*"],"labels":["*"],"accountIDs":["*"],"clusters":["*"]}' "${var.pcc_url}/api/v21.08/collections"
    curl -k -X POST -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"Log4Shell demo - vul-app-2","images":["${var.vul_app_image}"],"containers":["vul-app-2"],"hosts":["*"],"namespaces":["*"],"labels":["*"],"accountIDs":["*"],"clusters":["*"]}' "${var.pcc_url}/api/v21.08/collections"
    # add runtime rules
    NEW_RULES='[{"name":"vul-app-2","previousName":"","collections":[{"name":"Log4Shell demo - vul-app-2"}],"advancedProtection":true,"processes":{"effect":"prevent","blacklist":[],"whitelist":[],"checkCryptoMiners":true,"checkLateralMovement":true,"checkParentChild":true,"checkSuidBinaries":true},"network":{"effect":"alert","blacklistIPs":[],"blacklistListeningPorts":[],"whitelistListeningPorts":[],"blacklistOutboundPorts":[],"whitelistOutboundPorts":[],"whitelistIPs":[],"skipModifiedProc":false,"detectPortScan":true,"skipRawSockets":false},"dns":{"effect":"prevent","blacklist":[],"whitelist":[]},"filesystem":{"effect":"prevent","blacklist":[],"whitelist":[],"checkNewFiles":true,"backdoorFiles":true,"skipEncryptedBinaries":false,"suspiciousELFHeaders":true},"kubernetesEnforcement":true,"cloudMetadataEnforcement":true,"wildFireAnalysis":"alert"},{"name":"vul-app-1","previousName":"","collections":[{"name":"Log4Shell demo - vul-app-1"}],"advancedProtection":true,"processes":{"effect":"alert","blacklist":[],"whitelist":[],"checkCryptoMiners":true,"checkLateralMovement":true,"checkParentChild":true,"checkSuidBinaries":true},"network":{"effect":"alert","blacklistIPs":[],"blacklistListeningPorts":[],"whitelistListeningPorts":[],"blacklistOutboundPorts":[],"whitelistOutboundPorts":[],"whitelistIPs":[],"skipModifiedProc":false,"detectPortScan":true,"skipRawSockets":false},"dns":{"effect":"alert","blacklist":[],"whitelist":[]},"filesystem":{"effect":"alert","blacklist":[],"whitelist":[],"checkNewFiles":true,"backdoorFiles":true,"skipEncryptedBinaries":false,"suspiciousELFHeaders":true},"kubernetesEnforcement":true,"cloudMetadataEnforcement":true,"wildFireAnalysis":"alert"}]'
    ALL_RULES=$(curl -k -X GET -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v21.08/policies/runtime/container" | jq --argjson nr "$NEW_RULES" ' .rules = $nr + .rules ')
    curl -k -X PUT -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v21.08/policies/runtime/container" -d "$ALL_RULES"
    # add WAAS rule
    NEW_RULES='[{"name":"vul-app-2","collections":[{"name":"Log4Shell demo - vul-app-2"}],"applicationsSpec":[{"appID":"app-0001","sessionCookieSameSite":"Lax","customBlockResponse":{},"banDurationMinutes":5,"certificate":{"encrypted":""},"tlsConfig":{"minTLSVersion":"1.2","metadata":{"notAfter":"0001-01-01T00:00:00Z","issuerName":"","subjectName":""},"HSTSConfig":{"enabled":false,"maxAgeSeconds":31536000,"includeSubdomains":false,"preload":false}},"dosConfig":{"enabled":false,"alert":{},"ban":{}},"apiSpec":{"endpoints":[{"host":"*","basePath":"*","exposedPort":0,"internalPort":8080,"tls":false,"http2":false}],"effect":"disable","fallbackEffect":"disable","skipLearning":false},"botProtectionSpec":{"userDefinedBots":[],"knownBotProtectionsSpec":{"searchEngineCrawlers":"disable","businessAnalytics":"disable","educational":"disable","news":"disable","financial":"disable","contentFeedClients":"disable","archiving":"disable","careerSearch":"disable","mediaSearch":"disable"},"unknownBotProtectionSpec":{"generic":"disable","webAutomationTools":"disable","webScrapers":"disable","apiLibraries":"disable","httpLibraries":"disable","botImpersonation":"disable","browserImpersonation":"disable","requestAnomalies":{"threshold":9,"effect":"disable"}},"sessionValidation":"disable","interstitialPage":false,"jsInjectionSpec":{"enabled":false,"timeoutEffect":"disable"},"reCAPTCHASpec":{"enabled":false,"siteKey":"","secretKey":{"encrypted":""},"type":"checkbox","allSessions":true,"successExpirationHours":24}},"networkControls":{"advancedProtectionEffect":"alert","subnets":{"enabled":false,"allowMode":true,"fallbackEffect":"alert"},"countries":{"enabled":false,"allowMode":true,"fallbackEffect":"alert"}},"body":{"inspectionSizeBytes":131072},"intelGathering":{"infoLeakageEffect":"alert","removeFingerprintsEnabled":true},"maliciousUpload":{"effect":"disable","allowedFileTypes":[],"allowedExtensions":[]},"csrfEnabled":true,"clickjackingEnabled":true,"sqli":{"effect":"alert","exceptionFields":[]},"xss":{"effect":"alert","exceptionFields":[]},"attackTools":{"effect":"alert","exceptionFields":[]},"shellshock":{"effect":"alert","exceptionFields":[]},"malformedReq":{"effect":"alert","exceptionFields":[]},"cmdi":{"effect":"alert","exceptionFields":[]},"lfi":{"effect":"alert","exceptionFields":[]},"codeInjection":{"effect":"alert","exceptionFields":[]},"remoteHostForwarding":{},"customRules":[{"_id":37,"action":"audit","effect":"prevent"},{"_id":36,"action":"audit","effect":"prevent"}]}]}]'
    ALL_RULES=$(curl -k -X GET -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v21.08/policies/firewall/app/container" | jq --argjson nr "$NEW_RULES" ' .rules = $nr + .rules ')
    curl -k -X PUT -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v21.08/policies/firewall/app/container" -d "$ALL_RULES"
    # enable WildFire
    curl -k -X PUT -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "${var.pcc_url}/api/v1/settings/wildfire" -d '{"region":"sg","runtimeEnabled":true,"complianceEnabled":true,"uploadEnabled":true,"graywareAsMalware":false}'
    EOF

  tags = {
    Name      = "web-server"
    yor_trace = "813da62e-0634-427a-9d8f-3c4b46ff232c"
  }
  monitoring = true
  root_block_device {
    encrypted = true
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  #   ebs_block_device {
  #     encrypted = true
  #   }
}

output "server_public_ip" {
  value = aws_instance.web-server.public_ip
}