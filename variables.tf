variable "project" {
  type        = string
  description = "Project name"
}

variable "env" {
  type        = string
  description = "Environment"
}

variable "location" {
  type        = string
  description = "Location"
}

variable "tags" {
  type        = map(string)
  description = "Tags"
}

variable "resource_group" {
  type        = string
  description = "Resource group name"
}


variable "service_plan_id" {
  type        = string
  description = "App Service plan ID"
}

variable "name" {
  type        = string
  description = "Function index/name (like 007)"
}

variable "application_type" {
  type        = string
  description = "Application type (java, python, etc)"
  default     = "java"
}

variable "java_version" {
  type        = string
  description = "Java version"
  default     = "8"
}

variable "ip_restriction" {
  description = "Firewall settings for the function app"
  type = list(object({
    name                      = string
    ip_address                = string
    service_tag               = string
    virtual_network_subnet_id = string
    priority                  = string
    action                    = string
    headers = list(object({
      x_azure_fdid      = list(string)
      x_fd_health_probe = list(string)
      x_forwarded_for   = list(string)
      x_forwarded_host  = list(string)
    }))
  }))
  default = [
    {
      name                      = "allow_azure"
      ip_address                = null
      service_tag               = "AzureCloud"
      virtual_network_subnet_id = null
      priority                  = "100"
      action                    = "Allow"
      headers                   = null
    }
  ]
}

variable "app_settings" {
  type        = map(string)
  default     = {}
  description = "Application setting"
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the function app"
  default     = null
}

variable "use_private_net" {
  type        = bool
  description = "Use private network injection"
  default     = false
}
