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
  description = "Web index/name (like 007)"
}

variable "application_type" {
  type        = string
  description = "Application type (java, python, etc)"
  default     = "java"
}

variable "ip_restriction" {
  description = "Firewall settings for the web app"
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

variable "scm_ip_restriction" {
  description = "Firewall settings for the SCM web app"
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
  default = null
}

variable "app_settings" {
  type        = map(string)
  default     = {}
  description = "Application setting"
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the web app"
  default     = null
}

variable "use_private_net" {
  type        = bool
  description = "Use private network injection"
  default     = false
}

variable "application_stack" {
  type = map(string)
  default = {
    java_server         = "JAVA"
    java_server_version = 11
    java_version        = "java11"
  }
  description = "Application stack configuration, run `az webapp list-runtimes --os-type linux` to get the list of supported stacks"
}

variable "identity_ids" {
  type        = list(string)
  description = "List of user assigned identity IDs"
  default     = null
}

variable "logs" {
  type = object({
    detailed_error_messages = bool
    failed_request_tracing  = bool
    http_logs = object({
      file_system = object({
        retention_in_days = number
        retention_in_mb   = number
      })
    })
  })
  default = {
    detailed_error_messages = false
    failed_request_tracing  = false
    http_logs = {
      file_system = {
        retention_in_days = 7
        retention_in_mb   = 35
      }
    }
  }
  description = "Logs configuration"
}

variable "storage_account" {
  type = list(object({
    access_key   = string
    account_name = string
    name         = string
    share_name   = string
    type         = string
    mount_path   = string
  }))
  default     = []
  description = "BYOS storage mount configuration"
}

variable "websockets_enabled" {
  type        = bool
  description = "Enable websockets"
  default     = false
}

variable "enable_appinsights" {
  type        = bool
  description = "Enable application insights"
  default     = true
}
