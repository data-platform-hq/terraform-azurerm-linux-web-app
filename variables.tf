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
  validation {
    condition     = contains(["ios", "java", "MobileCenter", "Node.JS", "other", "phone", "store", "web"], var.application_type)
    error_message = "Valid values are ios for iOS, java for Java web, MobileCenter for App Center, Node.JS for Node.js, other for General, phone for Windows Phone, store for Windows Store and web for ASP.NET. Please note these values are case sensitive; unmatched values are treated as ASP.NET by Azure. Changing this forces a new resource to be created."
  }
}

variable "ip_restriction" {
  description = "Firewall settings for the function app"
  type = list(object({
    name                      = string
    ip_address                = optional(string, null)
    service_tag               = optional(string, null)
    virtual_network_subnet_id = optional(string, null)
    priority                  = optional(string, "100")
    action                    = string
    headers = optional(list(object({
      x_azure_fdid      = optional(list(string), null)
      x_fd_health_probe = optional(list(string), null)
      x_forwarded_for   = optional(list(string), null)
      x_forwarded_host  = optional(list(string), null)
    })), [])
  }))
  default = [
    {
      name        = "allow_azure"
      service_tag = "AzureCloud"
      action      = "Allow"
    }
  ]
}

variable "scm_ip_restriction" {
  description = "Firewall settings for the function app"
  type = list(object({
    name                      = string
    ip_address                = optional(string, null)
    service_tag               = optional(string, null)
    virtual_network_subnet_id = optional(string, null)
    priority                  = optional(string, "100")
    action                    = string
    headers = optional(list(object({
      x_azure_fdid      = optional(list(string), null)
      x_fd_health_probe = optional(list(string), null)
      x_forwarded_for   = optional(list(string), null)
      x_forwarded_host  = optional(list(string), null)
    })), [])
  }))
  default = [
    {
      name        = "allow_azure"
      service_tag = "AzureCloud"
      action      = "Allow"
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
    java_version        = "11"
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

variable "enable_appinsights" {
  type        = bool
  description = "Enable application insights"
  default     = true
}

variable "analytics_workspace_id" {
  type        = string
  description = "Resource ID of Log Analytics Workspace"
  default     = null
}

variable "analytics_destination_type" {
  type        = string
  description = "Possible values are AzureDiagnostics and Dedicated."
  default     = "Dedicated"
}

variable "enable_diagnostic_setting" {
  type        = bool
  description = "Enable diagnostic setting. var.analytics_workspace_id must be provided"
  default     = false
}

variable "client_affinity_enabled" {
  type        = bool
  description = "Improve performance of your stateless app by turning Affinity Cookie off, stateful apps should keep this setting on for compatibility"
  default     = false
}

variable "key_vault" {
  description = "Configure Linux Function App to Key Vault"
  type = object({
    id                  = optional(string, null)
    key_permissions     = optional(list(string), null)
    secret_permissions  = optional(list(string), ["Get", "List"])
    storage_permissions = optional(list(string), null)
  })
  default = {}
}

variable "site_config" {
  type = object({
    always_on                                     = optional(bool, true)
    ftps_state                                    = optional(string, "Disabled")
    http2_enabled                                 = optional(bool, true)
    websockets_enabled                            = optional(bool, false)
    use_32_bit_worker                             = optional(bool, false)
    container_registry_use_managed_identity       = optional(bool, false)
    container_registry_managed_identity_client_id = optional(string, null)
    worker_count                                  = optional(number, null)
  })
  default = {}
  description = "Site configuration"
}
