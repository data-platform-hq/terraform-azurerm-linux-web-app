# Azure Linux Web App Terraform module
Terraform module for creation Azure Linux Web App

## Usage

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.49.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 3.27.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_app_service_virtual_network_swift_connection.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service_virtual_network_swift_connection) | resource |
| [azurerm_application_insights.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights) | resource |
| [azurerm_key_vault_access_policy.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_access_policy) | resource |
| [azurerm_linux_web_app.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_web_app) | resource |
| [azurerm_monitor_diagnostic_setting.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |
| [azurerm_monitor_diagnostic_categories.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/monitor_diagnostic_categories) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_analytics_destination_type"></a> [analytics\_destination\_type](#input\_analytics\_destination\_type) | Possible values are AzureDiagnostics and Dedicated. | `string` | `"Dedicated"` | no |
| <a name="input_analytics_workspace_id"></a> [analytics\_workspace\_id](#input\_analytics\_workspace\_id) | Resource ID of Log Analytics Workspace | `string` | `null` | no |
| <a name="input_app_settings"></a> [app\_settings](#input\_app\_settings) | Application setting | `map(string)` | `{}` | no |
| <a name="input_application_stack"></a> [application\_stack](#input\_application\_stack) | Application stack configuration, run `az webapp list-runtimes --os-type linux` to get the list of supported stacks | `map(string)` | <pre>{<br>  "java_server": "JAVA",<br>  "java_server_version": 11,<br>  "java_version": "11"<br>}</pre> | no |
| <a name="input_application_type"></a> [application\_type](#input\_application\_type) | Application type (java, python, etc) | `string` | `"java"` | no |
| <a name="input_client_affinity_enabled"></a> [client\_affinity\_enabled](#input\_client\_affinity\_enabled) | Improve performance of your stateless app by turning Affinity Cookie off, stateful apps should keep this setting on for compatibility | `bool` | `false` | no |
| <a name="input_enable_appinsights"></a> [enable\_appinsights](#input\_enable\_appinsights) | Enable application insights | `bool` | `true` | no |
| <a name="input_enable_diagnostic_setting"></a> [enable\_diagnostic\_setting](#input\_enable\_diagnostic\_setting) | Enable diagnostic setting. var.analytics\_workspace\_id must be provided | `bool` | `false` | no |
| <a name="input_env"></a> [env](#input\_env) | Environment | `string` | n/a | yes |
| <a name="input_identity_ids"></a> [identity\_ids](#input\_identity\_ids) | List of user assigned identity IDs | `list(string)` | `null` | no |
| <a name="input_ip_restriction"></a> [ip\_restriction](#input\_ip\_restriction) | Firewall settings for the function app | <pre>list(object({<br>    name                      = string<br>    ip_address                = optional(string, null)<br>    service_tag               = optional(string, null)<br>    virtual_network_subnet_id = optional(string, null)<br>    priority                  = optional(string, "100")<br>    action                    = string<br>    headers = optional(list(object({<br>      x_azure_fdid      = optional(list(string), null)<br>      x_fd_health_probe = optional(list(string), null)<br>      x_forwarded_for   = optional(list(string), null)<br>      x_forwarded_host  = optional(list(string), null)<br>    })), [])<br>  }))</pre> | <pre>[<br>  {<br>    "action": "Allow",<br>    "name": "allow_azure",<br>    "service_tag": "AzureCloud"<br>  }<br>]</pre> | no |
| <a name="input_key_vault"></a> [key\_vault](#input\_key\_vault) | Configure Linux Function App to Key Vault | <pre>object({<br>    id                  = optional(string, null)<br>    key_permissions     = optional(list(string), null)<br>    secret_permissions  = optional(list(string), ["Get", "List"])<br>    storage_permissions = optional(list(string), null)<br>  })</pre> | `{}` | no |
| <a name="input_location"></a> [location](#input\_location) | Location | `string` | n/a | yes |
| <a name="input_logs"></a> [logs](#input\_logs) | Logs configuration | <pre>object({<br>    detailed_error_messages = bool<br>    failed_request_tracing  = bool<br>    http_logs = object({<br>      file_system = object({<br>        retention_in_days = number<br>        retention_in_mb   = number<br>      })<br>    })<br>  })</pre> | <pre>{<br>  "detailed_error_messages": false,<br>  "failed_request_tracing": false,<br>  "http_logs": {<br>    "file_system": {<br>      "retention_in_days": 7,<br>      "retention_in_mb": 35<br>    }<br>  }<br>}</pre> | no |
| <a name="input_name"></a> [name](#input\_name) | Web index/name (like 007) | `string` | n/a | yes |
| <a name="input_project"></a> [project](#input\_project) | Project name | `string` | n/a | yes |
| <a name="input_resource_group"></a> [resource\_group](#input\_resource\_group) | Resource group name | `string` | n/a | yes |
| <a name="input_scm_ip_restriction"></a> [scm\_ip\_restriction](#input\_scm\_ip\_restriction) | Firewall settings for the function app | <pre>list(object({<br>    name                      = string<br>    ip_address                = optional(string, null)<br>    service_tag               = optional(string, null)<br>    virtual_network_subnet_id = optional(string, null)<br>    priority                  = optional(string, "100")<br>    action                    = string<br>    headers = optional(list(object({<br>      x_azure_fdid      = optional(list(string), null)<br>      x_fd_health_probe = optional(list(string), null)<br>      x_forwarded_for   = optional(list(string), null)<br>      x_forwarded_host  = optional(list(string), null)<br>    })), [])<br>  }))</pre> | <pre>[<br>  {<br>    "action": "Allow",<br>    "name": "allow_azure",<br>    "service_tag": "AzureCloud"<br>  }<br>]</pre> | no |
| <a name="input_service_plan_id"></a> [service\_plan\_id](#input\_service\_plan\_id) | App Service plan ID | `string` | n/a | yes |
| <a name="input_site_config"></a> [site\_config](#input\_site\_config) | Site configuration | <pre>object({<br>    always_on                                     = optional(bool, true)<br>    ftps_state                                    = optional(string, "Disabled")<br>    http2_enabled                                 = optional(bool, true)<br>    websockets_enabled                            = optional(bool, false)<br>    use_32_bit_worker                             = optional(bool, false)<br>    container_registry_use_managed_identity       = optional(bool, false)<br>    container_registry_managed_identity_client_id = optional(string, null)<br>    worker_count                                  = optional(number, null)<br>  })</pre> | `{}` | no |
| <a name="input_storage_account"></a> [storage\_account](#input\_storage\_account) | BYOS storage mount configuration | <pre>list(object({<br>    access_key   = string<br>    account_name = string<br>    name         = string<br>    share_name   = string<br>    type         = string<br>    mount_path   = string<br>  }))</pre> | `[]` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet ID for the web app | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags | `map(string)` | n/a | yes |
| <a name="input_use_private_net"></a> [use\_private\_net](#input\_use\_private\_net) | Use private network injection | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_id"></a> [id](#output\_id) | Linux Web App ID |
| <a name="output_identity"></a> [identity](#output\_identity) | Function app Managed Identity |
<!-- END_TF_DOCS -->

## License

Apache 2 Licensed. For more information please see [LICENSE](https://github.com/data-platform-hq/terraform-azurerm-linux-web-app/tree/main/LICENSE)
