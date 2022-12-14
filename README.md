# Azure Linux Web App Terraform module
Terraform module for creation Azure Linux Web App

## Usage

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.23.0 |

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
| [azurerm_linux_web_app.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_web_app) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_settings"></a> [app\_settings](#input\_app\_settings) | Application setting | `map(string)` | `{}` | no |
| <a name="input_application_stack"></a> [application\_stack](#input\_application\_stack) | Application stack configuration, run `az webapp list-runtimes --os-type linux` to get the list of supported stacks | `map(string)` | <pre>{<br>  "java_server": "JAVA",<br>  "java_server_version": 11,<br>  "java_version": "java11"<br>}</pre> | no |
| <a name="input_application_type"></a> [application\_type](#input\_application\_type) | Application type (java, python, etc) | `string` | `"java"` | no |
| <a name="input_enable_appinsights"></a> [enable\_appinsights](#input\_enable\_appinsights) | Enable application insights | `bool` | `true` | no |
| <a name="input_appinsights_log_workspace_id"></a> [appinsights\_log\_workspace\_id](#input\_appinsights\_log\_workspace\_id) | Resource ID of Log Analytics workspace | `string` | `null` | no |
| <a name="input_env"></a> [env](#input\_env) | Environment | `string` | n/a | yes |
| <a name="input_identity_ids"></a> [identity\_ids](#input\_identity\_ids) | List of user assigned identity IDs | `list(string)` | `null` | no |
| <a name="input_ip_restriction"></a> [ip\_restriction](#input\_ip\_restriction) | Firewall settings for the web app | <pre>list(object({<br>    name                      = string<br>    ip_address                = string<br>    service_tag               = string<br>    virtual_network_subnet_id = string<br>    priority                  = string<br>    action                    = string<br>    headers = list(object({<br>      x_azure_fdid      = list(string)<br>      x_fd_health_probe = list(string)<br>      x_forwarded_for   = list(string)<br>      x_forwarded_host  = list(string)<br>    }))<br>  }))</pre> | <pre>[<br>  {<br>    "action": "Allow",<br>    "headers": null,<br>    "ip_address": null,<br>    "name": "allow_azure",<br>    "priority": "100",<br>    "service_tag": "AzureCloud",<br>    "virtual_network_subnet_id": null<br>  }<br>]</pre> | no |
| <a name="input_location"></a> [location](#input\_location) | Location | `string` | n/a | yes |
| <a name="input_logs"></a> [logs](#input\_logs) | Logs configuration | <pre>object({<br>    detailed_error_messages = bool<br>    failed_request_tracing  = bool<br>    http_logs = object({<br>      file_system = object({<br>        retention_in_days = number<br>        retention_in_mb   = number<br>      })<br>    })<br>  })</pre> | <pre>{<br>  "detailed_error_messages": false,<br>  "failed_request_tracing": false,<br>  "http_logs": {<br>    "file_system": {<br>      "retention_in_days": 7,<br>      "retention_in_mb": 35<br>    }<br>  }<br>}</pre> | no |
| <a name="input_name"></a> [name](#input\_name) | Web index/name (like 007) | `string` | n/a | yes |
| <a name="input_project"></a> [project](#input\_project) | Project name | `string` | n/a | yes |
| <a name="input_resource_group"></a> [resource\_group](#input\_resource\_group) | Resource group name | `string` | n/a | yes |
| <a name="input_scm_ip_restriction"></a> [scm\_ip\_restriction](#input\_scm\_ip\_restriction) | Firewall settings for the SCM web app | <pre>list(object({<br>    name                      = string<br>    ip_address                = string<br>    service_tag               = string<br>    virtual_network_subnet_id = string<br>    priority                  = string<br>    action                    = string<br>    headers = list(object({<br>      x_azure_fdid      = list(string)<br>      x_fd_health_probe = list(string)<br>      x_forwarded_for   = list(string)<br>      x_forwarded_host  = list(string)<br>    }))<br>  }))</pre> | `null` | no |
| <a name="input_service_plan_id"></a> [service\_plan\_id](#input\_service\_plan\_id) | App Service plan ID | `string` | n/a | yes |
| <a name="input_storage_account"></a> [storage\_account](#input\_storage\_account) | BYOS storage mount configuration | <pre>list(object({<br>    access_key   = string<br>    account_name = string<br>    name         = string<br>    share_name   = string<br>    type         = string<br>    mount_path   = string<br>  }))</pre> | `[]` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet ID for the web app | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags | `map(string)` | n/a | yes |
| <a name="input_use_private_net"></a> [use\_private\_net](#input\_use\_private\_net) | Use private network injection | `bool` | `false` | no |
| <a name="input_websockets_enabled"></a> [websockets\_enabled](#input\_websockets\_enabled) | Enable websockets | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_id"></a> [id](#output\_id) | Linux Web App ID |
| <a name="output_identity"></a> [identity](#output\_identity) | Function app Managed Identity |
<!-- END_TF_DOCS -->

## License

Apache 2 Licensed. For more information please see [LICENSE](https://github.com/data-platform-hq/terraform-azurerm-linux-web-app/tree/main/LICENSE)
