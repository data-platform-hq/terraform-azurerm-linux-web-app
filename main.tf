resource "azurerm_application_insights" "this" {
  name                = "fn-${var.project}-${var.env}-${var.location}-${var.name}"
  location            = var.location
  resource_group_name = var.resource_group
  application_type    = var.application_type
  tags                = var.tags
}

locals {
  app_settings = {
    WEBSITES_ENABLE_APP_SERVICE_STORAGE = "true"
    WEBSITE_ENABLE_SYNC_UPDATE_SITE     = "true"
    JAVA_OPTS                           = "-Dlog4j2.formatMsgNoLookups=true"
    LOG4J_FORMAT_MSG_NO_LOOKUPS         = "true"
    WEBSITE_USE_PLACEHOLDER             = "0"
    AZURE_LOG_LEVEL                     = "info"
    APPINSIGHTS_INSTRUMENTATIONKEY      = azurerm_application_insights.this.instrumentation_key
  }
  application_stack_struct = {
    docker_image        = null
    docker_image_tag    = null
    dotnet_version      = null
    java_server         = null
    java_server_version = null
    java_version        = null
    php_version         = null
    python_version      = null
    node_version        = null
    ruby_version        = null
  }
  application_stack = merge(local.application_stack_struct, var.application_stack)
}

resource "azurerm_linux_web_app" "this" {
  depends_on          = [azurerm_application_insights.this]
  name                = "web-${var.project}-${var.env}-${var.location}-${var.name}"
  location            = var.location
  resource_group_name = var.resource_group
  service_plan_id     = var.service_plan_id
  https_only          = true
  enabled             = true
  tags                = var.tags
  app_settings        = merge(local.app_settings, var.app_settings)

  identity {
    type = "SystemAssigned"
  }
  site_config {
    always_on          = true
    ftps_state         = "Disabled"
    http2_enabled      = true
    websockets_enabled = false
    use_32_bit_worker  = false
    ip_restriction     = var.ip_restriction
    scm_ip_restriction = var.ip_restriction
    application_stack {
      docker_image        = local.application_stack["docker_image"]
      docker_image_tag    = local.application_stack["docker_image_tag"]
      dotnet_version      = local.application_stack["dotnet_version"]
      java_server         = local.application_stack["java_server"]
      java_server_version = local.application_stack["java_server_version"]
      java_version        = local.application_stack["java_version"]
      php_version         = local.application_stack["php_version"]
      python_version      = local.application_stack["python_version"]
      node_version        = local.application_stack["node_version"]
      ruby_version        = local.application_stack["ruby_version"]
    }
  }
  lifecycle {
    ignore_changes = [
      tags["hidden-link: /app-insights-conn-string"],
      tags["hidden-link: /app-insights-instrumentation-key"],
      tags["hidden-link: /app-insights-resource-id"],
      virtual_network_subnet_id
    ]
  }
}

resource "azurerm_app_service_virtual_network_swift_connection" "this" {
  count          = var.use_private_net ? 1 : 0
  app_service_id = azurerm_linux_web_app.this.id
  subnet_id      = var.subnet_id
}
