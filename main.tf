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
      java_version = var.java_version
    }
  }
}

resource "azurerm_app_service_virtual_network_swift_connection" "this" {
  count          = var.use_private_net == null ? 0 : 1
  app_service_id = azurerm_linux_web_app.this.id
  subnet_id      = var.subnet_id
}
