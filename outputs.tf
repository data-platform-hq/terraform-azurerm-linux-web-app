output "id" {
  value       = azurerm_linux_web_app.this.id
  description = "Linux Web App ID"
}

output "identity" {
  value       = azurerm_linux_web_app.this.identity.*
  description = "Function app Managed Identity"
}
