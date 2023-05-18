output "id" {
  value       = azurerm_linux_web_app.this.id
  description = "Linux Web App ID"
}

output "identity" {
  value       = azurerm_linux_web_app.this.identity[*]
  description = "Linux Web App Managed Identity"
}

output "default_hostname" {
  value       = azurerm_linux_web_app.this.default_hostname
  description = "Linux Web App default hostname"
}
