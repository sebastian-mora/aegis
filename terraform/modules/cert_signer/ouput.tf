output "api_id" {
  description = "The ID of the API"
  value       = aws_apigatewayv2_api.api.id
}

output "api_url" {
  description = "The URL of the API"
  value       = aws_apigatewayv2_api.api.api_endpoint
}
