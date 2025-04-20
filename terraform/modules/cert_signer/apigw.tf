locals {
  name = "${var.stage_name}-${var.api_name}"
  scopes = {
    sign_user_key = "sign:user_key"
  }
}

resource "aws_apigatewayv2_api" "api" {
  name          = local.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "odic_auth" {
  api_id           = aws_apigatewayv2_api.api.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${local.name}-odic"

  jwt_configuration {
    audience = var.jwt_audience
    issuer   = var.jwt_issuer
  }
}


resource "aws_apigatewayv2_integration" "lambda" {
  api_id             = aws_apigatewayv2_api.api.id
  integration_type   = "AWS_PROXY"  
  integration_uri    = aws_lambda_function.ssh_cert_signer.arn 
  integration_method = "POST"  

  payload_format_version = "2.0"  # This should match the payload version for API Gateway v2
}


resource "aws_apigatewayv2_route" "sign" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "POST /sign_user_key"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"  # Updated target for Lambda integration

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.odic_auth.id
  authorization_scopes = [ local.scopes.sign_user_key ]
}


resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = var.stage_name
  auto_deploy = true

  depends_on = [
    aws_apigatewayv2_route.sign
  ]
}
