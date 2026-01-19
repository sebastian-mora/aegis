locals {
  name = "${var.stage_name}-${var.api_name}"
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

  payload_format_version = "2.0" # This should match the payload version for API Gateway v2
}

resource "aws_apigatewayv2_integration" "lambda_public_key" {
  api_id             = aws_apigatewayv2_api.api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.get_public_key.arn
  integration_method = "POST"

  payload_format_version = "2.0"
}


resource "aws_apigatewayv2_route" "sign" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "POST /sign_user_key"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}" # Updated target for Lambda integration

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.odic_auth.id
}

# Public key endpoint - no authentication required
resource "aws_apigatewayv2_route" "public_key" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "GET /aegis.pub"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_public_key.id}"

  authorization_type = "NONE"
}


resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = var.stage_name
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access_logs.arn
    format = jsonencode({
      accountId       = "$context.accountId"
      apiId           = "$context.apiId"
      requestId       = "$context.requestId"
      sourceIp        = "$context.identity.sourceIp"
      userAgent       = "$context.identity.userAgent"
      requestTime     = "$context.requestTime"
      httpMethod      = "$context.httpMethod"
      routeKey        = "$context.routeKey"
      status          = "$context.status"
      protocol        = "$context.protocol"
      responseLength  = "$context.responseLength"
      authorizerError = "$context.authorizer.error"
    })
  }

  depends_on = [
    aws_apigatewayv2_route.sign,
    aws_apigatewayv2_route.public_key
  ]

}

// Create CloudWatch Log Group for API Gateway access logs
resource "aws_cloudwatch_log_group" "apigw_access_logs" {
  name = "/aws/apigateway/${local.name}-access-logs"
}


// Create API Gateway Account for logging
resource "aws_api_gateway_account" "apgw_account" {
  cloudwatch_role_arn = aws_iam_role.cloudwatch.arn
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cloudwatch" {
  name               = "${var.stage_name}-api-gateway-cloudwatch-global"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "cloudwatch" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]

    resources = ["*"]
  }
}
resource "aws_iam_role_policy" "cloudwatch" {
  name   = "default"
  role   = aws_iam_role.cloudwatch.id
  policy = data.aws_iam_policy_document.cloudwatch.json
}