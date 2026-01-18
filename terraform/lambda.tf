data "aws_secretsmanager_secret" "user_ca_secret_id" {
  name = var.user_ca_secret_name
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Use the pre-built Lambda zip file
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../build/bootstrap"
  output_path = "${path.module}/../dist/lambda.zip"
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.stage_name}-lambda-ssh-cert-signing-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_signing_policy" {
  name = "${var.stage_name}-lambda-ssh-cert-signing-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["kms:Sign", "kms:GetPublicKey"]
        Resource = aws_kms_key.ssh_user_ca_key.arn
      },
            {
        Effect = "Allow"
        Action = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.audit_table.arn
      },
      {
        Effect = "Allow"
        Action = ["kms:GetPublicKey", "kms:Sign"]
        Resource = aws_kms_key.ssh_user_ca_key.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_permission" "allow_apigw_to_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ssh_cert_signer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.api.id}/*/*/*"
}

resource "aws_lambda_function" "ssh_cert_signer" {
  function_name    = "${var.stage_name}-aegis-ssh-cert-signer"  
  role             = aws_iam_role.lambda_role.arn
  package_type     = "Zip"
  filename         = data.archive_file.lambda_zip.output_path 
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256  
  handler          = "bootstrap"
  runtime          = var.lambda_runtime
  architectures    = ["x86_64"]

  environment {
    variables = {
      KMS_KEY_ID         = aws_kms_key.ssh_user_ca_key.key_id
      JSME_PATH_EXPRESSION = var.jsme_expression
      DYNAMO_DB_TABLE      = aws_dynamodb_table.audit_table.name
    }
  }
  depends_on = [data.archive_file.lambda_zip]
}


