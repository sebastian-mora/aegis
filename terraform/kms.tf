resource "aws_kms_key" "ssh_user_ca_key" {
  description              = "${var.stage_name}-ssh-user-ca-key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = 7
  tags = {
    Name  = "${var.stage_name}-ssh-user-ca-key"
    Stage = var.stage_name
  }
}