# Aegis SSH Certificate Signer

Aegis is a serverless SSH certificate authority built on AWS Lambda that simplifies SSH key management by issuing short-lived, signed certificates. It uses OpenID Connect (OIDC) for authentication and integrates with AWS KMS to securely manage the Certificate Authority (CA) private key.

Clients authenticate using the OIDC Device Authorization Flow. After successful authentication, the user's public key is sent to the Aegis API for signing. The signing function uses the OIDC ID token to map user attributes (e.g., email) to the SSH certificate's principal field.

All signing actions are recorded in an audit trail stored in DynamoDB, enabling traceability and accountability for each certificate issued.

This system provides short-term credentials and simplifies user management, making it easier to control access and minimize long-term key usage.

---



![aegis client](./img/client.png)

### How it Works 
![diagram](./img/diagram.png)


## Setup from Source

### 1. Build the Project

```bash
make build
```

### 2.  Deploy AWS Infrastructure

Before deployment, ensure you have the following OAuth values:
- Audience
- Issuer URL

Then deploy the infrastructure:

```bash
cd terraform
terraform plan
terraform apply
```

### 3. Configure Aegis User Client
```bash
cat <<EOF >> ~/.config/aegis/config
AUTH_DOMAIN="https://login.example.com"
CLIENT_ID="ABCD"
AEGIS_ENDPOINT="https://abcx.execute-api.us-east-1.amazonaws.com"
DEFAUlt_TTL="24h"
AUTHENTICATION_METHOD="pkce"  #(pkce or device_code. pkce is the default if not set)
EOF
```

Alternatively, you can pass the values directly via the command line:
```bash
./aegis \
  -auth-url https://login.example.com \
  -clientid ABCD \
  -aegis-endpoint https://abcx.execute-api.us-east-1.amazonaws.com/...
  -ttl 1h
```

---

## API Endpoints

Aegis exposes two API endpoints via AWS API Gateway. While the **CLI client is the recommended way to sign certificates** (it handles OIDC authentication and key management automatically), understanding the API is useful for custom integrations or debugging.

### Get CA Public Key

Retrieves the Certificate Authority's public key. This is useful for configuring SSH servers to trust certificates signed by Aegis.

```bash
curl https://<your-api-gateway-url>/aegis.pub
```

Add the returned public key to your SSH server's `TrustedUserCAKeys` file:
```bash
curl https://<your-api-gateway-url>/aegis.pub >> /etc/ssh/trusted_user_ca_keys
echo "TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### Sign User Public Key

Signs a user's SSH public key and returns a certificate. Requires a valid OIDC token.

```bash
curl -X POST https://<your-api-gateway-url>/sign_user_key \
  -H "Authorization: Bearer <your-oidc-token>" \
  -d "$(cat ~/.ssh/id_ed25519.pub)" \
  --url-query "ttl=60"
```

Save the certificate for SSH authentication:
```bash
curl -X POST https://<your-api-gateway-url>/sign_user_key \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(cat ~/.ssh/id_ed25519.pub)" \
  > ~/.ssh/id_ed25519-cert.pub

# SSH will automatically use the certificate if it matches your key
ssh user@server
```


