# AWS LDAP Authenticator

Authenticate in LDAP Server using AWS EKS tokens. Like [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator), but for LDAP.

## Features
- Validates EKS tokens by calling AWS STS
- Enforces allowed ARN prefixes
- Extracts LDAP identity from ARN
- Optional DN suffix and CN prefix checks for strict Bind DN validation
- Lightweight LDAP server

## How it works

It works just like [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator).

1. Client performs LDAP Bind with DN `<prefix><username>[,ou=<group>]<suffix>` and password set to an EKS token (`k8s-aws-v1.<...>`).
1. Server validates LDAP DN against configured suffix.
1. Server decodes the token to a presigned STS URL, validates it, and calls STS with `x-k8s-aws-id=<EKS_CLUSTER_ID>`.
1. Server validates STS address against allowlist.
1. On success, server receives the caller ARN and validates it against configured rules (prefixes).
1. Server tries to extract LDAP identity from ARN and validates it against configured rules (cn, ou).

## Configuration

Configure via environment variables:

- `EKS_CLUSTER_ID` (required): EKS cluster name/ID used in the `x-k8s-aws-id` header
- `STS_HOSTS` (optional, comma-separated): Allowlist of STS origins. Default: `https://sts.amazonaws.com`
- `ARN_PREFIXES` (optional, comma-separated): Allowed ARN prefixes. Default: `arn:aws:`
- `LDAP_HOST` (optional): Listen host. Default: `0.0.0.0`
- `LDAP_PORT` (optional): Listen port. Default: `3893`
- `LDAP_SUFFIX` (optional): Suffix that must match the Bind DN, e.g. `,dc=evil,dc=corp`
- `LDAP_PREFIX` (optional): Required CN prefix in Bind DN, e.g. `cn=aws_iam_`
- `LOG_LEVEL` (optional): `debug|info|warn|error`. Default: `info`
- `REQUEST_TIMEOUT_SECONDS` (optional): STS request timeout. Default: `10`

## Build

Requirements: Go 1.21+

```bash
go build -o dist/aws-ldap-authenticator ./cmd/aws-ldap-authenticator
```

To build docker image:
```bash
goreleaser release --snapshot --clean
```

Image will be named as `goreleaser.ko.local:0.1.0-SNAPSHOT-XXX`

## Run

### Run locally

```bash
export EKS_CLUSTER_ID="my-eks-cluster"
export STS_HOSTS="https://sts.eu-central-1.amazonaws.com"
export ARN_PREFIXES="arn:aws:"
export LDAP_PREFIX="cn=aws_iam_"
export LDAP_SUFFIX=",dc=evil,dc=corp"

./dist/aws-ldap-authenticator
```

It listens on `LDAP_HOST:LDAP_PORT` (default `0.0.0.0:3893`).

You can also use [air](https://github.com/air-verse/air) to run the server with hot reloading. Place `.env` file in the root directory and run `air`. Ensure that the `.env` file is respected. I use [mise](https://github.com/jdx/mise) for this.

### Helm

Install via the published Helm chart (Helm 3):

```bash
helm repo add aws-ldap-authenticator https://rgeraskin.github.io/aws-ldap-authenticator/
helm repo update

helm install aws-ldap-authenticator aws-ldap-authenticator/aws-ldap-authenticator \
  --create-namespace --namespace aws-ldap-authenticator \
  --version 0.1.0
```

## Examples

### Use with Postgres in Docker

1. Bring up Postgres with Docker and configure LDAP in `pg_hba.conf` to point to this authenticator. See `docker-compose.yml` for the example configuration. `pg_hba.conf` host rule looks like this:

   ```
   host all /^aws_iam_.+ all ldap ldapurl="ldap://host.docker.internal:3893" ldapprefix="cn=" ldapsuffix=",dc=evil,dc=corp"
   ```

   Restart Postgres after editing `pg_hba.conf`.

1. Create a user in Postgres with `CREATE USER aws_iam_john.doe;`
1. Start the server with `./dist/aws-ldap-authenticator` with example environment variables like in the example above.
1. Get token with `TOKEN=$(aws eks get-token --cluster-name my-eks-cluster --query 'status.token' --output text)`
1. Login to Postgres with `PGPASSWORD="$TOKEN" pgcli -h 127.0.0.1 -p 5432 postgres -U aws_iam_john.doe`

### Use with Postgres in Kubernetes ([CNPG](https://cloudnative-pg.io))

CNPG operator should be installed in advance.

1. Deploy the server with Helm:
   ```bash
   helm repo add aws-ldap-authenticator https://rgeraskin.github.io/aws-ldap-authenticator/
   helm repo update
   helm install aws-ldap-authenticator aws-ldap-authenticator/aws-ldap-authenticator \
     --create-namespace --namespace aws-ldap-authenticator \
     --version 0.1.0
   ```
1. Deploy the Postgres cluster with Helm. See [cnpg-values.yaml](cnpg-values.yaml) for the example configuration.
   ```bash
   helm repo add cnpg https://cloudnative-pg.github.io/charts
   helm repo update
   helm install cnpg-cluster cnpg/cluster -f cnpg-values.yaml
   ```
1. Get token with `TOKEN=$(aws eks get-token --cluster-name my-eks-cluster --query 'status.token' --output text)`
1. Login to Postgres with `PGPASSWORD="$TOKEN" pgcli -h <CNPG_LB_IP> -p 5432 postgres -U aws_iam_john.doe`

## Bind DN formats derived from ARN

Possible ARN formats:

| name                         | description                                           | example                                                                                                  | format                                                                      | cn                             | ou                           |
|------------------------------|-------------------------------------------------------|----------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|--------------------------------|------------------------------|
| Root User                    | Using the AWS root account credentials (not advised)  | `arn:aws:iam::123456789012:root`                                                                         | `arn:aws:iam::<account-id>:root`                                            | `root`                         | (empty)                      |
| IAM User                     | Logged in with long-term access keys of an IAM user   | `arn:aws:iam::123456789012:user/jane.doe`                                                                | `arn:aws:iam::<account-id>:user/<user-name>`                                | `jane.doe`                     | (empty)                      |
| IAM Role (Assumed)           | When calling with temporary creds from sts:AssumeRole | `arn:aws:sts::123456789012:assumed-role/AdminRole/Alice`                                                 | `arn:aws:sts::<account-id>:assumed-role/<role-name>/<session-name>`         | `Alice`                        | `AdminRole`                  |
| Cross-Account Role (Assumed) | When assuming a role in another AWS account           | `arn:aws:sts::123456789012:assumed-role/AdminRole/Alice`                                                 | `arn:aws:sts::<account-id>:assumed-role/<role-name>/<session-name>`         | `Alice`                        | `AdminRole`                  |
| Federated User               | Temporary creds from SAML, OIDC, or custom federation | `arn:aws:sts::123456789012:federated-user/GoogleOIDC:jane`                                               | `arn:aws:sts::<account-id>:federated-user/<user-name>`                      | `jane`                         | (empty)                      |
| Service-Linked Role          | When AWS services assume roles on your behalf         | `arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling` | `arn:aws:iam::<account-id>:role/aws-service-role/<service-name><role-name>` | `AWSServiceRoleForAutoScaling` | `autoscaling.amazonaws.com/` |

If `LDAP_SUFFIX` is set, the DN must end with it. If an `ou` is present, it must equal the role/group extracted from the ARN. No additional RDNs are allowed.

### Security notes
- Only allow trusted STS endpoints via `STS_HOSTS`
- Allow only trusted ARN prefixes via `ARN_PREFIXES`
- Prefer running behind a network boundary or ingress; consider StartTLS/LDAPS termination in front if needed
- Tokens are short‑lived; rotate and scope role permissions appropriately
- Debug logs may include metadata; avoid enabling `debug` in production

### Logging
Log level is controlled by `LOG_LEVEL`. Logs include timestamps and caller information.

### License

MIT License. See `LICENSE`.
