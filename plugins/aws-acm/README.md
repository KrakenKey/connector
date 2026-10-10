# aws-acm target plugin

A target for the KrakenKey connector that installs certificates in
[AWS Certificate Manager](https://docs.aws.amazon.com/acm/latest/userguide/)
(ACM) by re-importing them into an existing imported certificate.

Re-importing keeps the certificate's ARN, so every service that uses it
(Application and Network Load Balancers, CloudFront, API Gateway
and others) picks up the new certificate without any change on their side.

Binary: `krakenkey-connector-plugin-aws-acm`. It only reads and re-imports
the one certificate it is configured with, and never creates or deletes
certificates.

## How it works

| Call | What it does in AWS |
|------|---------------------|
| `Validate` | `DescribeCertificate`: the certificate must exist in the configured region and be an imported certificate. |
| `Current` | `DescribeCertificate`: reports the serial ACM holds under the ARN. |
| `Stage` | `DescribeCertificate` only. Checks the certificate, chain and key (key matches, valid now, key at most 5 KB) and that ACM will take it as a replacement (same key type, no key usage or extended key usage removed, every name the ACM certificate covers now is still covered). ACM has no staging, so nothing changes; the checked material waits in the plugin's memory for `Activate`. |
| `Activate` | `ImportCertificate` with the ARN, certificate, chain and key. The previous ref is the serial ACM held before. If it fails, ACM still holds the previous certificate. If ACM's answer is lost (for example a timeout), the plugin asks ACM which certificate it holds before reporting a failure. |
| `Rollback` | `ImportCertificate` with the previous certificate, chain and key, which the connector hands back (see below). |
| `Discard` | Drops staged material from memory. |

ACM never returns an imported certificate's private key, so the plugin
cannot keep the previous certificate itself. It sets the
`rollback_needs_material` capability, and the connector hands back the
certificate it last deployed to this target and its key when it rolls back.
That needs a key store that allows export (the built-in `local` key store
does). Without the material, for example on the very first deployment over
a certificate you imported by hand, a failed deployment is not rolled back
and the new certificate stays in ACM.

## Setup

The plugin re-imports into a certificate that already exists, so import one
certificate yourself first and put its ARN in the config. It can be a
temporary self-signed certificate, as long as:

- its key type is the one in `key_store.key_type` (ACM cannot change the key
  type on reimport), and
- it covers only names the KrakenKey certificate also covers (the plugin
  refuses to stop serving a name the ACM certificate serves).

For example, for `ecdsa-p256` and `api.example.com`:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj /CN=api.example.com -addext subjectAltName=DNS:api.example.com \
  -keyout placeholder.key -out placeholder.pem
aws acm import-certificate --region eu-west-1 \
  --certificate fileb://placeholder.pem --private-key fileb://placeholder.key \
  --tags Key=managed-by,Value=krakenkey-connector
rm placeholder.key
```

For RSA use `-newkey rsa:2048` instead. The command prints the ARN. Attach
the certificate to your load balancer listener, distribution or domain name,
then run the connector; its first pass replaces the placeholder.

Tags can only be set on that first import: ACM refuses tags on reimport and
keeps the existing ones, so the plugin never sends any.

The plugin does not create certificates (there is no `create_if_missing`).
It is stateless, so an ARN it created would only live in a log line until
someone copied it into the config, and every pass in between would create
another certificate. Importing once by hand keeps the ARN in your config and
in whatever references it.

## Configuration

```yaml
plugins:
  aws-acm:
    path: /usr/local/libexec/krakenkey-connector/krakenkey-connector-plugin-aws-acm
    sha256: "<sha256 of the binary>"

certificates:
  - id: 1043
    names: [api.example.com, www.example.com]
    key_store: { plugin: local, key_type: ecdsa-p256 }
    targets:
      - label: public-alb
        plugin: aws-acm
        region: eu-west-1
        certificate_arn: arn:aws:acm:eu-west-1:123456789012:certificate/0f3c8a52-1b9e-4d7a-9c61-2a5e8b7d4f10
        verify:
          host: api.example.com
          window: 10m
```

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `region` | string | required | AWS region of the certificate, for example `eu-west-1`. Must match the region in `certificate_arn`. CloudFront and edge-optimized API Gateway domains use certificates in `us-east-1`. |
| `certificate_arn` | string | required | ARN of an imported ACM certificate (`arn:aws:acm:<region>:<account>:certificate/<id>`). Certificates ACM issued itself (`AMAZON_ISSUED`) or AWS Private CA issued (`PRIVATE`) are refused: ACM does not allow importing over them. |

Other keys are refused, so a typo shows up in `krakenkey-connector validate`.

### Key types

The plugin accepts `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072` and
`rsa-4096`, which ACM imports. The services using the certificate may take
fewer:

| Service | Key types |
|---------|-----------|
| Application Load Balancer | all of the above |
| CloudFront | `ecdsa-p256`, `rsa-2048`, `rsa-3072`, `rsa-4096` (no P-384) |
| API Gateway custom domains | RSA keys up to 2048 bits; edge-optimized domains also follow CloudFront's rules |

`rsa-2048` is the safe choice when one certificate serves several services;
`ecdsa-p256` works with load balancers and CloudFront. Check the
documentation of the service you use before picking anything else. The
connector cannot see which services use the certificate, so it does not
check this for you.

### Verify window

The default verify window is 10 minutes. Load balancers serve a re-imported
certificate within a few minutes. CloudFront can take longer to reach every
edge location; set `verify.window: 30m` for distributions so a slow
propagation is not rolled back as a failure.

## Credentials

The plugin uses the AWS SDK for Go v2 default credential chain, which
covers environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`), the shared config and credentials files (`AWS_PROFILE`),
web identity (`AWS_ROLE_ARN` with `AWS_WEB_IDENTITY_TOKEN_FILE`, as set by EKS
IAM roles for service accounts), the ECS task role, and the EC2 instance
profile. The connector passes its environment to the plugin, so set these
for the connector. Prefer a task role or instance profile to static keys.

`AWS_ENDPOINT_URL_ACM` points the plugin at another ACM endpoint (for
example LocalStack); leave it unset in production.

## Permissions

The connector's credentials need `acm:DescribeCertificate` and
`acm:ImportCertificate` on the certificates it manages, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KrakenKeyConnectorReimport",
      "Effect": "Allow",
      "Action": [
        "acm:DescribeCertificate",
        "acm:ImportCertificate"
      ],
      "Resource": [
        "arn:aws:acm:eu-west-1:123456789012:certificate/0f3c8a52-1b9e-4d7a-9c61-2a5e8b7d4f10"
      ]
    }
  ]
}
```

List each certificate ARN the connector manages. An import that sets tags
also needs `acm:AddTagsToCertificate`, but the plugin never sends tags (ACM
refuses them on reimport), so it does not need it. Your own first import
needs `acm:ImportCertificate` and, with `--tags`, `acm:AddTagsToCertificate`
for whoever runs it.

When AWS refuses a call, the error names the action, for example
`AWS denied acm:ImportCertificate on arn:...; allow acm:ImportCertificate
for the connector's credentials`. Access errors are permanent and retried on
a later pass only after a config or policy change; throttling, server errors
and network errors are retried.

## Limitations

- Rollback needs the previous certificate and key from the connector, so it
  needs an exportable key store. It is not possible on the first deployment
  over a certificate imported by hand.
- ACM refuses a reimport that changes the key type or removes a key usage or
  extended key usage (except Client Authentication, and Key Encipherment on
  ECDSA keys). `Stage` checks this first and reports it, so nothing changes.
  The same rule applies to rollback: if the new certificate added a usage the
  previous one lacked, ACM refuses to go back.
- Dropping a name: the plugin refuses a certificate that does not cover a
  name the ACM certificate covers now. If that is intended, re-import a
  certificate without the name yourself first.
- Staged material lives in the plugin process's memory for at most an hour.
  The connector activates right after staging; if the plugin restarts in
  between, the deployment is retried on the next pass.
- `ImportCertificate` is limited to one request per second per account and
  region. Throttled calls are retried by the SDK and, if that is not enough,
  on the next pass.

## Development

```sh
go test ./... -race
```

The tests run against an in-process fake of the ACM API and drive the built
binary over go-plugin gRPC. To also run them against LocalStack:

```sh
docker run --rm -d --name localstack-acm -p 4566:4566 -e SERVICES=acm localstack/localstack:4.14.0
KK_TEST_LOCALSTACK_ENDPOINT=http://localhost:4566 go test ./internal/acmtarget/ -run LocalStack -v
docker stop localstack-acm
```

`4.14.0` is the last LocalStack community image that starts without an
account token; later images need `LOCALSTACK_AUTH_TOKEN`. LocalStack differs
from ACM in a few ways the tests allow for: it reports serials in decimal,
spells key algorithms with a dash, and drops tags on reimport.
