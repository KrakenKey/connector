# Deploy the connector on Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FKrakenKey%2Fconnector%2Fmain%2Fdeploy%2Fazure%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FKrakenKey%2Fconnector%2Fmain%2Fdeploy%2Fazure%2FcreateUiDefinition.json)

This template runs the connector on a small Ubuntu VM in your own Azure
subscription. The connector renews your KrakenKey certificates with keys that
[Azure Key Vault](../../plugins/azure-keyvault/README.md) creates and keeps,
and can put each renewal on an
[Application Gateway](../../plugins/azure-appgateway/README.md). Services that
read the Key Vault certificate without a version (App Service, Front Door,
Container Apps, API Management and others) pick up each renewal on their own.

The connector itself is free. You pay Azure for what the template creates
(the VM, its disk, and the NAT gateway if you choose one), and KrakenKey for
certificates through your KrakenKey plan.

## Before you start

- **A connector in KrakenKey.** In the dashboard, create a connector with the
  scopes `certs:read` and `certs:renew`, limited to the certificates this VM
  will manage, and copy its enrollment token (`kkce_...`). The token is shown
  once, works once and expires after 24 hours, so deploy soon after creating
  it.
- **The certificates in KrakenKey,** with their ids and names. A certificate
  can already be issued, or be created with names only, waiting for the
  connector to issue it.
- **A Key Vault** to keep keys and certificates in. Each KrakenKey
  certificate gets its own Key Vault certificate name; the connector creates
  it on the first renewal and refuses to take over a certificate it did not
  create (see [Ownership](../../plugins/azure-keyvault/README.md#ownership)).
- **Optionally, an Application Gateway v2** (`Standard_v2` or `WAF_v2`) with a
  user-assigned managed identity, and the SSL certificate entries its HTTPS
  listeners use already in place. See the
  [plugin's requirements](../../plugins/azure-appgateway/README.md#requirements).
- **Permission to grant access.** The template creates custom roles and
  assigns them to the VM, so you need **Owner** or **User Access
  Administrator** (plus rights to create resources) on the subscriptions of
  the vault and the gateway. For a vault that uses access policies instead of
  Azure RBAC, you need permission to change the vault.

## What it creates

In the resource group you deploy to:

| Resource | Notes |
|---|---|
| Virtual machine | Ubuntu 24.04 LTS (latest image), `Standard_B2ats_v2` by default (2 vCPUs, 1 GiB). Trusted launch, SSH key sign-in only, no public IP address, boot diagnostics in managed storage. System-assigned managed identity. |
| OS disk | Managed disk, Standard SSD by default, deleted with the VM. |
| Network interface | Deleted with the VM. |
| Network security group | No rules of its own: nothing needs to reach the connector. Azure's default rules still allow traffic from inside the virtual network, for SSH through Azure Bastion or a VPN. |
| Virtual network and subnet | If you create a new one (default `10.0.0.0/24`, subnet `10.0.0.0/27`). |
| NAT gateway and its public IP address | If you create a new network and keep the recommended outbound access. |

The VM needs outbound HTTPS to `packages.krakenkey.io`, the KrakenKey API,
Azure (Resource Manager, Key Vault, Microsoft Entra ID) and Ubuntu's update
servers. In a new network, choose a NAT gateway (recommended; it costs extra)
or Azure's default outbound access (free, but Microsoft recommends against it
and no longer turns it on by default for new networks). An existing subnet
must already provide outbound access.

Outside the resource group, the template creates custom roles in the
subscriptions of the vault and the gateway, and assigns them to the VM's
identity (see [Permissions](#permissions)).

## The wizard

| Tab | Asks for |
|---|---|
| Basics | Subscription, resource group, region, VM name, VM size (`Standard_B2ats_v2`, `Standard_B2als_v2`, `Standard_B1s`, `Standard_B1ms` or `Standard_B2s`), administrator username and SSH public key. |
| KrakenKey | The enrollment token, and the API URL (`https://api.krakenkey.io`). |
| Key Vault | The vault (any resource group or subscription), whether keys are exportable (default yes; Application Gateway needs it), and whether to allow rollbacks in Key Vault (default no; see [Permissions](#permissions)). |
| Application Gateway | Whether to deploy to a gateway, which one, and whether to give the gateway's identity read access to the vault's secrets (if it does not have it already). |
| Certificates | The key type (RSA 2048 by default; RSA only with a gateway) and a row per certificate: KrakenKey certificate id, its names (comma separated, exactly as in KrakenKey), the Key Vault certificate name, and for a gateway, the SSL certificate entry and an optional host name to check the gateway at after each update. |
| Networking | New or existing virtual network and subnet, and outbound access for a new network. |

The wizard reads the vault's permission model and the gateway's subnets,
public IP addresses, WAF policies and identity from Azure, and passes them
to the template.

## First boot

cloud-init runs [`bootstrap.sh`](bootstrap.sh) once, as root. It:

1. downloads the `krakenkey-archive-keyring` package, checks that its key is
   the [published signing key](../../README.md#debian-ubuntu-fedora-rhel-and-amazon-linux)
   (`386E 2558 2384 DD74 692A 4EE9 F7BA 53A4 E94F A5DA`), installs it, then
   installs `krakenkey-connector` from the signed apt repository;
2. writes `/etc/krakenkey-connector/config.yaml` from your choices: one
   `azure-keyvault` key store per certificate, which deploys to Key Vault
   through its [implicit target](../../README.md#implicit-targets), plus an
   `azure-appgateway` target where you named a gateway entry; and sets
   `AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential` in
   `/etc/default/krakenkey-connector`, so the plugins use the VM's managed
   identity;
3. lets unattended-upgrades upgrade the connector (see [Upgrades](#upgrades));
4. checks the config with `validate --offline`, then enrolls the connector as
   its service user with the token in a file only root and the
   `krakenkey-connector` group can read, and deletes the file;
5. runs `validate` until it passes (the VM's role assignments are created
   after the VM and take a few minutes to apply), for up to 30 minutes, then
   enables and starts the `krakenkey-connector` service.

On its first pass the connector renews every certificate once, so that Key
Vault holds the key, then deploys it. After that it renews when KrakenKey
says a certificate is due. The connector reports to the KrakenKey dashboard
after every pass.

The enrollment token is passed to the VM as custom data (a `secureString`
parameter in the template), which Azure does not return from the API or show
to the instance metadata service. cloud-init keeps a copy of the custom data
in root-only files under `/var/lib/cloud` and `/var/lib/waagent`; the token
in it is useless once the connector has enrolled, since it works only once.
It is never printed, logged or put on a command line.

The deployment finishes when the VM is up, before the first boot is done. To
follow it, sign in to the VM (for example through Azure Bastion) and run:

```sh
cloud-init status --wait --long
sudo grep krakenkey-bootstrap /var/log/cloud-init-output.log
journalctl -u krakenkey-connector
```

### If enrollment failed

If the token expired or was already used, or the config was refused, the
bootstrap stops before starting the service and says why in
`/var/log/cloud-init-output.log`. Fix the config if needed, create a new
enrollment token in the dashboard, and finish by hand as in
[Running as a service](../../README.md#running-as-a-service):

```sh
sudo install -m 0640 -o root -g krakenkey-connector /dev/null /etc/krakenkey-connector/enrollment-token
sudoedit /etc/krakenkey-connector/enrollment-token   # paste the kkce_... token
sudo -u krakenkey-connector env KK_ENROLLMENT_TOKEN_FILE=/etc/krakenkey-connector/enrollment-token \
  krakenkey-connector enroll
sudo rm /etc/krakenkey-connector/enrollment-token
sudo -u krakenkey-connector sh -c 'set -a; . /etc/default/krakenkey-connector; exec krakenkey-connector validate'
sudo systemctl enable --now krakenkey-connector
```

## Permissions

The VM's system-assigned identity gets the least-privilege roles from the
plugin READMEs, as custom roles. A role name must be unique in the tenant, so
each ends with the subscription id, for example
`KrakenKey connector Key Vault (<subscription id>)`. The roles are assignable
anywhere in their subscription, but assigned only on the resources below.
Deploying again in the same subscription reuses them.

| Role | Assigned on | Permissions |
|---|---|---|
| KrakenKey connector Key Vault | The vault | `certificates/read`, `certificates/create/action`, `certificates/update/action` |
| KrakenKey connector Key Vault rollback | The vault, only if you allow rollbacks | `certificates/import/action`, `secrets/getSecret/action` |
| KrakenKey Application Gateway certificate writer | The gateway | `applicationGateways/read`, `applicationGateways/write` |
| KrakenKey Application Gateway linked resources | The gateway's subnets, public IP addresses, WAF policies and user-assigned identity | `read` and `join/action` on each, `assign/action` on the identity |
| Key Vault Secrets User (built in) | The vault, for the gateway's identity, only if you ask for it | Read secrets |

Rollbacks in Key Vault (putting the previous certificate back as the latest
version after a failed deployment) need the rollback role, which lets the VM
read every secret in the vault. Without it, a failed deployment keeps the new
version and is reported as failed; Application Gateway rollbacks do not need
it. See [Rollback](../../plugins/azure-keyvault/README.md#rollback).

For a vault that uses access policies, the VM gets an access policy instead:
certificate permissions Get, List, Create and Update, plus Import and secret
Get with rollbacks; and the gateway's identity, if you ask for it, secret Get.

WAF policies attached to individual path rules are not looked up by the
wizard. If your gateway has any, assign the linked resources role on them
yourself.

## Upgrades

- **The connector:** unattended-upgrades installs new versions of
  `krakenkey-connector` from `packages.krakenkey.io` once a day, along with
  Ubuntu's security updates (`/etc/apt/apt.conf.d/52krakenkey-connector`). The
  package restarts the service after an upgrade. Because the template edits
  the connector's config files, that file also tells dpkg to keep edited
  config files on upgrades instead of asking, for every package on the VM.
  The config declares the bundled plugins without a version, so it keeps
  working across upgrades. To upgrade now: `sudo apt update && sudo apt
  install krakenkey-connector`.
- **Ubuntu:** security updates install automatically; reboots do not. Reboot
  the VM from time to time when `/var/run/reboot-required` exists.
- **The template:** a new version of the template does not change VMs
  already deployed. To change what the connector manages, edit
  `/etc/krakenkey-connector/config.yaml` on the VM (see
  [Configuration](../../README.md#configuration)), run `validate` as above,
  and `sudo systemctl restart krakenkey-connector`. A new certificate in a
  vault or gateway the VM can already reach needs no new roles.

## Uninstall

1. In the KrakenKey dashboard, revoke the connector.
2. Delete the VM, its disk, network interface and network security group,
   and the virtual network and NAT gateway if the template created them. If
   nothing else is in the resource group, delete the resource group.
3. Remove the role assignments (or access policies) for the VM's identity on
   the vault, the gateway and its linked resources. Role assignments of a
   deleted identity stay behind as "Identity not found" until you remove
   them. Remove the custom roles too if nothing else uses them.

The Key Vault certificates, their versions and the gateway's settings stay
as they are: the gateway keeps serving the last certificate it was given.

## Customer usage attribution

When you deploy this template, Microsoft can identify the installation of
KrakenKey software with the deployed Azure resources. Microsoft can correlate
these resources used to support the software. Microsoft collects this
information to provide the best experiences with their products and to
operate their business. The data is collected and governed by Microsoft's
privacy policies, located at <https://www.microsoft.com/trustcenter>.

The attribution is an empty deployment named `pid-<id>` in
`mainTemplate.json`. To opt out, remove the `partnerAttribution` resource from
the template and deploy your copy.

## Working on the template

| File | What it is |
|---|---|
| `main.bicep`, `modules/` | The template, in Bicep. |
| `mainTemplate.json` | Compiled from `main.bicep`. Commit it with every change. |
| `createUiDefinition.json` | The portal wizard. |
| `cloud-init.yaml`, `bootstrap.sh` | The first-boot setup, embedded in the template. |

```sh
make azure-template        # compile main.bicep into mainTemplate.json
make azure-template-check  # check that mainTemplate.json is current (CI runs this)
make azure-test            # ARM template test toolkit and cloud-init schema (CI runs this)
make azure-package         # dist/azure/krakenkey-connector-azure.zip for Partner Center
```

These use the Azure CLI and PowerShell if installed, otherwise their
container images. None of them signs in to Azure or deploys anything. To try
the wizard against your own subscription, open the
[Create UI Definition Sandbox](https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/SandboxBlade)
and paste `createUiDefinition.json`.
