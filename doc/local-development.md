# Local Development

## Prerequisites

- .NET 10 SDK
- Azure Functions Core Tools v4
- Azure CLI
- Azurite
- Bash plus `jq`, and/or PowerShell 7 for operator script tests

## Dev Container

The repository includes a feature-based [development container](../.devcontainer/devcontainer.json) with the .NET 10 SDK, the latest Azure CLI and Bicep, the stable Azure Developer CLI, Azure Functions Core Tools v4, PowerShell, and the VS Code extensions used by this project. Open the repository in VS Code and choose **Reopen in Container** when prompted.

Microsoft-maintained Dev Container features provide Azure CLI and Azure Developer CLI; the .NET image already includes PowerShell. Azure Functions Core Tools uses a community feature because Microsoft does not currently publish an equivalent feature. The Compose-based environment runs Microsoft's official Azurite image in the development container's network namespace, so `UseDevelopmentStorage=true` continues to resolve its services on `localhost`, and it exposes the Functions host and Azurite ports. Authenticate inside the container before using Azure-backed local settings:

```sh
az login
azd auth login
```

The container does not include credentials, `local.settings.json`, an HMAC key, or Azure resource configuration. Copy `src/KeyVaultSync.Function/local.settings.example.json` to ignored `src/KeyVaultSync.Function/local.settings.json` and provide approved disposable values privately.

## Build and Test

```sh
dotnet restore
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj --no-restore
dotnet build src/KeyVaultSync.Function/KeyVaultSync.Function.csproj --no-restore -p:GenerateDocumentationFile=true -warnaserror
bash tests/grant-keyvault-access.tests.sh
bash tests/prepare-deployment.tests.sh
bash tests/postdeploy-keyvault-access.tests.sh
pwsh -NoProfile -File tests/Grant-KeyVaultAccess.Tests.ps1
pwsh -NoProfile -File tests/Prepare-Deployment.Tests.ps1
pwsh -NoProfile -File tests/PostDeploy-KeyVaultAccess.Tests.ps1
az bicep build --file infra/main.bicep --outfile /tmp/keyvaultsync-main.json
```

Script tests use mocked Azure CLI behavior and must not make live Azure changes.

## Local Function Host

Authenticate with Azure CLI for a specifically approved tenant, then run the Function host from `src/KeyVaultSync.Function`. In the Dev Container, Azurite starts as a sidecar. In VS Code, **Run and Debug** → **.NET: Attach to KeyVaultSync Function** starts the local host through the pre-launch task, uses the Azure Functions process picker to select the isolated .NET worker, and attaches the debugger. Outside the container, start Azurite separately before launching the debugger.

The local identity must have the same least-privilege ARM, Blob, Key Vault, and RBAC permissions needed by the behavior being tested. A passing unit test or successful host startup does not prove live permissions or safe mutation.

## Sensitive Data

Never commit or print:

- HMAC keys;
- secret or certificate values;
- private keys;
- connection strings;
- tokens;
- tenant/subscription-specific inventories.

Protect ignored `.azure/`, `local.settings.json`, and local report files. Do not run synchronization against non-disposable vaults as a development check.
