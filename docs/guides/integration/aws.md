---
title: AWS CodeArtifact
description: Using uv with AWS CodeArtifact for installing and publishing Python packages.
---

# AWS CodeArtifact

uv can install packages from
[AWS CodeArtifact](https://docs.aws.amazon.com/codeartifact/latest/ug/using-python.html) using
credentials from the environment. You can also provide an access token explicitly, or use the
[`keyring`](https://github.com/jaraco/keyring) package.

The index can be declared like so:

```toml title="pyproject.toml"
[[tool.uv.index]]
name = "private-registry"
url = "https://<DOMAIN>-<ACCOUNT_ID>.d.codeartifact.<REGION>.amazonaws.com/pypi/<REPOSITORY>/simple/"
```

## Authenticate with AWS credentials

uv automatically searches for credentials when accessing AWS CodeArtifact indexes over HTTPS. It
calls [`GetAuthorizationToken`](https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetAuthorizationToken.html)
using the default AWS credential chain, including environment variables, shared configuration files,
instance profiles, and IRSA.

This uses the same credential lookup approach as the
[`keyrings.codeartifact`](https://github.com/jmkeyes/keyrings.codeartifact) keyring plugin, but does
not require the plugin to be installed.

## Authenticate with `keyring` and `keyrings.codeartifact`

!!! tip

    uv supports AWS CodeArtifact authentication natively, as described above. You do not need to
    install the keyring plugin unless you want to use the subprocess keyring provider.

You can also authenticate to CodeArtifact using the [`keyring`](https://github.com/jaraco/keyring)
package with the [`keyrings.codeartifact` plugin](https://github.com/jmkeyes/keyrings.codeartifact).
Because these two packages are required to authenticate to CodeArtifact, they must be pre-installed
from a source other than CodeArtifact.

The `keyrings.codeartifact` plugin wraps [boto3](https://pypi.org/project/boto3/) to generate
short-lived access tokens, securely store them in system keyring, and refresh them when they are
expired.

uv only supports using the `keyring` package in
[subprocess mode](../../reference/settings.md#keyring-provider). The `keyring` executable must be in
the `PATH`, i.e., installed globally or in the active environment. The `keyring` CLI requires a
username in the URL and it must be `aws`.

```bash
# Pre-install keyring and AWS CodeArtifact plugin from the public PyPI
uv tool install keyring --with keyrings.codeartifact

# Enable keyring authentication
export UV_KEYRING_PROVIDER=subprocess

# Set the username for the index
export UV_INDEX_PRIVATE_REGISTRY_USERNAME=aws
```

!!! note

    The [`tool.uv.keyring-provider`](../../reference/settings.md#keyring-provider)
    setting can be used to enable keyring in your `uv.toml` or `pyproject.toml`.

    Similarly, the username for the index can be added directly to the index URL.

## Authenticate with an AWS access token

Credentials can be provided via the "Basic" HTTP authentication scheme. Include the access token in
the password field of the URL. The username must be `aws`, otherwise authentication will fail.

Generate a token with `awscli`:

```bash
export AWS_CODEARTIFACT_TOKEN="$(
    aws codeartifact get-authorization-token \
    --domain <DOMAIN> \
    --domain-owner <ACCOUNT_ID> \
    --query authorizationToken \
    --output text
)"
```

!!! note

    This is a basic example; you might need to pass extra parameters to generate the token, such as
    `--region`.

Then set credentials for the index with:

```bash
export UV_INDEX_PRIVATE_REGISTRY_USERNAME=aws
export UV_INDEX_PRIVATE_REGISTRY_PASSWORD="$AWS_CODEARTIFACT_TOKEN"
```

!!! note

    `PRIVATE_REGISTRY` should match the name of the index defined in your `pyproject.toml`.

## Publishing packages

If you also want to publish your own packages to AWS CodeArtifact, you can use `uv publish` as
described in the [Building and publishing guide](../package.md).

First, add a `publish-url` to the index you want to publish packages to. For example:

```toml title="pyproject.toml" hl_lines="4"
[[tool.uv.index]]
name = "private-registry"
url = "https://<DOMAIN>-<ACCOUNT_ID>.d.codeartifact.<REGION>.amazonaws.com/pypi/<REPOSITORY>/simple/"
publish-url = "https://<DOMAIN>-<ACCOUNT_ID>.d.codeartifact.<REGION>.amazonaws.com/pypi/<REPOSITORY>/"
```

uv uses the same automatic AWS credential discovery when publishing. To provide an access token
explicitly instead, configure credentials with:

```console
$ export UV_PUBLISH_USERNAME=aws
$ export UV_PUBLISH_PASSWORD="$AWS_CODEARTIFACT_TOKEN"
```

When using the subprocess keyring provider instead, set `UV_PUBLISH_USERNAME=aws` so the keyring
lookup can find the CodeArtifact credentials.

And publish the package:

```console
$ uv publish --index private-registry
```

To use `uv publish` without adding the `publish-url` to the project, you can set `UV_PUBLISH_URL`:

```console
$ export UV_PUBLISH_URL=https://<DOMAIN>-<ACCOUNT_ID>.d.codeartifact.<REGION>.amazonaws.com/pypi/<REPOSITORY>/
$ uv publish
```

Note this method is not preferable because uv cannot check if the package is already published
before uploading artifacts.
