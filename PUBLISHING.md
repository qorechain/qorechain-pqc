# Publishing

Releases are automated by [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
Push a `v*` tag and each package publishes — **but only if its registry secret is
set**, so you can turn registries on one at a time.

```sh
# after bumping versions in every manifest (see "Versioning" below)
git tag v0.1.0
git push origin v0.1.0
```

## One-time account / namespace setup

| Registry | Package | Prerequisite |
|---|---|---|
| npm | `@qorechain/pqc` | Create the **`qorechain`** org on npmjs.com (the scope). |
| crates.io | `qorechain-pqc` | A crates.io account; the name must be free (it is, as of writing). |
| PyPI | `qorechain-pqc` | A PyPI account; create the project (first upload claims the name). |
| Maven Central | `network.qorechain:qorechain-pqc` | A **Central Portal** account (central.sonatype.com) **with the `network.qorechain` namespace verified** — see below. |
| Go | `…/qorechain-pqc/go` | None. pkg.go.dev indexes automatically from a `go/vX.Y.Z` tag. |

### Maven Central namespace — pick one before first publish

The Java `groupId` is `network.qorechain`. The Central Portal requires you to
**prove ownership** of that namespace, by one of:

- **Domain verification** — add the DNS TXT record Central gives you to the
  `qorechain.network` domain (the reverse of the groupId). Use this if you own
  that domain.
- **Switch to a GitHub-verified groupId** — change the groupId to
  `io.github.qorechain` (in `java/pom.xml`), which Central verifies automatically
  against the GitHub org. Lowest-friction if you don't own `qorechain.network`.

> Decision needed: keep `network.qorechain` (verify the domain) or switch to
> `io.github.qorechain`. Everything else is identical.

## Repository secrets to add

Settings → Secrets and variables → Actions → **New repository secret**:

| Secret | Used by | How to get it |
|---|---|---|
| `NPM_TOKEN` | npm | npmjs.com → Access Tokens → **Automation** token. |
| `CARGO_REGISTRY_TOKEN` | crates.io | crates.io → Account Settings → API Tokens. |
| `PYPI_TOKEN` | PyPI | pypi.org → Account → API tokens (scope to the project after first upload). |
| `MAVEN_CENTRAL_USERNAME` | Maven | Central Portal → Generate User Token → token **username**. |
| `MAVEN_CENTRAL_PASSWORD` | Maven | Central Portal user token **password**. |
| `GPG_PRIVATE_KEY` | Maven | `gpg --armor --export-secret-keys <KEYID>` — full ASCII-armored block. Publish the public key to a keyserver (`keys.openpgp.org`). |
| `MAVEN_GPG_PASSPHRASE` | Maven | The passphrase for that GPG key. |

A job whose secret is missing simply skips its publish step (the job still goes
green), so adding `NPM_TOKEN` alone will publish only npm on the next tag.

## Versioning

All six manifests carry the version independently — bump them together before
tagging:

- `js/package.json` → `version`
- `rust/Cargo.toml` → `version`
- `python/pyproject.toml` → `version`
- `java/pom.xml` → `<version>`
- Go module: tag `go/vX.Y.Z` (Go derives the version from the tag; a module in
  the `go/` subdirectory needs the `go/` tag prefix).

So a full release is two tags:

```sh
git tag v0.1.0      # triggers npm / crates / PyPI / Maven
git tag go/v0.1.0   # makes `go get …/qorechain-pqc/go@v0.1.0` resolve
git push origin v0.1.0 go/v0.1.0
```

## Local dry-runs (no secrets needed)

```sh
cd js     && npm publish --dry-run
cd rust   && cargo publish --dry-run
cd python && python -m build && twine check dist/*
cd java   && mvn -B -Prelease verify   # builds, signs locally, does not deploy
```
