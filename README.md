# platform-golden-path

The paved road for engineering at Zurich RiskGuardian.

Everything a product team needs to build, secure, and ship a service lives here — reusable
workflows, composite actions, Terraform modules, the organisation's policy bundle, and the
compliance rules we have encoded as CodeQL queries.

Owned by **@alraun-sandbox/platform-engineering**.

---

## Why this repository exists

A service team that has to assemble its own pipeline will assemble a different pipeline from
every other team. Multiply by 40 teams and the organisation has 40 security postures, 40
answers for the auditor, and no way to change any of them at once.

So the guarantees do not live in the service repositories. They live here, and services
*inherit* them:

- Change the security gate once → every service gets it on its next build.
- Add a compliance rule once → every service is measured against it.
- Fix a Terraform module once → every environment converges on the fix.

The trade is real and worth naming out loud: teams give up some autonomy over their pipeline
and get back the ability to ship without owning the security problem themselves.

**Design principle: make the compliant thing the easy thing.** The Terraform modules produce
resources that already satisfy every policy. The policy gate exists to catch what left the
paved road — not to teach people the rules one failed build at a time.

---

## What a service repository actually writes

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:

jobs:
  build:
    uses: alraun-sandbox/platform-golden-path/.github/workflows/build-dotnet.yml@v1
    with:
      project-path: src

  security:
    uses: alraun-sandbox/platform-golden-path/.github/workflows/security.yml@v1
    with:
      language: csharp
      build-mode: none

  deploy:
    if: github.ref == 'refs/heads/main'
    needs: [build, security]
    uses: alraun-sandbox/platform-golden-path/.github/workflows/deploy-container-app.yml@v1
    with:
      service-name: riskguardian-claims
      image-name: riskguardian-claims
      resource-group: rg-riskguardian-dev-chn
      registry: acrriskguardiandevchn.azurecr.io
    secrets: inherit
```

That is the whole pipeline. There is no security configuration in it, because security is not
the service team's to configure.

---

## Contents

### `.github/workflows/` — reusable workflows

| Workflow | Check name | Purpose |
|---|---|---|
| `build-dotnet.yml` | `build` | Restore, build, test, coverage floor, publish artifact |
| `build-java.yml` | `build` | Maven build, test, package |
| `build-node.yml` | `build` | Install, lint, typecheck, test, build |
| `security.yml` | `security` | CodeQL (stock + Zurich compliance pack), dependency review, licence policy |
| `terraform-plan.yml` | `terraform-plan` | fmt, validate, plan, Conftest, plan-and-verdict as a PR comment |
| `deploy-container-app.yml` | — | Dockerfile policy, build, image scan, OIDC deploy, health verification |
| `self-test.yml` | — | This repository proving its own policies still work |

The check names matter: the organisation rulesets require `build` and `security` on every
`tier=critical` repository. A team cannot satisfy the ruleset without calling these workflows,
and cannot call these workflows without inheriting the gates.

### `actions/` — composite actions

- **`azure-oidc-login`** — exchanges the workflow's OIDC token for Azure credentials and prints
  the identity it received. No client secret exists anywhere in the organisation.
- **`policy-check`** — runs the Rego bundle against a Terraform plan and renders the verdict as
  reviewable markdown rather than a red X.

### `policy/` — policy as code

Five organisational policies, plus a container supply-chain policy. Written in Rego, evaluated
by Conftest against `terraform show -json` output — so they reason about *what will exist after
apply*, not about HCL text. That distinction matters: modules, variables and `for_each` hide the
real values from anything that greps source.

| ID | Policy | Enforcement |
|---|---|---|
| `ZUR-SEC-001` | No publicly accessible data stores | deny |
| `ZUR-GOV-002` | Mandatory tags: `Environment`, `Owner`, `CostCenter` | deny |
| `ZUR-DAT-003` | Approved regions only (CH primary, DE/SE for DR) | deny |
| `ZUR-NET-004` | Regulated data reachable only via private endpoint; TLS 1.2 floor | deny |
| `ZUR-IAM-005` | No `Owner`, no subscription-scope assignments, no client secrets | deny |
| `ZUR-SUP-006` | Immutable image tags, non-root containers, no credentials in `ARG` | deny |

Run them locally — the same verdict a pull request will produce:

```bash
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
conftest test --policy policy/terraform --all-namespaces plan.json
conftest test --policy policy/container --parser dockerfile Dockerfile
```

`policy/fixtures/` holds a compliant and a deliberately non-compliant plan. `self-test.yml`
asserts that the first passes and the second is rejected, on every commit. Untested policy is
documentation with a worse error message.

### `codeql/queries/` — compliance rules as queries

Stock CodeQL knows about SQL injection. It does not know that a Swiss insurer may not write a
policyholder's AHV number into an application log — that is *our* rule, so we wrote it.

| Query | Language | Finds |
|---|---|---|
| `PiiInLogs.ql` | C#, Java | Personal data reaching a log sink (GDPR Art. 5(1)(c), FINMA 2023/1) |
| `MissingAuthorization.ql` | C# | A claims API action with no authorization decision at all |

`security.yml` adds the pack for the language under analysis and falls back to the stock suite
where no pack exists. The Java and C# `PiiInLogs` queries are deliberate mirrors: a compliance
rule that means two different things in two services is not a rule.

### `terraform-modules/` — infrastructure that is compliant by construction

| Module | Notes |
|---|---|
| `naming` | Names and the mandatory tag set. Every other module takes its tags from here. |
| `network` | VNet, delegated subnets, NSGs, **and the private DNS zones teams forget** |
| `postgres` | Public access is not a variable. Password generated and stored in Key Vault. |
| `storage` | Private endpoint, deny-by-default, Entra-only auth, infrastructure encryption |
| `keyvault` | RBAC authorization, private endpoint, no access policies |
| `observability` | Log Analytics + App Insights, plus the saved KQL query the runbook uses |
| `container-app-environment` | VNet-integrated environment and the registry |
| `container-app` | Managed identity, `AcrPull` scoped to the registry, Key Vault references, probes |

Note what the modules *refuse* to do. `public_network_access_enabled` is hard-coded, not
exposed. The `image` variable rejects `:latest` in a `validation` block. `naming` rejects an
unapproved region before `terraform plan` even runs. Failing in `terraform validate` is faster
and kinder than failing in code review.

The platform team applies its own policies to itself: the deployment identity holds
`Contributor` on **one resource group**, never `Owner`, because `ZUR-IAM-005` would reject it.
A platform team that exempts itself from its own policy does not have a policy.

---

## Versioning

Consume workflows and actions by tag, never by `@main`:

```yaml
uses: alraun-sandbox/platform-golden-path/.github/workflows/build-dotnet.yml@v1
```

`v1` is a moving major tag: security fixes and gate changes arrive automatically, breaking
changes do not. This is how the platform team ships a new control to 40 teams on a Tuesday
without breaking anyone's Monday.

## Rolling out a change to the estate

1. Open a pull request here. `self-test.yml` proves the policy bundle still behaves.
2. Add the new rule as **`warn`** first, and ship it. Nothing breaks; findings accumulate.
3. Publish the finding count per team. Teams fix what they can see.
4. Promote `warn` to `deny` once the count is near zero.

The organisation ruleset has a matching mechanism: `RiskGuardian — Signed commits (evaluate)`
runs in `evaluate` mode, reporting what *would* have been blocked without blocking anything.
That is the answer to "how do I roll this out to 800 repositories without a riot."

## Contributing

Changes here affect every team. CODEOWNERS requires review from
**@alraun-sandbox/platform-engineering**, and changes under `policy/` and `codeql/`
additionally require **@alraun-sandbox/security-guild**.

Add a fixture with every policy change. If it is not in `self-test.yml`, it is not enforced.

