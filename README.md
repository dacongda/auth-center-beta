<div align="center">
  <a>
    <img alt="HuiPass Logo" width="215" src="https://github.com/dacongda/auth-center-beta-ui/blob/main/apps/web-naive/public/AuthCenterLogo.svg">
  </a>
  <h1>HuiPass</h1>
  <p>
    A self-hosted, multi-protocol Identity and Access Management (IAM) platform built with .NET 9 and PostgreSQL.
  </p>
</div>

## Introduction

HuiPass is a unified authentication server that centralizes user identity, sign-on, and access control for your applications. It speaks OAuth 2.0, OpenID Connect, SAML 2.0, and CAS — so whether you're protecting a modern SPA, a legacy enterprise app, or an internal tool, there's one place to manage it.

**What you can do with it:**

  - **Single Sign-On** — Log in once across all connected applications. HuiPass acts as both an identity provider (IdP) and a federation broker to external OAuth 2.0 / OIDC / SAML providers.
- **Multi-protocol support** — OAuth 2.0 authorization code flow, OIDC (with Discovery), SAML 2.0 SP-initiated SSO, and CAS service tickets out of the box.
- **Modern authentication** — Passwordless login with FIDO2/WebAuthn (passkeys), TOTP-based multi-factor authentication (MFA), and flexible per-application login method policies.
- **Application management** — Register any number of client applications with independent scopes, redirect URIs, token lifetimes, and fully customizable login page branding (logo, colors, theme radius, form layout).
- **User & group administration** — Full user lifecycle management with group-based access control. Bulk import/export via Excel.
- **Audit logging** — Track authentication events across the platform.
- **CAPTCHA integration** — Built-in support for hCaptcha, reCAPTCHA v2, Cloudflare Turnstile, Aliyun Captcha, and Tencent TSec.
- **SMS & email** — Verification codes via Twilio, Tencent SMS, or SMTP (MailKit).
- **File storage backends** — Local disk or AWS S3 for avatars, logos, and uploads.

## Tech stack

| Layer | Technology |
|-------|------------|
| Runtime | .NET 10 (ASP.NET Core) |
| Database | PostgreSQL (via Entity Framework Core) |
| Cache / Sessions | Redis |
| Frontend | Vue 3 + Naive UI (separate [UI repo](https://github.com/dacongda/auth-center-beta-ui)) |
| Containerization | Docker & Docker Compose |

## Deploy

### Docker Compose (recommended)

```bash
git clone https://github.com/dacongda/auth-center-beta.git
cd auth-center-beta
docker compose up -d
```

This starts HuiPass, PostgreSQL 17, and Redis Stack. The API listens on port `8080`.

### Manual deployment

Prerequisites: .NET 10 SDK, PostgreSQL, Redis, Node.js 23+, pnpm.

```bash
# Backend
dotnet run --project AuthCenter.csproj

# Frontend (see ui/ submodule for full instructions)
cd ui && pnpm install && pnpm dev
```

## Status

HuiPass is currently in **beta**. APIs and database schema may change between releases. Production use is at your own risk.
