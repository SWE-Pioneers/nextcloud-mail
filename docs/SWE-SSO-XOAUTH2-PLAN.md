# Nextcloud Mail — generic custom OAuth2 provider (upstream) + SWE stack wiring

**Goal.** A user signs into Nextcloud via portal SSO → their Suite mailbox auto-connects in Mail,
authenticated by the **portal's OAuth token** (no password; Suite mailboxes are `authsource=generic-oidc`,
they have no IMAP password). See [[suite-email-oidc-only-login-trap]].

**Two layers, deliberately separated:**
- **Layer 1 (generic, UPSTREAM-first):** add a *config-driven custom OAuth2 provider* to Nextcloud Mail
  following the existing Google/Microsoft conventions, and contribute it back (nextcloud/mail #12491).
  Nothing SWE-specific — any Nextcloud Mail + mailcow/Dovecot/Keycloak/etc. adopter benefits.
- **Layer 2 (our config):** instantiate that generic provider for our portal + wire mailcow Dovecot +
  provisioning auto-connect. This is the only SWE-specific part.

## Layer 1 — the abstraction (derived from the code, not invented)
`lib/Integration/GoogleIntegration.php` and `MicrosoftIntegration.php` are ~identical. They differ ONLY in:
1. token endpoint URL (`https://oauth2.googleapis.com/token` vs MS),
2. app-config keys (`GOOGLE_OAUTH_CLIENT_ID/SECRET` vs `MICROSOFT_*` in `ConfigLexicon`),
3. account match (`getInboundHost() === 'imap.gmail.com' && getAuthMethod() === 'xoauth2'`),
4. redirect route (`mail.googleIntegration.oauthRedirect`).
Everything else — `configure/unlink/getClientId`, `finishConnect(code)` (code→token, store
enc access+refresh+ttl on `MailAccount`), `refresh()` (refresh-token grant), `getRedirectUrl()` — is verbatim.

**Refactor (the contribution):**
- Extract `lib/Integration/AbstractOauthIntegration.php`: concrete `finishConnect()`, `refresh()`,
  token storage, `getRedirectUrl()`; abstract hooks `getTokenEndpoint()`, `getAuthorizeEndpoint()`,
  `getScopes()`, `configPrefix()`, `getRedirectRoute()`, `matchesAccount(Account)`.
- `GoogleIntegration` / `MicrosoftIntegration` → `extends AbstractOauthIntegration`, override the 4 hooks
  (proves the base; upstream loves a refactor that removes duplication without behaviour change).
- New `CustomOauthIntegration`: **N admin-configured providers** (a registry), each with
  {id, displayName, discoveryUri OR authorize/token endpoints, clientId, clientSecret(enc), scopes,
  imapHost, smtpHost}. Discovery (`/.well-known/openid-configuration`) auto-fills endpoints. Account
  match = configured imapHost + `xoauth2`.
- Controller: generalise `OauthController`/`GoogleIntegrationController` to route by provider id.
- Admin settings (Vue): "Custom mail OAuth providers" CRUD. Connect screen: a button per configured
  provider ("Connect via <displayName>"), mirroring the Gmail/Outlook buttons.
- Tests mirroring `tests/.../GoogleIntegration*`; then open the upstream PR from `swe/sso-xoauth2`.

## Layer 2 — SWE stack wiring (after Layer 1 lands, even if upstream review is slow we ship our fork)
- **mailcow Dovecot**: `oauth2` passdb (`xoauth2`+`oauthbearer`) validating portal tokens via
  `…/oauth/userinfo/` (or an introspection view added to cloud-portal), map `email` → mailbox. Test on a
  THROWAWAY Dovecot first — a wrong passdb breaks all mail login.
- **cloud-portal**: a mail OIDC client whose access token Dovecot accepts (email claim present); confirm
  scope/audience.
- **Suite image**: build the fork (`composer install --no-dev` + `npm ci && npm run build`, package as a
  Nextcloud app) and bundle it in place of stock `mail` — our-fork doctrine, like the Frappe apps.
- **Provisioning** (`do_nextcloud_suite`): register the custom provider config + auto-provision the
  user's mail account on first SSO login using the token (extends Nextcloud Mail provisioning).

## Phases
0. Layer-1 refactor + CustomOauthIntegration + admin UI + tests → upstream PR (branch `swe/sso-xoauth2`).
1. mailcow Dovecot XOAUTH2 on a throwaway; prove token IMAP login.
2. cloud-portal token/introspection + mail client.
3. Build the fork + bundle into the Suite image.
4. Provisioning auto-connect; e2e on sanad-suite.

## Status (2026-08-29)
- Fork: `SWE-Pioneers/nextcloud-mail` (from `nextcloud/mail`, default `main`), plan on `swe/sso-xoauth2`.
- Feasibility confirmed; abstraction seam identified from the code (above). Implementation NOT started.
- Also pending (separate): SSO progress indicator (perceived-latency fix; portal measured fast at 0.3s).
