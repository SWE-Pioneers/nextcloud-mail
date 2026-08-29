# SWE Mail SSO — Nextcloud Mail ↔ mailcow via the cloud portal (XOAUTH2)

**Goal.** After a user signs into Nextcloud via portal SSO, their mailbox is connected in the Mail app
automatically, authenticated with the **portal's OAuth token** (no password anywhere). Suite mailboxes
are `authsource=generic-oidc` (no IMAP password), so token auth is the only correct path.

**Why a fork.** Stock Nextcloud Mail hardcodes OAuth2 to Google + Microsoft only; there is no generic
custom-provider handler (nextcloud/mail #12491, still open early 2026). So we fork
`nextcloud/mail` → **`SWE-Pioneers/nextcloud-mail`** and add a generic ("swecloud") provider modelled on
`lib/Integration/GoogleIntegration.php`.

## The two halves (both required)

### A. Backend — mailcow Dovecot accepts portal tokens (config, no fork)
- Enable Dovecot `oauth2` mechanism (`xoauth2` + `oauthbearer`) via a mailcow override
  (`data/conf/dovecot/extra.conf` + a `dovecot-oauth2.conf.ext`).
- Validate the bearer token against the portal: **introspection or userinfo**. DOT exposes
  `…/oauth/userinfo/`; confirm/enable an **introspection** endpoint (`…/oauth/introspect/`) or use
  userinfo. Map token → `email` claim → local mailbox. `username_attribute = email`.
- Milestone A-DONE = `curl`/`imaptest` XOAUTH2 login to Dovecot with a portal access token succeeds.
  Test off-prod first (a throwaway Dovecot) — a wrong passdb can break ALL mail login.

### B. Frontend — the SwecloudIntegration in the forked Mail app
- New `lib/Integration/SwecloudIntegration.php` (clone GoogleIntegration): authorize/token/userinfo =
  the portal's `…/oauth/{authorize,token,userinfo}/`, scope `openid email profile`, PKCE S256.
- New `lib/Controller/SwecloudIntegrationController.php` + register in `OauthController` /
  `OauthTokenRefreshListener` (refresh the IMAP token before expiry).
- Vue: a "Connect via SWE Cloud" button on the account-connect screen (the screen the user saw).
- App config for the provider's client_id/secret/discovery, set by provisioning (below).

## Portal (cloud-portal)
- A `nextcloud-mail` (or reuse `nextcloud`) OIDC client whose token is valid for IMAP. Confirm the
  access token carries/an introspection returns the `email` claim Dovecot maps on.
- If introspection is needed and DOT doesn't expose it: add an introspection view (small).

## Build + deploy
- The forked Mail app builds with `composer install --no-dev` + `npm ci && npm run build`, packaged as
  a Nextcloud app (`krankerl` or `make appstore`). Pin a fork branch `swe/sso-xoauth2`.
- Bundle our built Mail app into the **Suite Nextcloud image** (replace the stock `mail` app), the same
  "build from our fork" doctrine as the Frappe apps. `occ app:enable mail` picks ours.

## Provisioning wiring (do_nextcloud_suite)
- On suite provision (already wires user_oidc SSO): also set the Mail app's swecloud provider config +
  a provisioning template so the user's mail account auto-creates on first login using the OAuth token
  (extends the existing Nextcloud Mail provisioning API).

## Phases
1. **A (backend):** Dovecot XOAUTH2 on a throwaway, then mailcow override; prove token IMAP login.
2. **Portal:** token/introspection + client; prove the token Dovecot needs.
3. **B (fork):** SwecloudIntegration + controller + Vue button; unit-test the provider.
4. **Build+image:** build the fork, bundle into the Suite Nextcloud image.
5. **Provisioning:** auto-provision the mail account on SSO; e2e test on sanad-suite.

## Status (2026-08-29)
- Fork created: `SWE-Pioneers/nextcloud-mail` (from `nextcloud/mail`, default `main`).
- Feasibility confirmed: Dovecot supports custom-IdP XOAUTH2; Nextcloud Mail needs the fork (this doc).
- Not started: A–5. Next: Phase A on a throwaway Dovecot (no prod risk) + confirm the portal token shape.
