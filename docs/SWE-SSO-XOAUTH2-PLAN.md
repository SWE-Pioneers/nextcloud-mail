# Nextcloud Mail — generic custom OAuth2 (XOAUTH2) provider + SWE stack wiring

**Goal.** A user signs into Nextcloud via portal SSO → connects their mailbox in Mail with a single
**"Sign in with SWE Cloud"** button, authenticated by the **portal's OAuth token** — no password
(Suite mailboxes are `authsource=generic-oidc`; they have no IMAP password).

Stock Nextcloud Mail hard-codes OAuth2 to **Google and Microsoft only** (nextcloud/mail #12491). This
fork (`SWE-Pioneers/nextcloud-mail`, branch `swe/sso-xoauth2`) adds a **generic, admin-configured
custom OAuth2 provider** so any standards-compliant IdP (our portal, Keycloak, Authentik,
django-oauth-toolkit, …) can authenticate a mailbox via XOAUTH2. Intended for upstream contribution.

---

## Two layers, deliberately separated

- **Layer 1 (generic, upstream-worthy):** the custom OAuth2 provider in the Mail app. Nothing
  SWE-specific — any Nextcloud Mail + Dovecot/mailcow adopter benefits.
- **Layer 2 (our config):** instantiate that provider for our portal, wire mailcow's Dovecot to accept
  the portal's tokens, and configure it per Suite.

---

## Design decisions (as they were actually made)

1. **Self-contained, NOT a refactor of Google/Microsoft.** The original plan was to extract an
   `AbstractOauthIntegration` and make Google/MS extend it. **Rejected by the user:** we can't validate
   Google/MS without real accounts, so leave them byte-for-byte untouched. `CustomOauthIntegration` is
   self-contained, mirroring `GoogleIntegration`'s shape and reading its config from `ConfigLexicon`
   (`custom_oauth_*`). A cleaner upstream contribution too: *add a provider*, don't refactor two.
2. **Matching is by IMAP host, never email domain.** An account is "custom-OAuth" iff its inbound host
   equals the configured `custom_oauth_imap_host` **and** auth method is `xoauth2`. This makes the
   provider **multi-tenant**: a hosting provider fronts many customer domains (`alice@acme.ly`,
   `bob@foo.example`) behind **one shared mail host** and **one IdP** — the mailbox username is the
   customer's own-domain address, the host is the provider's. (`isCustomOauthAccount`, test
   `testMatchesRegardlessOfMailboxDomain`.) The one out-of-fork dependency: Dovecot maps the token to a
   mailbox by the userinfo `email` claim, so provisioning must keep the portal account email == the
   mailbox address (it fails **closed** if they diverge).
3. **A discoverable button on the Auto tab.** The connect button first rendered only in *Manual* mode
   when the IMAP-host field matched (mirroring Google/MS) — undiscoverable for a config-driven IdP. The
   Auto tab now shows **"Sign in with {name}"** whenever a custom provider is configured; it forces the
   account onto the provider host and reuses the xoauth2 submit path (`connectCustomOauth`).
4. **PKCE (RFC 7636) is mandatory in the flow.** Our portal (and many IdPs) require `code_challenge` on
   the authorize request. Login worked (it sends PKCE); the mail flow didn't → `invalid_request`. The
   custom flow now does **S256 PKCE**: a verifier is minted server-side, **encrypted into the existing
   stateless HMAC state** (no new storage; the plaintext verifier never leaves the server, so a redirect
   interceptor sees only ciphertext and can't forge a verifier matching the public challenge), the
   challenge goes in the authorize URL, and the verifier is sent at token exchange. Opt-in per request
   (`pkce` flag on `/api/oauth/state`) so Google/MS stay unchanged.
5. **Popup completion must survive a strict-COOP IdP.** The consent popup signalled the opener only via
   `window.opener.postMessage`. An IdP that serves its authorize page with `Cross-Origin-Opener-Policy:
   same-origin` (e.g. a Django portal) **severs `window.opener`** on the cross-origin hop, so the signal
   is lost and the connected account is rolled back. **We do NOT weaken the IdP's COOP** (a control-plane
   security header should not be relaxed to fix a client bug). Instead the popup also signals over a
   same-origin **`BroadcastChannel`** (popup + opener are same-origin) which survives the
   browsing-context-group swap, with a short grace before a closed-looking handle is treated as an abort.
   Works against any IdP's COOP posture.

---

## Layer 1 — what shipped (files)

**Backend**
- `lib/Integration/CustomOauthIntegration.php` — config-driven provider: `configure`/`unlink`,
  `getClientId`/`getImapHost`/endpoints/`getScopes`/`getDisplayName`, `isConfigured`,
  `isCustomOauthAccount(Account)` (host + xoauth2), `finishConnect($account, $code, $codeVerifier='')`
  (code→token with optional PKCE verifier; stores encrypted access+refresh+ttl), `refresh()`.
- `lib/ConfigLexicon.php` — `custom_oauth_{name,client_id,client_secret,authorization_endpoint,
  token_endpoint,scopes,imap_host}`.
- `lib/Controller/CustomIntegrationController.php` + routes — `POST/DELETE /api/integration/custom`,
  `GET /integration/custom-auth` (redirect handler; validates the PKCE state, consumes the verifier,
  finishes the connect).
- `lib/Controller/PageController.php` — provides the `custom-oauth` initial state (authorize URL with
  `_state_`/`_challenge_`/`_email_` placeholders + `code_challenge_method=S256`, imapHost, displayName).
- `lib/Controller/OauthController.php` — `generateState($accountId, $pkce=false)`; PKCE path returns
  `{state, codeChallenge}`.
- `lib/Service/OauthStateService.php` — `createPkceState`/`validateAndConsumePkce` (encrypted verifier
  carried inside the stateless HMAC state).
- `lib/Command/ConfigureCustomOauth.php` — `occ mail:custom-oauth:configure` (stores the secret
  **encrypted** via `configure()`; a plain `config:app:set` would store cleartext and break the exchange).

**Frontend**
- `src/store/mainStore*.js`, `src/init.js` — `customOauth` state from `loadState('mail','custom-oauth')`.
- `src/components/AccountForm.vue` — `isCustomOauthAccount`/`useOauth`/`customOauthButtonText`, the
  Auto-tab button + `connectCustomOauth`, PKCE via `generateOauthPkceState`.
- `src/service/OauthStateService.js` — `generateOauthPkceState`.
- `src/service/CustomIntegrationService.js`, `src/components/settings/CustomAdminOauthSettings.vue`,
  `AdminSettings.vue`/`AdminSettings.php` — admin CRUD for the provider.
- `src/integration/oauth.js` (`getUserConsent`) + `src/main-oauth-popup.js` — COOP-resilient
  `BroadcastChannel` signalling.

**Tests** (run via a standalone phpunit harness — the app bootstrap needs a full server):
`CustomOauthIntegrationTest`, `CustomIntegrationControllerTest`, `OauthStateServiceTest` (incl. the PKCE
round-trip + tamper/expiry). Pre-upstream-PR TODO: CRLF→LF normalize; run the app's real
eslint/psalm/jest in CI; open the PR to nextcloud/mail.

---

## Layer 2 — SWE stack wiring (shipped)

- **mailcow Dovecot** — `oauth2` passdb (`xoauth2`+`oauthbearer`) validating the portal's OPAQUE tokens
  via `https://cloud.swe.com.ly/oauth/userinfo/` (`introspection_mode=auth`, `username_attribute=email`
  → the `email` claim IS the mailbox). Applied additively (validate-before-reload). Config +
  proof/apply scripts live in vps-infra `ops/dovecot-oauth2-proof/`.
- **cloud-portal** — django-oauth-toolkit; the org's Nextcloud OIDC client is reused for BOTH the
  Nextcloud login (`user_oidc`) and the mail app, carrying the mail redirect URIs. `PKCE_REQUIRED=True`
  (kept — the fork now does PKCE). COOP stays `same-origin` (kept — the fork is COOP-resilient).
- **Suite deploy** — build the fork (`composer install --no-dev` + `npm ci && npm run build`, packaged
  as a Nextcloud app) and drop it in place of stock `mail`. Scripts: vps-infra
  `ops/nextcloud-mail-build/` (`build-nc-mail.sh`, `deploy-mail-fork.sh`, `migrate-suite-nc32.sh`,
  `configure-mail-sso.sh`). Bump the app version on each redeploy or NC's `?v=` asset cache-buster stays
  stale and the browser serves the old bundle.

**Status (2026-08-29): LIVE on `sanad-suite` + `suitedemo` (NC 32).** Button appears, PKCE authorize
succeeds, token exchange + Dovecot XOAUTH2 verified, popup completes over BroadcastChannel, mailbox
connects with no password.

---

## Remaining work

- **Consent/identity screen (agreed next):** give Mail its own portal OAuth client with
  auto-authorization OFF, so the connect popup shows a proper one-time consent — "Nextcloud Mail wants
  access to your mailbox · signed in as `<email>` · Authorize" — while login stays frictionless on its
  own client.
- **Future-suite auto-provisioning (deferred to CI/CD):** provision new suites on our Nextcloud image
  factory with the fork baked in + `do_nextcloud_suite` auto-config; zero-click mail auto-connect.
- **Upstream PR** to nextcloud/mail once CRLF/lint/psalm/jest are green.
