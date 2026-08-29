<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Integration;

use Exception;
use OCA\Mail\Account;
use OCA\Mail\AppInfo\Application;
use OCA\Mail\ConfigLexicon;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\IURLGenerator;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;
use function json_decode;

/**
 * A generic, admin-configured OAuth2 (XOAUTH2) provider for Mail.
 *
 * Google and Microsoft each ship a dedicated integration with their endpoints and IMAP host baked in.
 * This one reads them from app config instead, so any standards-compliant OpenID Connect / OAuth2
 * identity provider (a self-hosted Keycloak, Authentik, a company IdP in front of Dovecot, …) can
 * authenticate a mailbox via XOAUTH2 without a bespoke integration class. Deliberately mirrors
 * {@see GoogleIntegration} / {@see MicrosoftIntegration} in shape; the token request is form-encoded
 * per RFC 6749.
 */
class CustomOauthIntegration {
	private ITimeFactory $timeFactory;
	private IAppConfig $appConfig;
	private ICrypto $crypto;
	private IClientService $clientService;
	private IURLGenerator $urlGenerator;

	public function __construct(
		ITimeFactory $timeFactory,
		IAppConfig $appConfig,
		ICrypto $crypto,
		IClientService $clientService,
		IURLGenerator $urlGenerator,
		private LoggerInterface $logger,
	) {
		$this->timeFactory = $timeFactory;
		$this->clientService = $clientService;
		$this->crypto = $crypto;
		$this->appConfig = $appConfig;
		$this->urlGenerator = $urlGenerator;
	}

	public function configure(
		string $clientId,
		string $clientSecret,
		string $authorizationEndpoint,
		string $tokenEndpoint,
		string $imapHost,
		?string $name = null,
		?string $scopes = null,
	): void {
		$config = [
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID => $clientId,
			ConfigLexicon::CUSTOM_OAUTH_AUTHORIZATION_ENDPOINT => $authorizationEndpoint,
			ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT => $tokenEndpoint,
			ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => $imapHost,
		];
		if ($name !== null) {
			$config[ConfigLexicon::CUSTOM_OAUTH_NAME] = $name;
		}
		if ($scopes !== null) {
			$config[ConfigLexicon::CUSTOM_OAUTH_SCOPES] = $scopes;
		}
		foreach ($config as $key => $value) {
			$this->appConfig->setValueString(Application::APP_ID, $key, $value);
		}
		$this->appConfig->setValueString(
			Application::APP_ID,
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET,
			$this->crypto->encrypt($clientSecret),
		);
	}

	public function unlink(): void {
		foreach ([
			ConfigLexicon::CUSTOM_OAUTH_NAME,
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID,
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET,
			ConfigLexicon::CUSTOM_OAUTH_AUTHORIZATION_ENDPOINT,
			ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT,
			ConfigLexicon::CUSTOM_OAUTH_SCOPES,
			ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST,
		] as $key) {
			$this->appConfig->deleteKey(Application::APP_ID, $key);
		}
	}

	public function getClientId(): ?string {
		$value = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID);
		if ($value === '') {
			return null;
		}
		return $value;
	}

	/** The IMAP host that identifies accounts belonging to this provider, or null if unset. */
	public function getImapHost(): ?string {
		$value = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST);
		if ($value === '') {
			return null;
		}
		return $value;
	}

	public function getAuthorizationEndpoint(): string {
		return $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_AUTHORIZATION_ENDPOINT);
	}

	public function getTokenEndpoint(): string {
		return $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT);
	}

	public function getScopes(): string {
		return $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_SCOPES, 'openid email profile');
	}

	public function getDisplayName(): string {
		$name = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_NAME, 'Custom');
		return $name === '' ? 'Custom' : $name;
	}

	/** A provider is usable only when the client, both endpoints and the IMAP host are all set. */
	public function isConfigured(): bool {
		return $this->getClientId() !== null
			&& $this->getImapHost() !== null
			&& $this->getTokenEndpoint() !== ''
			&& $this->getAuthorizationEndpoint() !== '';
	}

	public function isCustomOauthAccount(Account $account): bool {
		$imapHost = $this->getImapHost();
		return $imapHost !== null
			&& $account->getMailAccount()->getInboundHost() === $imapHost
			&& $account->getMailAccount()->getAuthMethod() === 'xoauth2';
	}

	public function finishConnect(Account $account,
		string $code): Account {
		$clientId = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID);
		$encryptedClientSecret = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET);
		$tokenEndpoint = $this->getTokenEndpoint();
		if (empty($clientId) || empty($encryptedClientSecret) || empty($tokenEndpoint)) {
			// This is highly unexpected
			$this->logger->critical('Can not finish custom OAuth account linking due to missing client configuration');
			return $account;
		}
		$clientSecret = $this->crypto->decrypt($encryptedClientSecret);
		$httpClient = $this->clientService->newClient();
		try {
			$response = $httpClient->post($tokenEndpoint, [
				'form_params' => [
					'client_id' => $clientId,
					'client_secret' => $clientSecret,
					'grant_type' => 'authorization_code',
					'redirect_uri' => $this->getRedirectUrl(),
					'code' => $code,
				],
			]);
		} catch (Exception $e) {
			$this->logger->error('Could not link custom OAuth account: ' . $e->getMessage(), [
				'exception' => $e,
			]);
			return $account;
		}

		$data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
		$encryptedRefreshToken = $this->crypto->encrypt($data['refresh_token']);
		$account->getMailAccount()->setOauthRefreshToken($encryptedRefreshToken);
		$encryptedAccessToken = $this->crypto->encrypt($data['access_token']);
		$account->getMailAccount()->setOauthAccessToken($encryptedAccessToken);
		$account->getMailAccount()->setOauthTokenTtl($this->timeFactory->getTime() + $data['expires_in']);
		return $account;
	}

	public function refresh(Account $account): Account {
		$oauthRefreshToken = $account->getMailAccount()->getOauthRefreshToken();
		if ($account->getMailAccount()->getOauthTokenTtl() === null || $oauthRefreshToken === null) {
			// Account is not authorized yet
			return $account;
		}

		// Only refresh if the token expires in the next minute
		if ($this->timeFactory->getTime() <= ($account->getMailAccount()->getOauthTokenTtl() - 60)) {
			// No need to refresh yet
			return $account;
		}

		$clientId = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID);
		$encryptedClientSecret = $this->appConfig->getValueString(Application::APP_ID, ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET);
		$tokenEndpoint = $this->getTokenEndpoint();
		if (empty($clientId) || empty($encryptedClientSecret) || empty($tokenEndpoint)) {
			// Nothing to do here
			return $account;
		}

		$refreshToken = $this->crypto->decrypt($oauthRefreshToken);
		$clientSecret = $this->crypto->decrypt($encryptedClientSecret);
		$httpClient = $this->clientService->newClient();
		try {
			$response = $httpClient->post($tokenEndpoint, [
				'form_params' => [
					'client_id' => $clientId,
					'client_secret' => $clientSecret,
					'grant_type' => 'refresh_token',
					'refresh_token' => $refreshToken,
				],
			]);
		} catch (Exception $e) {
			$this->logger->warning('Could not refresh custom OAuth token for account {accountId}: ' . $e->getMessage(), [
				'exception' => $e,
				'accountId' => $account->getId(),
			]);
			return $account;
		}

		$data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
		$encryptedAccessToken = $this->crypto->encrypt($data['access_token']);
		$account->getMailAccount()->setOauthAccessToken($encryptedAccessToken);
		$account->getMailAccount()->setOauthTokenTtl($this->timeFactory->getTime() + $data['expires_in']);

		return $account;
	}

	public function getRedirectUrl(): string {
		return $this->urlGenerator->linkToRouteAbsolute('mail.customIntegration.oauthRedirect');
	}
}
