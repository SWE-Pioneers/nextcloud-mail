<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Tests\Unit\Integration;

use OCA\Mail\Account;
use OCA\Mail\ConfigLexicon;
use OCA\Mail\Db\MailAccount;
use OCA\Mail\Integration\CustomOauthIntegration;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\IAppConfig;
use OCP\IURLGenerator;
use OCP\Security\ICrypto;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class CustomOauthIntegrationTest extends TestCase {
	private ITimeFactory&MockObject $timeFactory;
	private IAppConfig&MockObject $appConfig;
	private ICrypto&MockObject $crypto;
	private IClientService&MockObject $clientService;
	private IURLGenerator&MockObject $urlGenerator;
	private LoggerInterface&MockObject $logger;
	private CustomOauthIntegration $integration;

	protected function setUp(): void {
		parent::setUp();
		$this->timeFactory = $this->createMock(ITimeFactory::class);
		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->crypto = $this->createMock(ICrypto::class);
		$this->clientService = $this->createMock(IClientService::class);
		$this->urlGenerator = $this->createMock(IURLGenerator::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->integration = new CustomOauthIntegration(
			$this->timeFactory,
			$this->appConfig,
			$this->crypto,
			$this->clientService,
			$this->urlGenerator,
			$this->logger,
		);
	}

	/** Stub app config so getValueString returns the configured value per key, its default otherwise. */
	private function config(array $values): void {
		$this->appConfig->method('getValueString')->willReturnCallback(
			static function (string $app, string $key, string $default = '') use ($values): string {
				return $values[$key] ?? $default;
			}
		);
	}

	private function account(string $inboundHost, string $authMethod): Account {
		$mailAccount = new MailAccount();
		$mailAccount->setInboundHost($inboundHost);
		$mailAccount->setAuthMethod($authMethod);
		return new Account($mailAccount);
	}

	public function testMatchesConfiguredImapHostWithXoauth2(): void {
		$this->config([ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => 'mail.example.com']);
		$this->assertTrue($this->integration->isCustomOauthAccount($this->account('mail.example.com', 'xoauth2')));
	}

	public function testDoesNotMatchOtherHost(): void {
		$this->config([ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => 'mail.example.com']);
		$this->assertFalse($this->integration->isCustomOauthAccount($this->account('imap.gmail.com', 'xoauth2')));
	}

	public function testDoesNotMatchPasswordAuth(): void {
		$this->config([ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => 'mail.example.com']);
		$this->assertFalse($this->integration->isCustomOauthAccount($this->account('mail.example.com', 'password')));
	}

	public function testDoesNotMatchWhenHostUnconfigured(): void {
		$this->config([]);
		$this->assertFalse($this->integration->isCustomOauthAccount($this->account('mail.example.com', 'xoauth2')));
	}

	public function testIsConfiguredRequiresEveryField(): void {
		$this->config([
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID => 'cid',
			ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => 'mail.example.com',
			ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT => 'https://idp/token',
			ConfigLexicon::CUSTOM_OAUTH_AUTHORIZATION_ENDPOINT => 'https://idp/authorize',
		]);
		$this->assertTrue($this->integration->isConfigured());
	}

	public function testIsNotConfiguredWhenTokenEndpointMissing(): void {
		$this->config([
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID => 'cid',
			ConfigLexicon::CUSTOM_OAUTH_IMAP_HOST => 'mail.example.com',
			ConfigLexicon::CUSTOM_OAUTH_AUTHORIZATION_ENDPOINT => 'https://idp/authorize',
		]);
		$this->assertFalse($this->integration->isConfigured());
	}

	public function testFinishConnectStoresEncryptedTokensAndTtl(): void {
		$this->config([
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID => 'cid',
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET => 'enc-secret',
			ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT => 'https://idp/token',
		]);
		$this->crypto->method('decrypt')->with('enc-secret')->willReturn('secret');
		$this->crypto->method('encrypt')->willReturnCallback(static fn (string $v): string => 'enc(' . $v . ')');
		$this->timeFactory->method('getTime')->willReturn(1000);

		$response = $this->createMock(IResponse::class);
		$response->method('getBody')->willReturn(json_encode([
			'access_token' => 'AT', 'refresh_token' => 'RT', 'expires_in' => 3600,
		], JSON_THROW_ON_ERROR));
		$client = $this->createMock(IClient::class);
		$client->expects($this->once())->method('post')
			->with('https://idp/token', $this->callback(static function (array $opts): bool {
				return isset($opts['form_params'])
					&& $opts['form_params']['grant_type'] === 'authorization_code'
					&& $opts['form_params']['code'] === 'the-code';
			}))
			->willReturn($response);
		$this->clientService->method('newClient')->willReturn($client);

		$account = $this->account('mail.example.com', 'xoauth2');
		$this->integration->finishConnect($account, 'the-code');

		$this->assertSame('enc(RT)', $account->getMailAccount()->getOauthRefreshToken());
		$this->assertSame('enc(AT)', $account->getMailAccount()->getOauthAccessToken());
		$this->assertSame(4600, $account->getMailAccount()->getOauthTokenTtl());
	}

	public function testFinishConnectAbortsWithoutClientConfig(): void {
		$this->config([]); // no client id/secret/token endpoint
		$this->logger->expects($this->once())->method('critical');
		$this->clientService->expects($this->never())->method('newClient');

		$account = $this->account('mail.example.com', 'xoauth2');
		$this->integration->finishConnect($account, 'the-code');

		$this->assertNull($account->getMailAccount()->getOauthAccessToken());
	}

	public function testRefreshRenewsAccessTokenWhenNearExpiry(): void {
		$this->config([
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_ID => 'cid',
			ConfigLexicon::CUSTOM_OAUTH_CLIENT_SECRET => 'enc-secret',
			ConfigLexicon::CUSTOM_OAUTH_TOKEN_ENDPOINT => 'https://idp/token',
		]);
		$this->crypto->method('decrypt')->willReturnCallback(static fn (string $v): string => 'dec-' . $v);
		$this->crypto->method('encrypt')->willReturnCallback(static fn (string $v): string => 'enc(' . $v . ')');
		$this->timeFactory->method('getTime')->willReturn(1000);

		$response = $this->createMock(IResponse::class);
		$response->method('getBody')->willReturn(json_encode([
			'access_token' => 'AT2', 'expires_in' => 3600,
		], JSON_THROW_ON_ERROR));
		$client = $this->createMock(IClient::class);
		$client->expects($this->once())->method('post')
			->with('https://idp/token', $this->callback(static fn (array $o): bool
				=> ($o['form_params']['grant_type'] ?? null) === 'refresh_token'))
			->willReturn($response);
		$this->clientService->method('newClient')->willReturn($client);

		$account = $this->account('mail.example.com', 'xoauth2');
		$account->getMailAccount()->setOauthRefreshToken('enc-RT');
		$account->getMailAccount()->setOauthTokenTtl(1030); // within the 60s window of now=1000
		$this->integration->refresh($account);

		$this->assertSame('enc(AT2)', $account->getMailAccount()->getOauthAccessToken());
		$this->assertSame(4600, $account->getMailAccount()->getOauthTokenTtl());
		$this->assertSame('enc-RT', $account->getMailAccount()->getOauthRefreshToken()); // unchanged
	}

	public function testRefreshSkipsWhenTokenStillValid(): void {
		$this->timeFactory->method('getTime')->willReturn(1000);
		$this->clientService->expects($this->never())->method('newClient');

		$account = $this->account('mail.example.com', 'xoauth2');
		$account->getMailAccount()->setOauthRefreshToken('enc-RT');
		$account->getMailAccount()->setOauthTokenTtl(5000); // far from now
		$this->integration->refresh($account);

		$this->assertNull($account->getMailAccount()->getOauthAccessToken());
	}
}
