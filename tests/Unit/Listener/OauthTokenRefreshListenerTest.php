<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Tests\Unit\Listener;

use OCA\Mail\Account;
use OCA\Mail\Db\MailAccount;
use OCA\Mail\Events\BeforeImapClientCreated;
use OCA\Mail\Integration\CustomOauthIntegration;
use OCA\Mail\Integration\GoogleIntegration;
use OCA\Mail\Integration\MicrosoftIntegration;
use OCA\Mail\Listener\OauthTokenRefreshListener;
use OCA\Mail\Service\AccountService;
use OCP\EventDispatcher\Event;
use OCP\ICacheFactory;
use OCP\IMemcache;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OauthTokenRefreshListenerTest extends TestCase {
	private GoogleIntegration&MockObject $googleIntegration;
	private MicrosoftIntegration&MockObject $microsoftIntegration;
	private CustomOauthIntegration&MockObject $customOauthIntegration;
	private AccountService&MockObject $accountService;
	private ICacheFactory&MockObject $cacheFactory;
	private IMemcache&MockObject $cache;
	private OauthTokenRefreshListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->googleIntegration = $this->createMock(GoogleIntegration::class);
		$this->microsoftIntegration = $this->createMock(MicrosoftIntegration::class);
		$this->customOauthIntegration = $this->createMock(CustomOauthIntegration::class);
		$this->accountService = $this->createMock(AccountService::class);
		$this->cacheFactory = $this->createMock(ICacheFactory::class);
		$this->cache = $this->createMock(IMemcache::class);
		$this->cacheFactory->method('createDistributed')->willReturn($this->cache);
		$this->cache->method('add')->willReturn(true);
		$this->listener = new OauthTokenRefreshListener(
			$this->googleIntegration,
			$this->microsoftIntegration,
			$this->customOauthIntegration,
			$this->accountService,
			$this->cacheFactory,
		);
	}

	private function account(string $email, ?int $ttl = null, ?string $accessToken = null): Account {
		$mailAccount = new MailAccount();
		$mailAccount->setId(42);
		$mailAccount->setEmail($email);
		$mailAccount->setOauthTokenTtl($ttl);
		$mailAccount->setOauthAccessToken($accessToken);
		return new Account($mailAccount);
	}

	public function testRefreshesCustomOauthAccount(): void {
		$account = $this->account('user@example.com', 1000, 'enc-old');
		$refreshed = $this->account('user@example.com', 4600, 'enc-new');
		$this->googleIntegration->method('isGoogleOauthAccount')->willReturn(false);
		$this->microsoftIntegration->method('isMicrosoftOauthAccount')->willReturn(false);
		$this->customOauthIntegration->method('isCustomOauthAccount')->willReturn(true);
		$this->customOauthIntegration->expects($this->once())
			->method('refresh')
			->with($account)
			->willReturn($refreshed);
		$this->accountService->expects($this->once())
			->method('update')
			->with($refreshed->getMailAccount());

		$this->listener->handle(new BeforeImapClientCreated($account));
	}

	public function testRefreshesGoogleAccountWithoutTouchingCustomIntegration(): void {
		$account = $this->account('user@gmail.com', 1000, 'enc-old');
		$refreshed = $this->account('user@gmail.com', 4600, 'enc-new');
		$this->googleIntegration->method('isGoogleOauthAccount')->willReturn(true);
		$this->googleIntegration->expects($this->once())
			->method('refresh')
			->with($account)
			->willReturn($refreshed);
		$this->customOauthIntegration->expects($this->never())->method('refresh');
		$this->accountService->expects($this->once())
			->method('update')
			->with($refreshed->getMailAccount());

		$this->listener->handle(new BeforeImapClientCreated($account));
	}

	public function testDoesNotPersistWhenRefreshLeftTheTokenUnchanged(): void {
		$account = $this->account('user@example.com', 1000, 'enc-old');
		$refreshed = $this->account('user@example.com', 1000, 'enc-old');
		$this->googleIntegration->method('isGoogleOauthAccount')->willReturn(false);
		$this->microsoftIntegration->method('isMicrosoftOauthAccount')->willReturn(false);
		$this->customOauthIntegration->method('isCustomOauthAccount')->willReturn(true);
		$this->customOauthIntegration->method('refresh')->willReturn($refreshed);
		$this->accountService->expects($this->never())->method('update');
		$this->cache->expects($this->once())->method('remove')->with('account-42');

		$this->listener->handle(new BeforeImapClientCreated($account));
	}

	public function testSkipsRefreshWhileAnotherProcessHoldsTheLock(): void {
		$account = $this->account('user@example.com', 1000, 'enc-old');
		$this->googleIntegration->method('isGoogleOauthAccount')->willReturn(false);
		$this->microsoftIntegration->method('isMicrosoftOauthAccount')->willReturn(false);
		$this->customOauthIntegration->method('isCustomOauthAccount')->willReturn(true);
		$cache = $this->createMock(IMemcache::class);
		$cache->method('add')->with('account-42', 1, 30)->willReturn(false);
		$cache->expects($this->never())->method('remove');
		$cacheFactory = $this->createMock(ICacheFactory::class);
		$cacheFactory->method('createDistributed')->willReturn($cache);
		$listener = new OauthTokenRefreshListener(
			$this->googleIntegration,
			$this->microsoftIntegration,
			$this->customOauthIntegration,
			$this->accountService,
			$cacheFactory,
		);
		$this->customOauthIntegration->expects($this->never())->method('refresh');
		$this->accountService->expects($this->never())->method('update');

		$listener->handle(new BeforeImapClientCreated($account));
	}

	public function testIgnoresAccountOfNoKnownProvider(): void {
		$this->googleIntegration->method('isGoogleOauthAccount')->willReturn(false);
		$this->microsoftIntegration->method('isMicrosoftOauthAccount')->willReturn(false);
		$this->customOauthIntegration->method('isCustomOauthAccount')->willReturn(false);
		$this->googleIntegration->expects($this->never())->method('refresh');
		$this->microsoftIntegration->expects($this->never())->method('refresh');
		$this->customOauthIntegration->expects($this->never())->method('refresh');
		$this->accountService->expects($this->never())->method('update');

		$this->listener->handle(new BeforeImapClientCreated($this->account('user@example.com')));
	}

	public function testIgnoresUnrelatedEvent(): void {
		$this->googleIntegration->expects($this->never())->method('refresh');
		$this->microsoftIntegration->expects($this->never())->method('refresh');
		$this->customOauthIntegration->expects($this->never())->method('refresh');
		$this->accountService->expects($this->never())->method('update');

		$this->listener->handle(new Event());
	}
}
