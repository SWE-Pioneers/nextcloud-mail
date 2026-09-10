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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OauthTokenRefreshListenerTest extends TestCase {
	private GoogleIntegration&MockObject $googleIntegration;
	private MicrosoftIntegration&MockObject $microsoftIntegration;
	private CustomOauthIntegration&MockObject $customOauthIntegration;
	private AccountService&MockObject $accountService;
	private OauthTokenRefreshListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->googleIntegration = $this->createMock(GoogleIntegration::class);
		$this->microsoftIntegration = $this->createMock(MicrosoftIntegration::class);
		$this->customOauthIntegration = $this->createMock(CustomOauthIntegration::class);
		$this->accountService = $this->createMock(AccountService::class);
		$this->listener = new OauthTokenRefreshListener(
			$this->googleIntegration,
			$this->microsoftIntegration,
			$this->customOauthIntegration,
			$this->accountService,
		);
	}

	private function account(string $email): Account {
		$mailAccount = new MailAccount();
		$mailAccount->setEmail($email);
		return new Account($mailAccount);
	}

	public function testRefreshesCustomOauthAccount(): void {
		$account = $this->account('user@example.com');
		$refreshed = $this->account('user@example.com');
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
		$account = $this->account('user@gmail.com');
		$refreshed = $this->account('user@gmail.com');
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
