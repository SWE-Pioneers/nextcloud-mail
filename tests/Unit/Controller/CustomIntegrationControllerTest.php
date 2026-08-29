<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Tests\Unit\Controller;

use OCA\Mail\Account;
use OCA\Mail\Controller\CustomIntegrationController;
use OCA\Mail\Db\MailAccount;
use OCA\Mail\Http\JsonResponse;
use OCA\Mail\IMAP\MailboxSync;
use OCA\Mail\Integration\CustomOauthIntegration;
use OCA\Mail\Service\AccountService;
use OCA\Mail\Service\OauthStateService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class CustomIntegrationControllerTest extends TestCase {
	private IRequest&MockObject $request;
	private CustomOauthIntegration&MockObject $integration;
	private AccountService&MockObject $accountService;
	private LoggerInterface&MockObject $logger;
	private MailboxSync&MockObject $mailboxSync;
	private OauthStateService&MockObject $oauthStateService;

	protected function setUp(): void {
		parent::setUp();
		$this->request = $this->createMock(IRequest::class);
		$this->integration = $this->createMock(CustomOauthIntegration::class);
		$this->accountService = $this->createMock(AccountService::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->mailboxSync = $this->createMock(MailboxSync::class);
		$this->oauthStateService = $this->createMock(OauthStateService::class);
	}

	private function controller(?string $userId): CustomIntegrationController {
		return new CustomIntegrationController(
			$this->request,
			$userId,
			$this->integration,
			$this->accountService,
			$this->logger,
			$this->mailboxSync,
			$this->oauthStateService,
		);
	}

	public function testConfigureRejectsMissingFields(): void {
		$this->integration->expects($this->never())->method('configure');
		$response = $this->controller('bob')->configure('cid', '', 'https://idp/authorize', 'https://idp/token', 'mail.example.com');
		$this->assertInstanceOf(JsonResponse::class, $response);
		$this->assertSame(Http::STATUS_UNPROCESSABLE_ENTITY, $response->getStatus());
	}

	public function testConfigurePersistsAndNormalisesEmptyOptionals(): void {
		$this->integration->expects($this->once())->method('configure')
			->with('cid', 'sec', 'https://idp/authorize', 'https://idp/token', 'mail.example.com', null, null);
		$response = $this->controller('bob')->configure(
			'cid', 'sec', 'https://idp/authorize', 'https://idp/token', 'mail.example.com');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
	}

	public function testUnlinkDelegates(): void {
		$this->integration->expects($this->once())->method('unlink');
		$response = $this->controller('bob')->unlink();
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
	}

	public function testOauthRedirectRendersDoneForGuest(): void {
		$this->integration->expects($this->never())->method('finishConnect');
		$response = $this->controller(null)->oauthRedirect('code', 'state', null, null);
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
	}

	public function testOauthRedirectRendersDoneWhenParamsMissing(): void {
		$this->integration->expects($this->never())->method('finishConnect');
		$response = $this->controller('bob')->oauthRedirect(null, null, null, null);
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
	}

	public function testOauthRedirectFinishesConnectAndPersists(): void {
		$mailAccount = new MailAccount();
		$account = new Account($mailAccount);
		$this->oauthStateService->expects($this->once())->method('validateAndConsume')
			->with('the-state', 'bob')->willReturn(42);
		$this->accountService->expects($this->once())->method('find')->with('bob', 42)->willReturn($account);
		$this->integration->expects($this->once())->method('finishConnect')
			->with($account, 'the-code')->willReturn($account);
		$this->accountService->expects($this->once())->method('update')->with($mailAccount);
		$this->mailboxSync->expects($this->once())->method('sync');

		$response = $this->controller('bob')->oauthRedirect('the-code', 'the-state', null, null);
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
	}
}
