<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Listener;

use OCA\Mail\Account;
use OCA\Mail\Events\BeforeImapClientCreated;
use OCA\Mail\Events\BeforeSmtpClientCreated;
use OCA\Mail\Integration\CustomOauthIntegration;
use OCA\Mail\Integration\GoogleIntegration;
use OCA\Mail\Integration\MicrosoftIntegration;
use OCA\Mail\Service\AccountService;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\ICacheFactory;
use OCP\IMemcache;

/**
 * @template-implements IEventListener<Event|BeforeImapClientCreated|BeforeSmtpClientCreated>
 */
class OauthTokenRefreshListener implements IEventListener {
	private const LOCK_TTL = 30;

	public function __construct(
		private GoogleIntegration $googleIntegration,
		private MicrosoftIntegration $microsoftIntegration,
		private CustomOauthIntegration $customOauthIntegration,
		private AccountService $accountService,
		private ICacheFactory $cacheFactory,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!($event instanceof BeforeImapClientCreated) && !($event instanceof BeforeSmtpClientCreated)) {
			return;
		}
		$account = $event->getAccount();
		if ($this->googleIntegration->isGoogleOauthAccount($account)) {
			$refresh = fn (Account $a): Account => $this->googleIntegration->refresh($a);
		} elseif ($this->microsoftIntegration->isMicrosoftOauthAccount($account)) {
			$refresh = fn (Account $a): Account => $this->microsoftIntegration->refresh($a);
		} elseif ($this->customOauthIntegration->isCustomOauthAccount($account)) {
			$refresh = fn (Account $a): Account => $this->customOauthIntegration->refresh($a);
		} else {
			return;
		}

		// Rotating IdPs revoke the old refresh token, so two processes exchanging the same one
		// leaves the loser with a revoked token it must not write back over the winner's.
		$cache = $this->cacheFactory->createDistributed('mail_oauth_refresh');
		$lockKey = 'account-' . $account->getId();
		if ($cache instanceof IMemcache && !$cache->add($lockKey, 1, self::LOCK_TTL)) {
			return;
		}

		try {
			$ttlBefore = $account->getMailAccount()->getOauthTokenTtl();
			$accessTokenBefore = $account->getMailAccount()->getOauthAccessToken();
			$updated = $refresh($account);
			if ($updated->getMailAccount()->getOauthTokenTtl() === $ttlBefore
				&& $updated->getMailAccount()->getOauthAccessToken() === $accessTokenBefore) {
				return;
			}
			$this->accountService->update($updated->getMailAccount());
		} finally {
			$cache->remove($lockKey);
		}
	}
}
