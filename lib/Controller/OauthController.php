<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Controller;

use OCA\Mail\Exception\ClientException;
use OCA\Mail\Http\JsonResponse;
use OCA\Mail\Service\AccountService;
use OCA\Mail\Service\OauthStateService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\IRequest;

#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class OauthController extends Controller {
	public function __construct(
		string $appName,
		IRequest $request,
		private ?string $userId,
		private AccountService $accountService,
		private OauthStateService $oauthStateService,
	) {
		parent::__construct($appName, $request);
	}

	#[NoAdminRequired]
	public function generateState(int $accountId, bool $pkce = false): JsonResponse {
		if ($this->userId === null) {
			return JsonResponse::fail(null, Http::STATUS_UNAUTHORIZED);
		}

		try {
			$this->accountService->find($this->userId, $accountId);
		} catch (ClientException) {
			return JsonResponse::fail(null, Http::STATUS_NOT_FOUND);
		}

		// PKCE is opt-in so the Google/Microsoft flows keep their existing plain state; the custom
		// provider requests it for IdPs that mandate RFC 7636.
		if ($pkce) {
			$result = $this->oauthStateService->createPkceState($accountId, $this->userId);
			return JsonResponse::success([
				'state' => $result['state'],
				'codeChallenge' => $result['challenge'],
			]);
		}

		$state = $this->oauthStateService->createState($accountId, $this->userId);
		return JsonResponse::success(['state' => $state]);
	}
}
