<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Service;

use OCA\Mail\Exception\InvalidOauthStateException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ICrypto;

class OauthStateService {
	public const TTL = 600;

	public function __construct(
		private ICrypto $crypto,
		private ITimeFactory $time,
	) {
	}

	public function createState(int $accountId, string $userId): string {
		$timestamp = $this->time->getTime();
		$hmac = bin2hex($this->crypto->calculateHMAC("$accountId.$userId.$timestamp"));
		return "$accountId.$timestamp.$hmac";
	}

	/**
	 * Like {@see createState()} but also mints a PKCE (RFC 7636) code verifier for providers whose
	 * IdP requires it. The verifier is encrypted with the server key and carried inside the state, so
	 * the stateless-HMAC design is kept (no server-side storage) while the plaintext verifier never
	 * leaves the server: an interceptor of the redirect sees only the ciphertext and cannot forge a
	 * verifier matching the (public) challenge.
	 *
	 * @return array{state: string, challenge: string} the opaque state and the S256 code challenge
	 */
	public function createPkceState(int $accountId, string $userId): array {
		$timestamp = $this->time->getTime();
		$verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); // 43 chars, RFC 7636
		$encVerifier = rtrim(strtr(base64_encode($this->crypto->encrypt($verifier)), '+/', '-_'), '=');
		$hmac = bin2hex($this->crypto->calculateHMAC("$accountId.$userId.$timestamp.$encVerifier"));
		return [
			'state' => "$accountId.$timestamp.$encVerifier.$hmac",
			'challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
		];
	}

	/**
	 * @throws InvalidOauthStateException
	 */
	public function validateAndConsume(string $state, string $userId): int {
		$parts = explode('.', $state, 3);
		if (count($parts) !== 3) {
			throw new InvalidOauthStateException('Malformed OAuth state');
		}
		[$accountId, $timestamp, $hmac] = $parts;

		$expected = bin2hex($this->crypto->calculateHMAC("$accountId.$userId.$timestamp"));
		if (!hash_equals($expected, $hmac)) {
			throw new InvalidOauthStateException('OAuth state HMAC mismatch');
		}

		if (($this->time->getTime() - (int)$timestamp) > self::TTL) {
			throw new InvalidOauthStateException('OAuth state expired');
		}

		return (int)$accountId;
	}

	/**
	 * Validate a state minted by {@see createPkceState()} and return the account id plus the decrypted
	 * PKCE verifier for the token exchange.
	 *
	 * @return array{accountId: int, verifier: string}
	 * @throws InvalidOauthStateException
	 */
	public function validateAndConsumePkce(string $state, string $userId): array {
		$parts = explode('.', $state, 4);
		if (count($parts) !== 4) {
			throw new InvalidOauthStateException('Malformed PKCE OAuth state');
		}
		[$accountId, $timestamp, $encVerifier, $hmac] = $parts;

		$expected = bin2hex($this->crypto->calculateHMAC("$accountId.$userId.$timestamp.$encVerifier"));
		if (!hash_equals($expected, $hmac)) {
			throw new InvalidOauthStateException('PKCE OAuth state HMAC mismatch');
		}
		if (($this->time->getTime() - (int)$timestamp) > self::TTL) {
			throw new InvalidOauthStateException('OAuth state expired');
		}

		$decoded = base64_decode(strtr($encVerifier, '-_', '+/'), true);
		if ($decoded === false) {
			throw new InvalidOauthStateException('Malformed PKCE verifier');
		}
		return [
			'accountId' => (int)$accountId,
			'verifier' => $this->crypto->decrypt($decoded),
		];
	}
}
