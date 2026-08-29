/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { generateUrl } from '@nextcloud/router'

export async function generateOauthState(accountId) {
	const response = await axios.post(
		generateUrl('/apps/mail/api/oauth/state'),
		{ accountId },
		{
			headers: {
				Accept: 'application/json',
			},
		},
	)

	return response.data.data.state
}

/**
 * Generate an OAuth state that also carries a PKCE (RFC 7636) code challenge, for custom providers
 * whose IdP requires PKCE. The matching verifier stays server-side inside the state.
 *
 * @param {number} accountId the temporary account id
 * @return {Promise<{state: string, codeChallenge: string}>}
 */
export async function generateOauthPkceState(accountId) {
	const response = await axios.post(
		generateUrl('/apps/mail/api/oauth/state'),
		{ accountId, pkce: true },
		{
			headers: {
				Accept: 'application/json',
			},
		},
	)

	return {
		state: response.data.data.state,
		codeChallenge: response.data.data.codeChallenge,
	}
}
