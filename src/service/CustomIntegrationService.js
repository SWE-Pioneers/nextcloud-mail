/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { generateUrl } from '@nextcloud/router'

export async function configure(clientId, clientSecret, authorizationEndpoint, tokenEndpoint, imapHost, name, scopes) {
	const response = await axios.post(
		generateUrl('/apps/mail/api/integration/custom'),
		{
			clientId,
			clientSecret,
			authorizationEndpoint,
			tokenEndpoint,
			imapHost,
			name,
			scopes,
		},
		{
			headers: {
				Accept: 'application/json',
			},
		},
	)

	return response.data.data
}

export async function unlink() {
	const response = await axios.delete(
		generateUrl('/apps/mail/api/integration/custom'),
		{
			headers: {
				Accept: 'application/json',
			},
		},
	)

	return response.data.data
}
