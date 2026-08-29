/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { translate as t } from '@nextcloud/l10n'
import logger from '../logger.js'

export const CONSENT_ABORTED = 'OAUTH_CONSENT_ABORTED'

export async function getUserConsent(redirectUrl) {
	const ssoWindow = window.open(
		redirectUrl,
		t('mail', 'Connect OAUTH2 account'),
		'toolbar=no, menubar=no, width=600, height=700',
	)
	ssoWindow.focus()

	// The popup signals success by posting 'DONE'. window.opener.postMessage only works while the
	// browsing context is intact; an IdP that serves its authorize page with COOP: same-origin severs
	// window.opener during the cross-origin hop (and makes our handle look closed mid-flow). So we
	// also listen on a same-origin BroadcastChannel — both popup and opener are same-origin here — which
	// survives that context-group swap, and we give a late 'DONE' a moment before treating a
	// closed-looking window as an abort.
	const channel = 'BroadcastChannel' in window ? new BroadcastChannel('mail-oauth-consent') : null
	await new Promise((resolve, reject) => {
		let settled = false
		let closeGrace = null

		const cleanup = () => {
			window.removeEventListener('message', onMessage)
			if (channel) {
				channel.close()
			}
			clearInterval(windowClosedTimer)
			if (closeGrace) {
				clearTimeout(closeGrace)
			}
		}
		const succeed = () => {
			if (settled) {
				return
			}
			settled = true
			cleanup()
			logger.info('OAUTH2 user consent given')
			try {
				ssoWindow.close()
			} catch (e) {
				// handle already severed/closed, nothing to do
			}
			resolve()
		}
		const fail = () => {
			if (settled) {
				return
			}
			settled = true
			cleanup()
			reject(new Error(CONSENT_ABORTED))
		}
		const onMessage = (event) => {
			logger.debug('Child window message received', { event })
			if (event.data === 'DONE') {
				succeed()
			}
		}

		window.addEventListener('message', onMessage)
		if (channel) {
			channel.onmessage = (event) => {
				if (event.data === 'DONE') {
					succeed()
				}
			}
		}

		const windowClosedTimer = setInterval(() => {
			if (!ssoWindow.closed || settled || closeGrace) {
				return
			}
			// ponytail: 2s grace bridges the COOP context-swap race; bump if a slow IdP out-races it
			closeGrace = setTimeout(fail, 2000)
		}, 200)
	})
}
