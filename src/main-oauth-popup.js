/**
 * SPDX-FileCopyrightText: 2022 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { getRequestToken } from '@nextcloud/auth'
import { generateFilePath } from '@nextcloud/router'
import Vue from 'vue'
import OauthDone from './views/OauthDone.vue'
import Nextcloud from './mixins/Nextcloud.js'

__webpack_nonce__ = btoa(getRequestToken())

__webpack_public_path__ = generateFilePath('mail', '', 'js/')

Vue.mixin(Nextcloud)

const View = Vue.extend(OauthDone)
new View({}).$mount('#mail-oauth-done')

if (window.opener) {
	window.opener.postMessage('DONE')
}
// window.opener is severed when the IdP serves its authorize page with COOP: same-origin; a
// same-origin BroadcastChannel still reaches the opener that started the flow.
try {
	const channel = new BroadcastChannel('mail-oauth-consent')
	channel.postMessage('DONE')
	channel.close()
} catch (e) {
	// BroadcastChannel unsupported; window.opener.postMessage above is the fallback
}
