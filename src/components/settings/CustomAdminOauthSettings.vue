<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<template>
	<form @submit.prevent="onSubmit">
		<label for="mail-custom-oauth-name"> {{ t('mail', 'Provider name') }} </label>
		<input
			id="mail-custom-oauth-name"
			v-model="nameVal"
			:disabled="loading"
			type="text"
			:placeholder="t('mail', 'Custom')">
		<label for="mail-custom-oauth-imap-host"> {{ t('mail', 'IMAP host') }} </label>
		<input
			id="mail-custom-oauth-imap-host"
			v-model="imapHostVal"
			:disabled="loading"
			type="text"
			required>
		<label for="mail-custom-oauth-authorization-endpoint"> {{ t('mail', 'Authorization endpoint') }} </label>
		<input
			id="mail-custom-oauth-authorization-endpoint"
			v-model="authorizationEndpointVal"
			:disabled="loading"
			type="url"
			required>
		<label for="mail-custom-oauth-token-endpoint"> {{ t('mail', 'Token endpoint') }} </label>
		<input
			id="mail-custom-oauth-token-endpoint"
			v-model="tokenEndpointVal"
			:disabled="loading"
			type="url"
			required>
		<label for="mail-custom-oauth-scopes"> {{ t('mail', 'Scopes') }} </label>
		<input
			id="mail-custom-oauth-scopes"
			v-model="scopesVal"
			:disabled="loading"
			type="text"
			:placeholder="t('mail', 'openid email profile')">
		<label for="mail-custom-oauth-client-id"> {{ t('mail', 'Client ID') }} </label>
		<input
			id="mail-custom-oauth-client-id"
			v-model="clientIdVal"
			:disabled="loading"
			type="text"
			required>
		<label for="mail-custom-oauth-client-secret"> {{ t('mail', 'Client secret') }} </label>
		<input
			id="mail-custom-oauth-client-secret"
			v-model="clientSecret"
			:disabled="loading"
			type="password"
			required>
		<button
			type="submit"
			:disabled="!canSubmit || loading"
			class="primary">
			{{ t('mail', 'Save') }}
		</button>
		<button :disabled="loading" @click.prevent="onUnlink">
			{{ t('mail', 'Unlink') }}
		</button>
	</form>
</template>

<script>
import { showError, showSuccess } from '@nextcloud/dialogs'
import { translate as t } from '@nextcloud/l10n'
import logger from '../../logger.js'
import { configure, unlink } from '../../service/CustomIntegrationService.js'

const PASSWORD_PLACEHOLDER = '*****'

export default {
	name: 'CustomAdminOauthSettings',
	props: {
		clientId: {
			type: String,
			default: '',
		},
		name: {
			type: String,
			default: '',
		},
		authorizationEndpoint: {
			type: String,
			default: '',
		},
		tokenEndpoint: {
			type: String,
			default: '',
		},
		imapHost: {
			type: String,
			default: '',
		},
		scopes: {
			type: String,
			default: '',
		},
	},

	data() {
		return {
			loading: false,
			clientIdVal: this.clientId,
			clientSecret: this.clientId ? PASSWORD_PLACEHOLDER : '',
			nameVal: this.name,
			authorizationEndpointVal: this.authorizationEndpoint,
			tokenEndpointVal: this.tokenEndpoint,
			imapHostVal: this.imapHost,
			scopesVal: this.scopes,
		}
	},

	computed: {
		canSubmit() {
			return !!this.clientIdVal
				&& !!this.clientSecret
				&& !!this.authorizationEndpointVal
				&& !!this.tokenEndpointVal
				&& !!this.imapHostVal
		},
	},

	methods: {
		async onSubmit() {
			this.loading = true
			try {
				await configure(
					this.clientIdVal,
					this.clientSecret,
					this.authorizationEndpointVal,
					this.tokenEndpointVal,
					this.imapHostVal,
					this.nameVal,
					this.scopesVal,
				)
				showSuccess(t('mail', 'Custom OAuth integration configured'))
			} catch (error) {
				logger.error('Could not configure custom OAuth integration', { error })
				showError(t('mail', 'Could not configure custom OAuth integration'))
			} finally {
				this.loading = false
			}
		},

		async onUnlink() {
			this.loading = true
			try {
				await unlink()
				this.clientIdVal = ''
				this.clientSecret = ''
				this.nameVal = ''
				this.authorizationEndpointVal = ''
				this.tokenEndpointVal = ''
				this.imapHostVal = ''
				this.scopesVal = ''
				showSuccess(t('mail', 'Custom OAuth integration unlinked'))
			} catch (error) {
				logger.error('Could not unlink custom OAuth integration', { error })
				showError(t('mail', 'Could not unlink custom OAuth integration'))
			} finally {
				this.loading = false
			}
		},
	},
}
</script>
