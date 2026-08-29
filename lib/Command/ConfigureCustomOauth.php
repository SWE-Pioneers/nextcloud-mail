<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Mail\Command;

use OCA\Mail\Integration\CustomOauthIntegration;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Configure the generic custom OAuth2 provider from the CLI. The client secret is passed through
 * CustomOauthIntegration::configure(), which encrypts it before it is written — so provisioning can
 * set it up non-interactively (a plain `occ config:app:set` would store the secret in clear text,
 * and the integration decrypts it, so that would break the token exchange).
 */
final class ConfigureCustomOauth extends Command {
	public function __construct(
		private CustomOauthIntegration $integration,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this->setName('mail:custom-oauth:configure')
			->setDescription('Configure the generic custom OAuth2 provider (stores the client secret encrypted)')
			->addOption('client-id', null, InputOption::VALUE_REQUIRED, 'OAuth client id')
			->addOption('client-secret', null, InputOption::VALUE_REQUIRED, 'OAuth client secret (stored encrypted)')
			->addOption('authorization-endpoint', null, InputOption::VALUE_REQUIRED, 'Authorization endpoint URL')
			->addOption('token-endpoint', null, InputOption::VALUE_REQUIRED, 'Token endpoint URL')
			->addOption('imap-host', null, InputOption::VALUE_REQUIRED, 'IMAP host identifying accounts of this provider')
			->addOption('name', null, InputOption::VALUE_OPTIONAL, 'Display name shown on the connect button')
			->addOption('scopes', null, InputOption::VALUE_OPTIONAL, 'Space-separated OAuth scopes');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		foreach (['client-id', 'client-secret', 'authorization-endpoint', 'token-endpoint', 'imap-host'] as $required) {
			if (empty($input->getOption($required))) {
				$output->writeln("<error>--$required is required</error>");
				return 1;
			}
		}
		$name = $input->getOption('name');
		$scopes = $input->getOption('scopes');
		$this->integration->configure(
			(string)$input->getOption('client-id'),
			(string)$input->getOption('client-secret'),
			(string)$input->getOption('authorization-endpoint'),
			(string)$input->getOption('token-endpoint'),
			(string)$input->getOption('imap-host'),
			$name === null ? null : (string)$name,
			$scopes === null ? null : (string)$scopes,
		);
		$output->writeln('Custom OAuth provider configured (' . $input->getOption('imap-host') . ')');
		return 0;
	}
}
