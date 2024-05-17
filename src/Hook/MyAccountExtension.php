<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Hook;

use Combodo\iTop\AuthentToken\Helper\TokenAuthConfig;
use Combodo\iTop\AuthentToken\Service\PersonalTokenService;
use Combodo\iTop\MyAccount\Hook\iMyAccountExtension;
use UserRights;
use utils;

class MyAccountExtension implements iMyAccountExtension
{

	public function GetTemplatePath(): string
	{
		return APPROOT.'env-'.utils::GetCurrentEnvironment().'/authent-token/templates';
	}

	/**
	 * @inheritDoc
	 */
	public function GetSectionParams(): array
	{
		if (TokenAuthConfig::GetInstance()->GetBoolean('display_as_separate_tab', 'personal_token', true) ||
			PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed(UserRights::GetUserObject()) === false) {
			return [];
		}

		$aSectionParams = PersonalTokenService::GetInstance()->ProvideHtmlTokenInfo(UserRights::GetUserObject());
		$aSectionParams['sHtmlTwig'] = 'personaltokens.html.twig';
		$aSectionParams['sReadyJsTwig'] = 'personaltokens.ready.js.twig';

		return $aSectionParams;
	}
}