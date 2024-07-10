<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Hook;

use Combodo\iTop\AuthentToken\Service\PersonalTokenService;
use Combodo\iTop\MyAccount\Hook\iMyAccountTabContentExtension;
use UserRights;
use utils;

class MyAccountSectionTabContentExtension implements iMyAccountTabContentExtension
{

	public function GetTemplatePath(): string
	{
		return APPROOT.'env-'.utils::GetCurrentEnvironment().'/authent-token/templates';
	}

	public function GetTabCode(): string
	{
		return 'MyAccount:SubTitle:PersonalTokens';
	}

	public function GetTemplateName(): string
	{
		return 'personaltokens';
	}

	public function GetSectionCallback(): callable
	{
		return [PersonalTokenService::GetInstance(), 'ProvideHtmlTokenInfo'];
	}

	public function GetSectionRank(): float
	{
		return 0;
	}

	public function IsActive(): bool
	{
		return PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed(UserRights::GetUserObject());
	}
}