<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Hook;

use Combodo\iTop\AuthentToken\Helper\TokenAuthConfig;
use Combodo\iTop\AuthentToken\Service\PersonalTokenService;
use Combodo\iTop\MyAccount\Hook\iMyAccountAjaxTabExtension;
use Dict;
use UserRights;
use utils;

class MyAccountAjaxTabExtension implements iMyAccountAjaxTabExtension
{

	/**
	 * @inheritDoc
	 */
	public function IsTabPresent(): bool
	{
		return TokenAuthConfig::GetInstance()->GetBoolean('display_as_separate_tab', 'personal_token', true) &&
			PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed(UserRights::GetUserObject());
	}

	/**
	 * @inheritDoc
	 */
	public function GetAjaxTabCode(): string
	{
		return 'MyAccount:SubTitle:PersonalTokens';
	}

	/**
	 * @inheritDoc
	 */
	public function GetAjaxTabUrl(): string
	{
		return utils::GetAbsoluteUrlModulePage('authent-token', 'index.php');
	}

	/**
	 * @inheritDoc
	 */
	public function GetAjaxTabIsCached(): bool
	{
		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function GetAjaxTabLabel(): string
	{
		return Dict::S('MyAccount:SubTitle:PersonalTokens');
	}
}