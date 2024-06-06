<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Hook;

use Combodo\iTop\AuthentToken\Service\PersonalTokenService;
use Combodo\iTop\MyAccount\Hook\iMyAccountTabExtension;
use Dict;
use UserRights;

class MyAccountTabExtension implements iMyAccountTabExtension
{

	/**
	 * @inheritDoc
	 */
	public function IsTabPresent(): bool
	{
		return PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed(UserRights::GetUserObject());
	}

	/**
	 * @inheritDoc
	 */
	public function GetTabCode(): string
	{
		return 'MyAccount:SubTitle:PersonalTokens';
	}

	/**
	 * @inheritDoc
	 */
	public function GetTabIsCached(): bool
	{
		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function GetTabLabel(): string
	{
		return Dict::S('MyAccount:SubTitle:PersonalTokens');
	}

	public function GetTabRank(): float
	{
		return 10;
	}
}