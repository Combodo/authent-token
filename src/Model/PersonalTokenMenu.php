<?php
/**
 * @copyright   Copyright (C) 2010-2023 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\Extension\Model;

use ApplicationMenu;
use OQLMenuNode;
use UserRights;
use utils;
use WebPageMenuNode;

class PersonalTokenMenu extends \ModuleHandlerAPI
{
	/**
	 * Create the menu to manage the configuration of the extension, but only for
	 * users allowed to manage the configuration
	 */
	public static function OnMenuCreation()
	{
		$bConfigMenuEnabled = UserRights::IsAdministrator() && version_compare(ITOP_DESIGN_LATEST_VERSION, '3.0') >= 0;
		if ($bConfigMenuEnabled) {
			new OQLMenuNode(
				'SearchPersonalTokens',
				"SELECT PersonalToken",
				ApplicationMenu::GetMenuIndexById('UserManagement'),
				30,
				true);
		}
	}
}