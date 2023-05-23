<?php

namespace Combodo\iTop\AuthentToken\Hook;

use Combodo\iTop\AuthentToken\Controller\MyAccountController;
use Dict;
use iPopupMenuExtension;
use URLPopupMenuItem;
use utils;
use UserRights;

class MyAccountPopupMenuExtension implements iPopupMenuExtension
{
	/**
	 * Get the list of items to be added to a menu.
	 *
	 * This method is called by the framework for each menu.
	 * The items will be inserted in the menu in the order of the returned array.
	 * @param int $iMenuId The identifier of the type of menu, as listed by the constants MENU_xxx
	 * @param mixed $param Depends on $iMenuId, see the constants defined above
	 * @return object[] An array of ApplicationPopupMenuItem or an empty array if no action is to be added to the menu
	 */
	public static function EnumItems($iMenuId, $param) {
		$aResult = [];
		switch ($iMenuId) // type of menu in which to add menu items
		{
			/**
			 * Insert an item into the User menu (upper right corner of the page)
			 *
			 * $param is null
			 */
			case iPopupMenuExtension::MENU_USER_ACTIONS:
				if (MyAccountController::IsMenuAllowed(UserRights::GetUserObject())){
					$aResult[] = new URLPopupMenuItem('UI:MyAccount', Dict::S('UI:MyAccount'), utils::GetAbsoluteUrlModulePage('authent-token', "index.php"));
				}
				break;
        }
			return $aResult;
	}
}
