<?php
namespace Combodo\iTop\Extension\Hook;

use AbstractApplicationUIExtension;
use WebPage;
use Dict;
use User;

class TokenUserUIExtension  extends AbstractApplicationUIExtension{
	public function OnDisplayRelations($oObject, WebPage $oPage, $bEditMode = false)
	{
		if (! $oObject instanceof User)
		{
			return;
		}

		$oPage->SetCurrentTab('Tokens:Tab', Dict::S('Tokens:TabTitle'));
	}
}
