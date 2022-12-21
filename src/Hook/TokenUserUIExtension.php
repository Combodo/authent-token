<?php
namespace Combodo\iTop\AuthentToken\Hook;

use AbstractApplicationUIExtension;
use Dict;
use User;
use WebPage;

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
