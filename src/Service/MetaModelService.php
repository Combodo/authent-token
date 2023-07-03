<?php

namespace Combodo\iTop\AuthentToken\Service;

class MetaModelService {
	public function GetObject($sClass, $iKey, $bMustBeFound = true, $bAllowAllData = false, $aModifierProperties = null)
	{
		return \MetaModel::GetObject($sClass, $iKey, $bMustBeFound, $bAllowAllData, $aModifierProperties);
	}
}
