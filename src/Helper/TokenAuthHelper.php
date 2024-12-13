<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Helper;

class TokenAuthHelper
{
	const MODULE_NAME = 'authent-token';

	public function __construct()
	{
		TokenAuthLog::Enable(APPROOT.'log/error.log');
	}

	public static function GenerateUrl(string $sUrl, array $aUrlParameters)
	{
		if (count($aUrlParameters) === 0){
			return $sUrl;
		}

		if (false === strpos($sUrl, '?')){
			$sUrl .= '?';
		} else {
			$sUrl .= '&';
		}


		foreach ($aUrlParameters as $sKey => $sValue) {
			$sUrl .= "$sKey=" . urlencode($sValue) . "&";
		}

		return $sUrl;
	}
}
