<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Helper;

class TokenAuthHelper
{
	const MODULE_NAME         = 'authent-token';
	const TAG_OAUTH2_GETUSER_ENDPOINT = "Oauth2/GetUser";

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
			$sLastChar = substr($sUrl, strlen($sUrl), 1);
			if ('&' === $sLastChar || '?' === $sLastChar) {
				$sUrl .= "$sKey=".urlencode($sValue);
			} else {
				$sUrl .= "&$sKey=".urlencode($sValue);
			}
		}

		return $sUrl;
	}
}
