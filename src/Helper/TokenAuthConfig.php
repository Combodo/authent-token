<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Helper;

use MetaModel;

class TokenAuthConfig
{
	private static TokenAuthConfig $oInstance;

	private function __construct()
	{
	}

	public static function GetInstance(): TokenAuthConfig
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new TokenAuthConfig();
		}

		return static::$oInstance;
	}

	public function Get(string $sParamName, string $sTokenType = null, $default = null)
	{
		if (is_null($sTokenType)) {
			return MetaModel::GetModuleSetting('authent-token', $sParamName, $default);
		}
		$aParamsByTokenType = MetaModel::GetModuleSetting('authent-token', 'application_token', array());
		if (array_key_exists($sParamName, $aParamsByTokenType)) {
			return $aParamsByTokenType[$sParamName];
		}

		return $default;
	}

	public function GetBoolean(string $sParamName, string $sTokenType = null, $default = null)
	{
		$res = $this->Get($sParamName, $sTokenType, $default);
		if (is_string($res)) {
			return $res === 'true';
		}

		return $res;
	}


}