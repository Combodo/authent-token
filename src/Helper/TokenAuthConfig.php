<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Helper;

use MetaModel;

class TokenAuthConfig
{
	const OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS = 4 * 3600; // 4 hours
	const OAUTH2_REFRESH_TOKEN_EXPIRATION_IN_SECONDS = 6 * 30 * 24 * 3600; // 6 months

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
		$aParamsByTokenType = MetaModel::GetModuleSetting('authent-token', $sTokenType, array());
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

	public function GetAccessTokenRetentionInSeconds() : int {
		return (int) TokenAuthConfig::GetInstance()->Get(strtolower('OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS'), null,
			self::OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
	}

	public function GetRefreshTokenRetentionInSeconds() : int {
		return (int) TokenAuthConfig::GetInstance()->Get(strtolower('OAUTH2_REFRESH_TOKEN_EXPIRATION_IN_SECONDS'), null,
			self::OAUTH2_REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
	}

}
