<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;

class Oauth2ApplicationService {
	const CONSENT = "OAUTH2_SERVER_CONSENT";
	const APPLICATION_ID = "OAUTH2_SERVER_APP_ID";

	private static Oauth2ApplicationService $oInstance;

	protected function __construct()
	{
	}

	final public static function GetInstance(): Oauth2ApplicationService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?Oauth2ApplicationService $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	public function GenerateClientId() : string
	{
		return base64_encode(random_bytes(24));
	}

	public function GenerateClientSecret() : string
	{
		return base64_encode(random_bytes(24));
	}

	public function DecodeAutorizationRequest($sJsonBody) : \Oauth2Application
	{
		$aReq = json_decode($sJsonBody, true);
		if (false === $aReq) {
			throw new TokenAuthException("Invalid Json");
		}

		$sGrantType = $aReq['grant_type'] ?? '';
		if ($sGrantType !== 'authorization_code') {
			throw new TokenAuthException("Incorrect authorize grant_type");
		}

		$sClientId = $aReq['client_id'] ?? null;
		$sClientSecret = $aReq['client_secret'] ?? null;
		$oApplication = $this->GetApplication($sClientId, $sClientSecret);

		return $oApplication;
	}

	public function GetApplication(string $sClientId, string $sClientSecret) : \Oauth2Application
	{

	}
}