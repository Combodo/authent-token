<?php

namespace Combodo\iTop\AuthentToken\Service;

class Oauth2ApplicationService {
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
		return random_bytes(24);
	}

	public function GenerateClientSecret() : string
	{
		return random_bytes(24);
	}
}