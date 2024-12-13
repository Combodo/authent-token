<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use DBObjectSearch;
use DBObjectSet;
use Exception;
use Oauth2Application;
use utils;

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

	public function DecodeAuthorizationRequest(string $sClientId, string $sRedirectUri) : Oauth2Application
	{
		$oApplication = $this->GetApplication($sClientId, $sRedirectUri);

		return $oApplication;
	}

	/**
	 * @param string $sClientId
	 *
	 * @return \Oauth2Application
	 */
	public function GetApplication(string $sClientId, string $sRedirectUri) : Oauth2Application
	{
		try {
			$sFilter = "SELECT Oauth2Application WHERE client_id = :client_id AND redirect_url=:redirect_url";
			$oSet = new DBObjectSet(DBObjectSearch::FromOQL($sFilter), [], [
				'client_id' => $sClientId,
				'redirect_url' => $sRedirectUri,
			]);
			/** @var Oauth2Application $oOauth2Application */
			$oOauth2Application = $oSet->Fetch();
			if ($oOauth2Application === null) {
				throw new TokenAuthException("Invalid client_id");
			}

			return $oOauth2Application;
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}

	public function SaveCode(\Oauth2Application $oOauth2Application, string $sCode) : void
	{
		$oOauth2Application->Set('code', $sCode);
		$oOauth2Application->AllowWrite();
		$oOauth2Application->DBWrite();
	}
}