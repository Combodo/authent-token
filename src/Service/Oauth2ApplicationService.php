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

	public function DecodeAuthorizationRequest() : Oauth2Application
	{
		$sGrantType = utils::ReadParam('grant_type', null);
		if ($sGrantType !== 'authorization_code') {
			throw new TokenAuthException("Incorrect authorize grant_type");
		}

		$sClientId = utils::ReadParam('client_id', null);
		$sRedirectUri = utils::ReadParam('redirect_uri', null);
		$sScope = utils::ReadParam('scope', null);
		$sPrompt = utils::ReadParam('prompt', null);
		$sAccessType = utils::ReadParam('access_type', null);

		$oApplication = $this->GetApplication($sClientId);

		return $oApplication;
	}

	/**
	 * @param string $sClientId
	 *
	 * @return \Oauth2Application
	 */
	public function GetApplication(string $sClientId) : Oauth2Application
	{
		try {
			$sFilter = "SELECT Oauth2Application WHERE client_id = :client_id";
			$oSet = new DBObjectSet(DBObjectSearch::FromOQL($sFilter));
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
}