<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use DBObjectSearch;
use DBObjectSet;
use Exception;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use UserRights;
use utils;
use AttributeDateTime;
use DateTime;

class Oauth2ApplicationService {
	const CONSENT = "OAUTH2_SERVER_CONSENT";
	const APPLICATION_ID = "OAUTH2_SERVER_APP_ID";
	const ACCESS_TOKEN_EXPIRATION_IN_SECONDS = 4 * 3600; // 4 hours
	const REFRESH_TOKEN_EXPIRATION_IN_SECONDS = 6 * 30 * 24 * 3600; // 6 months

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

	public function GenerateToken() : string
	{
		return base64_encode(random_bytes(24));
	}

	public function GenerateClientId() : string
	{
		return base64_encode(random_bytes(24));
	}

	public function GenerateClientSecret() : string
	{
		return base64_encode(random_bytes(24));
	}

	public function GetOauthToken($sToken) : lnkOauth2ApplicationToUser {
	}

	public function GetTokenFields(string $sClientId, string $sClientSecret, string $sCode, string $sGrantType, string $sRedirectUri) : array {
		if ($sGrantType !== 'authorization_code'){
			throw new TokenAuthException(__FUNCTION__.': invalid grant_type', 500, null, ['grant_type' => $sGrantType]);
		}

		$oOauth2UserApplication = Oauth2ApplicationService::GetInstance()->DecodeAuthorizationRequest($sClientId, $sRedirectUri);

		$oOauth2Application = $oOauth2UserApplication->oOauth2Application;
		$oLnkOauth2ApplicationToUser = $oOauth2UserApplication->oLnkOauth2ApplicationToUser;

		$sExpectedSecret = $oOauth2Application->oOauth2Application->Get('client_secret')->GetPassword();
		if ($sClientSecret !== $sExpectedSecret){
			$aParams = [
				'Oauth2Application' => $oOauth2Application->GetKey(),
				'posted_client_secret' => $sClientSecret,
				'client_secret' => $sExpectedSecret,
				'client_id' => $sClientId,
				'redirect_uri' => $sRedirectUri,
			];
			TokenAuthLog::Debug("Invalid client_secret provided", null, $aParams);
			throw new TokenAuthException(__FUNCTION__.': invalid client_secret', 500, null, $aParams);
		}

		$sExpectedCode = $oOauth2Application->oOauth2Application->Get('code');
		if ($sGrantType === 'authorization_code' && $sExpectedCode !== $sCode){
			$aParams = [
				'Oauth2Application' => $oOauth2Application->GetKey(),
				'lnkOauth2ApplicationToUser' => $oOauth2UserApplication->GetKey(),
				'posted_code' => $sCode,
				'code' => $sExpectedCode,
				'client_id' => $sClientId,
			];
			TokenAuthLog::Debug("Invalid code provided", null, $aParams);
			throw new TokenAuthException(__FUNCTION__.': invalid code', 500, null, $aParams);
		}

		$oAttDateTime = $oLnkOauth2ApplicationToUser->Get('access_token_expiration');
		if (is_null($oAttDateTime)) {
			throw new TokenAuthException('No access_token_expiration date found');
		}
		$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $oAttDateTime);
		$iExpireIn = $oDateTime - new DateTime();
		if ($iExpireIn < 0){
			$iExpireIn = 0;
		}

		return [
			'access_token' => $oLnkOauth2ApplicationToUser->Get('access_token'),
			'token_type' => $oLnkOauth2ApplicationToUser->Get('token_type'),
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token'),
			'expires_in' => $iExpireIn,
		];
	}

	public function GetOauth2UserApplication(string $sApplicationId) : Oauth2UserApplication
	{
		try {
			$sOQL = <<<OQL
SELECT l,a FROM 
	lnkOauth2ApplicationToUser AS l JOIN Oauth2Application AS a 
	ON l.application_id = a.id 
	WHERE 
	a.id =:application_id 
	AND l.user_id=:user_id
OQL;
			$sUserId = UserRights::GetUserId();

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[ 'application_id' => $sApplicationId, 'user_id' => $sUserId ]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			$aObjects = $oSet->FetchAssoc();
			$iCount = $oSet->Count();
			if ($iCount !== 1) {
				$aParams = [
					'application_id' => $sApplicationId,
					'user_id' => UserRights::GetUserId(),
					'count' => $iCount,
				];
				throw new TokenAuthException("Invalid application_id/user_id", 400, null, $aParams);
			}

			/** @var Oauth2Application $oOauth2Application */
			$oOauth2Application = $aObjects['a'];

			/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = $aObjects['l'];

			return new Oauth2UserApplication($oOauth2Application, $oLnkOauth2ApplicationToUser);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}

	/**
	 * @param string $sClientId
	 *
	 * @return \Oauth2Application
	 */
	public function DecodeAuthorizationRequest(string $sClientId, string $sRedirectUri) : Oauth2UserApplication
	{
		try {
			$sOQL = <<<OQL
SELECT l,a FROM 
	lnkOauth2ApplicationToUser AS l JOIN Oauth2Application AS a 
	ON l.application_id = a.id 
	WHERE 
	a.client_id =:client_id 
	AND a.redirect_uri=:redirect_uri
	AND l.user_id=:user_id
OQL;
			$sUserId = UserRights::GetUserId();

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[ 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri, 'user_id' => $sUserId ]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			$aObjects = $oSet->FetchAssoc();
			$iCount = $oSet->Count();
			if ($iCount !== 1) {
				$aParams = [
					'client_id' => $sClientId,
					'redirect_uri' => $sRedirectUri,
					'user_id' => UserRights::GetUserId(),
					'count' => $iCount,
				];
				throw new TokenAuthException("Invalid client_id/redirect_uri/user_id", 400, null, $aParams);
			}

			/** @var Oauth2Application $oOauth2Application */
			$oOauth2Application = $aObjects['a'];

			/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = $aObjects['l'];

			return new Oauth2UserApplication($oOauth2Application, $oLnkOauth2ApplicationToUser);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}

	public function SaveCode(lnkOauth2ApplicationToUser $oOauth2Application, string $sCode, string $state) : void
	{
		$oOauth2Application->Set('code', $sCode);
		$oOauth2Application->Set('authorization_state', $state);
		$oOauth2Application->Set('refresh_token', Oauth2ApplicationService::GetInstance()->GenerateToken());
		$oOauth2Application->Set('access_token', Oauth2ApplicationService::GetInstance()->GenerateToken());

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
		$oOauth2Application->Set('access_token_expiration', $sExpireAt);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
		$oOauth2Application->Set('refresh_token_expiration', $sExpireAt);

		$oOauth2Application->AllowWrite();
		$oOauth2Application->DBWrite();
	}
}
