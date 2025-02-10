<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use Combodo\iTop\ItopAttributeEncryptedPassword\Model\ormEncryptedPassword;
use ContextTag;
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

	public function SaveCode(lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser, string $sCode, string $state) : void
	{
		$oLnkOauth2ApplicationToUser->Set('code', $sCode);
		$oLnkOauth2ApplicationToUser->Set('authorization_state', $state);
		$oLnkOauth2ApplicationToUser->Set('refresh_token', Oauth2ApplicationService::GetInstance()->GenerateToken());
		$oLnkOauth2ApplicationToUser->Set('access_token', Oauth2ApplicationService::GetInstance()->GenerateToken());

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
		$oLnkOauth2ApplicationToUser->Set('access_token_expiration', $sExpireAt);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
		$oLnkOauth2ApplicationToUser->Set('refresh_token_expiration', $sExpireAt);

		$oLnkOauth2ApplicationToUser->AllowWrite();
		$oLnkOauth2ApplicationToUser->DBWrite();
	}

	public function GetLnkOauth2ApplicationToUserByAccesToken(string $sAccessToken) : lnkOauth2ApplicationToUser
	{
		try {
			$sOQL = <<<OQL
SELECT lnkOauth2ApplicationToUser AS l 
OQL;

			$oSearch = DBObjectSearch::FromOQL($sOQL, []);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);
			/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			while ($oLnkOauth2ApplicationToUser = $oSet->Fetch()) {
				$sFetchedAccessToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
				TokenAuthLog::Debug(__METHOD__, null,
					[
						'access_token'       => $sAccessToken,
						'fetch_access_token' => $sFetchedAccessToken,
					]
				);

				if ($sFetchedAccessToken === $sAccessToken) {
					return $oLnkOauth2ApplicationToUser;
				}
			}
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}

		throw new TokenAuthException("Invalid access_token", 400, null, []);
	}

	public function GetLnkOauth2ApplicationToUserByRefreshToken(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sRefreshToken) : lnkOauth2ApplicationToUser
	{
		return $this->GetLnkOauth2ApplicationToUserBy($sClientId, $sClientSecret, $sRedirectUri, 'refresh_token', $sRefreshToken);
	}

	public function GetLnkOauth2ApplicationToUserByCode(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sCode) : lnkOauth2ApplicationToUser
	{
		return $this->GetLnkOauth2ApplicationToUserBy($sClientId, $sClientSecret, $sRedirectUri, 'code', $sCode);
	}

	private function GetLnkOauth2ApplicationToUserBy(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sFieldName, string $sFieldValue) : lnkOauth2ApplicationToUser
	{
		try {
			$sOQL = <<<OQL
SELECT l,a FROM 
	lnkOauth2ApplicationToUser AS l JOIN Oauth2Application AS a 
	ON l.application_id = a.id 
	WHERE 
	a.client_id =:client_id 
	AND a.redirect_uri=:redirect_uri
OQL;

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[
					'client_id' => $sClientId,
					'client_secret' => $sClientSecret,
					'redirect_uri' => $sRedirectUri,
				]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			while ($aObjects = $oSet->FetchAssoc()){
				/** @var Oauth2Application $oOauth2Application */
				$oOauth2Application = $aObjects['a'];

				/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
				$oLnkOauth2ApplicationToUser = $aObjects['l'];

				if ($oOauth2Application->Get('client_secret')->GetPassword() !== $sClientSecret){
					throw new TokenAuthException("Invalid client_secret", 400, null,
						[
							'application_id' => $oOauth2Application->GetKey(),
							'client_id' => $sClientId,
							'redirect_uri' => $sRedirectUri,
						]
					);
				}

				$oValue = $oLnkOauth2ApplicationToUser->Get($sFieldName);
				if (is_string($oValue)){
					$sValue = $oValue;
				} else {
					$sValue = $oValue->GetPassword();
				}

				if ($sValue === $sFieldValue){
					return $oLnkOauth2ApplicationToUser;
				}

			}

			throw new TokenAuthException("Cannot find lnkOauth2Application by provided $sFieldName", 400, null,
				[
					'field' => $sFieldName,
					'client_id' => $sClientId,
					'redirect_uri' => $sRedirectUri,
				]
			);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}
}
