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
		TokenAuthLog::Enable(APPROOT.'log/error.log');
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

	public function GenerateToken(LnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser) : string
	{
		return AuthentTokenService::GetInstance()->CreateNewToken($oLnkOauth2ApplicationToUser, 24);
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
	 * @return Oauth2Application
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
		$oLnkOauth2ApplicationToUser->Set('refresh_token', Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser));
		$oLnkOauth2ApplicationToUser->Set('access_token', Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser));

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
		$oLnkOauth2ApplicationToUser->Set('access_token_expiration', $sExpireAt);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
		$oLnkOauth2ApplicationToUser->Set('refresh_token_expiration', $sExpireAt);

		$oLnkOauth2ApplicationToUser->AllowWrite();
		$oLnkOauth2ApplicationToUser->DBWrite();
		$oLnkOauth2ApplicationToUser->Reload();
	}

	public function RenewAccessToken(lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser) : void
	{
		$sNewAccessToken = Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser);
		$oLnkOauth2ApplicationToUser->Set('access_token', $sNewAccessToken);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + self::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
		$oLnkOauth2ApplicationToUser->Set('access_token_expiration', $sExpireAt);

		$oLnkOauth2ApplicationToUser->AllowWrite();
		$oLnkOauth2ApplicationToUser->DBWrite();
		$oLnkOauth2ApplicationToUser->Reload();
	}

	public function GetLnkOauth2ApplicationToUserByAccessToken(string $sAccessToken) : lnkOauth2ApplicationToUser
	{
		try {
			/** @var ?lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = AuthentTokenService::GetInstance()->DecryptToken($sAccessToken);

			if (! is_null($oLnkOauth2ApplicationToUser)){
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
		try {
			/** @var ?lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = AuthentTokenService::GetInstance()->DecryptToken($sRefreshToken);

			if (! is_null($oLnkOauth2ApplicationToUser)){
				$sFetchedRefreshToken = $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword();
				TokenAuthLog::Debug(__METHOD__, null,
					[
						'refresh_token'       => $sRefreshToken,
						'fetch_access_token' => $sFetchedRefreshToken,
					]
				);

				if ($sFetchedRefreshToken !== $sRefreshToken) {
					throw new TokenAuthException("Overwritten refresh_token used", 400, null, []);
				}

				/** @var Oauth2Application $oOauth2Application */
				$oOauth2Application = \MetaModel::GetObject(Oauth2Application::class, $oLnkOauth2ApplicationToUser->Get('application_id'));

				if ($oOauth2Application->Get('client_secret')->GetPassword() !== $sClientSecret){
					throw new TokenAuthException("Invalid client_secret provided", 400, null,
						[
							'application_id' => $oOauth2Application->GetKey(),
							'client_id' => $sClientId,
							'redirect_uri' => $sRedirectUri,
						]
					);
				}

				return $oLnkOauth2ApplicationToUser;
			}
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}

		throw new TokenAuthException("Invalid refresh_token", 400, null, []);
	}

	public function GetLnkOauth2ApplicationToUserByCode(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sCode) : lnkOauth2ApplicationToUser
	{
		try {
			$sOQL = <<<OQL
SELECT l,a FROM 
	lnkOauth2ApplicationToUser AS l JOIN Oauth2Application AS a 
	ON l.application_id = a.id 
	WHERE 
	a.client_id =:client_id 
	AND a.redirect_uri=:redirect_uri
	AND l.code = :code
OQL;

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[
					'client_id' => $sClientId,
					'client_secret' => $sClientSecret,
					'redirect_uri' => $sRedirectUri,
					'code' => $sCode
				]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			if ($oSet->Count() !== 1){
				throw new TokenAuthException("Invalid code provided", 400, null,
					[
						'client_id' => $sClientId,
						'redirect_uri' => $sRedirectUri,
						'code' => $sCode,
					]
				);
			}

			$aObjects = $oSet->FetchAssoc();

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

			return $oLnkOauth2ApplicationToUser;
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}
}
