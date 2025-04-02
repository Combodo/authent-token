<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthConfig;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use Combodo\iTop\ItopAttributeEncryptedPassword\Model\ormEncryptedPassword;
use Combodo\iTop\Service\Events\EventData;
use ContextTag;
use DBObjectSearch;
use DBObjectSet;
use Exception;
use MetaModel;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use UserRights;
use utils;
use AttributeDateTime;
use DateTime;

class Oauth2ApplicationService {
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

			$iCount = $oSet->Count();
			if ($iCount !== 1) {
				$aParams = [
					'client_id' => $sClientId,
					'redirect_uri' => $sRedirectUri,
					'user_id' => $sUserId,
					'count' => $iCount,
				];
				throw new TokenAuthException("Invalid client_id/redirect_uri/user_id", 400, null, $aParams);
			}

			$aObjects = $oSet->FetchAssoc();

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

	public function SaveCode(lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser, string $state) : string
	{
		$sCode = Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser);
		$oLnkOauth2ApplicationToUser->Set('code', $sCode);
		$oLnkOauth2ApplicationToUser->Set('consent_mode', 'form');
		$oLnkOauth2ApplicationToUser->Set('authorization_state', $state);
		$oLnkOauth2ApplicationToUser->Set('refresh_token', Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser));
		$oLnkOauth2ApplicationToUser->Set('access_token', Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser));

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + TokenAuthConfig::GetInstance()->GetAccessTokenRetentionInSeconds());
		$oLnkOauth2ApplicationToUser->Set('access_token_expiration', $sExpireAt);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + TokenAuthConfig::GetInstance()->GetRefreshTokenRetentionInSeconds());
		$oLnkOauth2ApplicationToUser->Set('refresh_token_expiration', $sExpireAt);

		$oLnkOauth2ApplicationToUser->AllowWrite();
		$oLnkOauth2ApplicationToUser->DBWrite();
		$oLnkOauth2ApplicationToUser->Reload();
		return $sCode;
	}

	public function RenewAccessToken(lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser) : void
	{
		$sNewAccessToken = Oauth2ApplicationService::GetInstance()->GenerateToken($oLnkOauth2ApplicationToUser);
		$oLnkOauth2ApplicationToUser->Set('access_token', $sNewAccessToken);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + TokenAuthConfig::GetInstance()->GetAccessTokenRetentionInSeconds());
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

				//check access token has not been refreshed in the meantime
				if ($sFetchedAccessToken === $sAccessToken) {
					return $oLnkOauth2ApplicationToUser;
				}

				TokenAuthLog::Warning(__METHOD__. ': access_token does not match the one stored');
				throw new TokenAuthException("Overwritten access_token used", 400, null, []);
			}
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}

		throw new TokenAuthException("Invalid access_token", 400, null, []);
	}

	private function GetLnkOauth2ApplicationToUserByTokenField(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sTokenValue, string $sTokenField) : lnkOauth2ApplicationToUser
	{
		try {
			/** @var ?lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = AuthentTokenService::GetInstance()->DecryptToken($sTokenValue);

			if (! is_null($oLnkOauth2ApplicationToUser)){
				$sFetchedRefreshToken = $oLnkOauth2ApplicationToUser->Get($sTokenField)->GetPassword();
				TokenAuthLog::Debug(__METHOD__, null,
					[
						$sTokenField       => $sTokenValue,
						'fetch_' . $sTokenField => $sFetchedRefreshToken,
					]
				);

				if ($sFetchedRefreshToken !== $sTokenValue) {
					TokenAuthLog::Warning(__METHOD__. ": $sTokenField does not match the one stored");
					throw new TokenAuthException("Overwritten $sTokenField used", 400, null, []);
				}

				/** @var Oauth2Application $oOauth2Application */
				$oOauth2Application = MetaModel::GetObject(Oauth2Application::class, $oLnkOauth2ApplicationToUser->Get('application_id'));

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

		throw new TokenAuthException("Invalid $sTokenField", 400, null, []);
	}

	public function GetLnkOauth2ApplicationToUserByRefreshToken(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sRefreshToken) : lnkOauth2ApplicationToUser
	{
		return $this->GetLnkOauth2ApplicationToUserByTokenField($sClientId, $sClientSecret, $sRedirectUri, $sRefreshToken, 'refresh_token');
	}

	public function GetLnkOauth2ApplicationToUserByCode(string $sClientId, string $sClientSecret, string $sRedirectUri, string $sCode) : lnkOauth2ApplicationToUser
	{
		return $this->GetLnkOauth2ApplicationToUserByTokenField($sClientId, $sClientSecret, $sRedirectUri, $sCode, 'code');
	}

	/**
	 * Only one lnk associated to Oauth2Application can be in headless mode
	 * @param \lnkOauth2ApplicationToUser $olnkOauth2ApplicationToUser
	 * @param \Combodo\iTop\AuthentToken\Service\EventData $oEventData
	 *
	 * @return void
	 * @throws \ArchivedObjectException
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 */
	public function PropagateFormConsentFormToOtherObjects(lnkOauth2ApplicationToUser $olnkOauth2ApplicationToUser, EventData $oEventData)
	{
		if (! $oEventData->Get('is_new') && ! array_key_exists('consent_mode', $oEventData->Get('changes'))){
			return;
		}

		if ("headless" !== $olnkOauth2ApplicationToUser->Get('consent_mode')){
			return;
		}

		try {
			$sOQL = <<<OQL
SELECT lnkOauth2ApplicationToUser AS l
	WHERE 
	l.application_id =:application_id 
OQL;

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[
					'application_id' => $olnkOauth2ApplicationToUser->Get('application_id'),
				    'key' => $olnkOauth2ApplicationToUser->GetKey(),
					'consent_mode' => 'headless'
				]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			while($oLnkOauth2ApplicationToUser2 = $oSet->Fetch()){
				/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser2 */
				$oLnkOauth2ApplicationToUser2->Set('consent_mode', 'form');
				$oLnkOauth2ApplicationToUser2->AllowWrite();
				$oLnkOauth2ApplicationToUser2->DBWrite();
			}
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}

	public function GetNoConsentLnkOauth2ApplicationToUser(string $sClientId, string $sRedirectUri) : lnkOauth2ApplicationToUser
	{
		try {
			$sOQL = <<<OQL
SELECT l,a FROM 
	lnkOauth2ApplicationToUser AS l JOIN Oauth2Application AS a 
	ON l.application_id = a.id 
	WHERE 
	a.client_id =:client_id 
	AND a.redirect_uri=:redirect_uri
	AND l.consent_mode=:consent_mode
OQL;

			$oSearch = DBObjectSearch::FromOQL($sOQL,
				[ 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri, 'consent_mode' => 'headless' ]);
			$oSearch->AllowAllData();
			$oSet = new DBObjectSet($oSearch);

			$aObjects = $oSet->FetchAssoc();
			$iCount = $oSet->Count();
			if ($iCount !== 1) {
				$aParams = [
					'client_id' => $sClientId,
					'redirect_uri' => $sRedirectUri,
					'count' => $iCount,
				];
				throw new TokenAuthException("Invalid client_id/redirect_uri", 400, null, $aParams);
			}

			/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
			$oLnkOauth2ApplicationToUser = $aObjects['l'];

			return $oLnkOauth2ApplicationToUser;
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException("Internal Server Error", 500, $e);
		}
	}

	public function ResetSecret($sId)
	{
		/** @var Oauth2Application $oObj */
		$oObj = MetaModel::GetObject(Oauth2Application::class, $sId);

		$oObj->Set('client_secret', $this->GenerateClientSecret());
		$oObj->DBWrite();
	}
}
