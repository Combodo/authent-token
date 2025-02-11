<?php

namespace Combodo\iTop\AuthentToken\Controller;

use AttributeDateTime;
use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use DateTime;
use Dict;
use Exception;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use utils;
use \Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;

class Oauth2AuthorizeController extends Controller
{
	private static Oauth2AuthorizeController $oInstance;

	final public static function GetInstance(): Oauth2AuthorizeController
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new static();
		}

		return static::$oInstance;
	}

	final public static function SetInstance(?Oauth2AuthorizeController $oInstance): void
	{
		static::$oInstance = $oInstance;
	}

	public function OperationOauth2Authorize(): void
	{
		TokenAuthLog::Enable();
		$sClientId = utils::ReadParam('client_id', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sState = utils::ReadParam('state', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sRedirectUri = utils::ReadParam('redirect_uri', '', false, utils::ENUM_SANITIZATION_FILTER_URL);
		$sScope = utils::ReadParam('scope', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);

		/** @var Oauth2UserApplication $oOauth2UserApplication */
		$oOauth2UserApplication = Oauth2ApplicationService::GetInstance()->DecodeAuthorizationRequest($sClientId, $sRedirectUri);

		$oOauth2Application = $oOauth2UserApplication->oOauth2Application;
		$aParams = [
			'sApplication' => $oOauth2Application->Get('application'),
			'iApplicationId' => $oOauth2Application->GetKey(),
			'sScope' => $sScope,
			'sState' => $sState,
			'sTransactionId' => utils::GetNewTransactionId(),
		];
		$this->DisplayPage($aParams);
	}

	/**
	 * Manage the consent of the User
	 *
	 * @return void
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 */
	public function OperationDoAuthorize(): void
	{
		try {
			TokenAuthLog::Enable();
			$sTransactionId = utils::ReadPostedParam('transaction_id', '', utils::ENUM_SANITIZATION_FILTER_TRANSACTION_ID);

			if (!utils::IsTransactionValid($sTransactionId)) {
				throw new TokenAuthException(Dict::S('UI:Error:InvalidTransactionId'), 400);
			}

			$sApplicationId = utils::ReadPostedParam('application_id', '', utils::ENUM_SANITIZATION_FILTER_RAW_DATA);

			/** @var Oauth2UserApplication $oOauth2UserApplication */
			$oOauth2UserApplication = Oauth2ApplicationService::GetInstance()->GetOauth2UserApplication($sApplicationId);

			$oOauth2Application = $oOauth2UserApplication->oOauth2Application;
			$sUrl = $oOauth2Application->Get('redirect_uri');

			$sScope = utils::ReadPostedParam('scope', '', utils::ENUM_SANITIZATION_FILTER_STRING);
			$sState = utils::ReadPostedParam('state', '', utils::ENUM_SANITIZATION_FILTER_RAW_DATA);
			$aUrlParameters = [
				'state' => $sState,
				'scope' => $sScope,
			];

			// Either allow or disallow
			$sDecision = utils::ReadPostedParam('decision', null, utils::ENUM_SANITIZATION_FILTER_STRING);
			if ($sDecision === 'disallow') {
				$aUrlParameters['error'] =  'access_denied';
			} else {
				$sCode = base64_encode(random_bytes(24));
				Oauth2ApplicationService::GetInstance()->SaveCode($oOauth2UserApplication->oLnkOauth2ApplicationToUser, $sCode, $sState);
				$aUrlParameters['code'] = $sCode;
			}

			$aParams = [
				'sURL' => TokenAuthHelper::GenerateUrl($sUrl, $aUrlParameters),
			];

			TokenAuthLog::Info("Redirection to oauth client uri", null, $aParams);

			$this->DisplayPage($aParams);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException(__FUNCTION__.': failed', 500, $e);
		}
	}

	private function GetHeaderAuthorization(): ?string
	{
		$aHeaders = getallheaders();
		return $aHeaders['Authorization'] ?? null;
	}

	public function IsOauthToken() : bool {
		TokenAuthLog::Debug(__METHOD__ . ": header received for Oauth2 check", null, getallheaders());

		$sAuthorization = $this->GetHeaderAuthorization();
		if (! is_null($sAuthorization)) {
			if (preg_match('/Bearer (.*)/', $sAuthorization, $aMatches)){
				return true;
			} else {
				TokenAuthLog::Debug(__METHOD__ . ": Authorization header does not match Oauth2 authentication", null,
					['Authorization Header' => $sAuthorization]);
			}
		}

		return \ContextTag::Check(TokenAuthHelper::TAG_OAUTH2_ENDPOINT);
	}

	public function AuthenticateViaOauth() : lnkOauth2ApplicationToUser {
		try {
			TokenAuthLog::Enable();
			$sAuthorization = $this->GetHeaderAuthorization();
			if (! is_null($sAuthorization)) {
				if (preg_match('/Bearer (.*)/', $sAuthorization, $aMatches)) {
					$sAccessToken = $aMatches[1];
					TokenAuthLog::Debug(__METHOD__ . ": try Oauth2 by access_token", null,
						['access_token' => $sAccessToken]);
					$olnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByAccessToken($sAccessToken);

					TokenAuthLog::Debug(__METHOD__ . ": check access_token_expiration", null,
						['id' => $olnkOauth2ApplicationToUser->GetKey(), 'access_token_expiration' => $olnkOauth2ApplicationToUser->Get('access_token_expiration')]);

					$iExpireIn = $this->GetExpiredInSeconds($olnkOauth2ApplicationToUser, 'access_token_expiration');
					if ($iExpireIn == 0){
						throw new TokenAuthException('Expired access_token must be refreshed', 400, null,
							['lnk_id' => $olnkOauth2ApplicationToUser, 'application_id' => $olnkOauth2ApplicationToUser->Get('application_id')]);
					}
					return $olnkOauth2ApplicationToUser;
				} else {
					TokenAuthLog::Debug(__METHOD__ . ": Authorization header does not match Oauth2 authentication", null,
						['Authorization Header' => $sAuthorization]);
				}
			}

			if (\ContextTag::Check(TokenAuthHelper::TAG_OAUTH2_ENDPOINT)) {
				$sClientId = utils::ReadPostedParam('client_id', null, utils::ENUM_SANITIZATION_FILTER_STRING);
				$sClientSecret = utils::ReadPostedParam('client_secret', null, utils::ENUM_SANITIZATION_FILTER_STRING);
				$sGrantType = utils::ReadPostedParam('grant_type', null, utils::ENUM_SANITIZATION_FILTER_STRING);
				$sRedirectUri = utils::ReadPostedParam('redirect_uri', null, utils::ENUM_SANITIZATION_FILTER_URL);

				if ($sGrantType === "authorization_code"){
					$sToken = utils::ReadPostedParam('code', null, utils::ENUM_SANITIZATION_FILTER_RAW_DATA);
					if (! is_null($sToken)) {

						TokenAuthLog::Debug("try Oauth2 by code", null,
							[
								'code' => $sToken,
								'grant_type' => $sGrantType,
								'client_id' => $sClientId,
								'client_secret' => $sClientSecret,
								'redirect_uri' => $sRedirectUri,
							]
						);
						return Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByCode($sClientId, $sClientSecret, $sRedirectUri, $sToken);
					}

					throw new TokenAuthException('Missing Oauth2 code', 400, null, ['grant_type' => $sGrantType]);
				} else if ($sGrantType === "refresh_token"){
					$sToken = utils::ReadPostedParam('refresh_token', null, utils::ENUM_SANITIZATION_FILTER_RAW_DATA);

					if (! is_null($sToken)) {
						$olnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByRefreshToken($sClientId, $sClientSecret, $sRedirectUri, $sToken);

						$iExpireIn = $this->GetExpiredInSeconds($olnkOauth2ApplicationToUser, 'refresh_token_expiration');
						if ($iExpireIn == 0){
							throw new TokenAuthException('Expired refresh_token', 400, null,
								['lnk_id' => $olnkOauth2ApplicationToUser, 'application_id' => $olnkOauth2ApplicationToUser->Get('application_id')]);
						}

						return $olnkOauth2ApplicationToUser;
					}

					throw new TokenAuthException('Missing Oauth2 refresh_token', 400, null, ['grant_type' => $sGrantType]);
				}

				throw new TokenAuthException('Invalid grant_type access', 400, null, ['grant_type' => $sGrantType]);
			}

			throw new TokenAuthException('No Oauth token found. No Oauth Bearer token provider in the header /Specific token endpoint not reached.', 400, null);

		} catch(TokenAuthException $e){
			throw $e;
		} catch(\Exception $e){
			throw new TokenAuthException('invalid_token', 400, $e);
		}
	}

	public function OperationOauth2Token(): string {
		TokenAuthLog::Enable();

		//TokenLoginExtension handled whole authentication and stored token_id in the session
		$sTokenId = Session::Get('token_id');
		$oLnkOauth2ApplicationToUser = \MetaModel::GetObject(lnkOauth2ApplicationToUser::class, $sTokenId);

		$iExpireIn = $this->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'access_token_expiration');

		$aParams = [
			'access_token' => $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(),
			'token_type' => $oLnkOauth2ApplicationToUser->Get('token_type'),
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			'expires_in' => $iExpireIn,
		];

		$sJson = json_encode($aParams, JSON_PRETTY_PRINT);
		echo $sJson;
		return $sJson;
	}

	public function GetExpiredInSeconds(lnkOauth2ApplicationToUser $olnkOauth2ApplicationToUser, string $sExpirationDateFieldName) : int
	{
		$oAttDateTime = $olnkOauth2ApplicationToUser->Get($sExpirationDateFieldName);
		if (is_null($oAttDateTime)) {
			throw new TokenAuthException("No $sExpirationDateFieldName date found");
		}
		$oDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $oAttDateTime);
		$oNow = new DateTime();
		$iExpireIn = $oDateTime->getTimestamp() - $oNow->getTimestamp();
		if ($iExpireIn <= 0){
			return 0;
		}

		return $iExpireIn;
	}
}
