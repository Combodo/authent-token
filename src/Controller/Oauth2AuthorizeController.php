<?php

namespace Combodo\iTop\AuthentToken\Controller;

use AttributeDateTime;
use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use ContextTag;
use DateTime;
use Dict;
use Exception;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use utils;
use \Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;

class Oauth2AuthorizeController extends Controller
{
	private ?array $aFakeAllHeadersForTest;
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
				$sCode = Oauth2ApplicationService::GetInstance()->SaveCode($oOauth2UserApplication->oLnkOauth2ApplicationToUser, $sState);
				$aUrlParameters['code'] = $sCode;
			}

			$sUrl = TokenAuthHelper::GenerateUrl($sUrl, $aUrlParameters);
			$aParams = [
				'sURL' => $sUrl,
			];

			TokenAuthLog::Info("Redirection to oauth client uri", null, [ 'sURL' => $sUrl ]);

			$this->DisplayPage($aParams);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException(__FUNCTION__.': failed', 500, $e);
		}
	}

	private function GetBearerToken(): ?string
	{
		$sAuthorization = $this->GetHeaderAuthorization();
		if (is_null($sAuthorization)) {
			return null;
		}

		if (preg_match("/^Bearer (?<token>.+)$/", $sAuthorization, $aMatches)) {
			return trim($aMatches['token']);
		}

		TokenAuthLog::Debug(__METHOD__ . ": Header Authorization received ", null,
			['Authorization' => $sAuthorization]);
		return null;
	}

	private function GetHeaderAuthorization(): ?string
	{
		$aHeaders = isset($this->aFakeAllHeadersForTest) ? $this->aFakeAllHeadersForTest : getallheaders();
		return $aHeaders['Authorization'] ?? null;
	}

	public function IsOauthToken() : bool {
		if (Session::Get('oauth_authentication', false)) {
			return true;
		}

		$sBearerToken = $this->GetBearerToken();
		if (! is_null($sBearerToken)) {
			Session::Set('oauth_authentication', true);
			return true;
		}

		TokenAuthLog::Debug(__METHOD__ . ": no oauth authentication possible", null,
			['authentication_header' => $this->GetHeaderAuthorization(), 'context_tags' => ContextTag::GetTags()]);

		return false;
	}

	public function AuthenticateViaOauth() : lnkOauth2ApplicationToUser {
		try {
			TokenAuthLog::Enable();
			$sBearerToken = $this->GetBearerToken();
			if (! is_null($sBearerToken)) {
				TokenAuthLog::Debug(__METHOD__ . ": Bearer token received", null,
					['access_token' => $sBearerToken]);

				$olnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByAccessToken($sBearerToken);

				TokenAuthLog::Debug(__METHOD__ . ": check access_token_expiration", null,
					['id' => $olnkOauth2ApplicationToUser->GetKey(), 'access_token_expiration' => $olnkOauth2ApplicationToUser->Get('access_token_expiration')]);

				$iExpireIn = $this->GetExpiredInSeconds($olnkOauth2ApplicationToUser, 'access_token_expiration');
				if ($iExpireIn == 0){
					throw new TokenAuthException('Expired access_token must be refreshed', 498, null,
						['lnk_id' => $olnkOauth2ApplicationToUser, 'application_id' => $olnkOauth2ApplicationToUser->Get('application_id')]);
				}
				return $olnkOauth2ApplicationToUser;
			}

			$sClientId = utils::ReadPostedParam('client_id', null, utils::ENUM_SANITIZATION_FILTER_STRING);
			$sClientSecret = utils::ReadPostedParam('client_secret', null, utils::ENUM_SANITIZATION_FILTER_STRING);
			$sGrantType = utils::ReadPostedParam('grant_type', null, utils::ENUM_SANITIZATION_FILTER_STRING);
			$sRedirectUri = utils::ReadPostedParam('redirect_uri', null, utils::ENUM_SANITIZATION_FILTER_URL);
			$sCode = utils::ReadPostedParam('code', null, utils::ENUM_SANITIZATION_FILTER_RAW_DATA);
			$sRefreshToken = utils::ReadPostedParam('refresh_token', null, utils::ENUM_SANITIZATION_FILTER_RAW_DATA);

			TokenAuthLog::Debug("Oauth2 authentication parameters", null,
				[
					'code' => $sCode,
					'grant_type' => $sGrantType,
					'client_id' => $sClientId,
					'client_secret' => $sClientSecret,
					'refresh_token' => $sRefreshToken,
					'redirect_uri' => $sRedirectUri,
				]
			);

			if ($sGrantType === "authorization_code"){
				if (! is_null($sCode)) {
					return Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByCode($sClientId, $sClientSecret, $sRedirectUri, $sCode);
				}

				throw new TokenAuthException('Missing Oauth2 code', 400, null,
					['grant_type' => $sGrantType, 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri]);
			} else if ($sGrantType === "refresh_token"){
				if (! is_null($sRefreshToken)) {
					$olnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByRefreshToken($sClientId, $sClientSecret, $sRedirectUri, $sRefreshToken);

					$iExpireIn = $this->GetExpiredInSeconds($olnkOauth2ApplicationToUser, 'refresh_token_expiration');
					if ($iExpireIn == 0){
						throw new TokenAuthException('Expired refresh_token', 498, null,
							['lnk_id' => $olnkOauth2ApplicationToUser, 'application_id' => $olnkOauth2ApplicationToUser->Get('application_id'), 'grant_type' => $sGrantType, 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri]);
					}

					Oauth2ApplicationService::GetInstance()->RenewAccessToken($olnkOauth2ApplicationToUser);
					return $olnkOauth2ApplicationToUser;
				}

				throw new TokenAuthException('Missing Oauth2 refresh_token', 400, null,
					['grant_type' => $sGrantType, 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri]);

			}

			throw new TokenAuthException('Invalid grant_type', 400, null,
				['grant_type' => $sGrantType, 'client_id' => $sClientId, 'redirect_uri' => $sRedirectUri]);
		} catch(TokenAuthException $e){
			throw $e;
		} catch(\Exception $e){
			throw new TokenAuthException('invalid_token', 500, $e);
		}
	}

	/**
	 * @param $sSimulateTokenIdInSession: provided only in testing context
	 *
	 * @return string
	 * @throws \ArchivedObjectException
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 */
	public function OperationOauth2Token(?string $sSimulateTokenIdInSession=null): string {
		TokenAuthLog::Enable();

		//TokenLoginExtension handled whole authentication and stored token_id in the session
		if (! is_null($sSimulateTokenIdInSession)){
			$sTokenId = $sSimulateTokenIdInSession;
		} else {
			$sTokenId = Session::Get('token_id') ?? null;
		}

		if (is_null($sTokenId)){
			throw new TokenAuthException('Missing token_id', 400);
		}

		$oLnkOauth2ApplicationToUser = \MetaModel::GetObject(lnkOauth2ApplicationToUser::class, $sTokenId);

		$iExpireIn = $this->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'access_token_expiration');

		$aResult = [
			'access_token' => $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(),
			'token_type' => $oLnkOauth2ApplicationToUser->Get('token_type'),
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			'expires_in' => $iExpireIn,
		];

		if (is_null($sSimulateTokenIdInSession)) {
			$this->DisplayJSONPage($aResult);
		}

		return json_encode($aResult, JSON_PRETTY_PRINT);
	}

	public function OperationOauth2GetUser(): string {
		TokenAuthLog::Enable();

		$aResult = $this->GetUserFields();
		$this->DisplayJSONPage($aResult);
		return json_encode($aResult, JSON_PRETTY_PRINT);
	}

	private function GetUserFields() : array
	{
		$oUser = \UserRights::GetUserObject();
		if (is_null($oUser)){
			http_response_code(500);
		}

		$sLogin = $oUser->Get('login');
		$oContact = \UserRights::GetContactObject();
		return [
			'email' => 	$oUser->Get('email'),
			'firstName' => 	\UserRights::GetContactFirstname() ?? '',
			'organization' => 	\UserRights::GetContactOrganizationFriendlyname() ?? '',
			'lastName' => 	! is_null($oContact) ? $oUser->Get('last_name') : '',
			'displayName' => 	\UserRights::GetContactFriendlyname() ?? $sLogin,
			'identifier' => $sLogin,
			'language' => 	$oUser->Get('language'),
		];
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
