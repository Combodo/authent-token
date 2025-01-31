<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Dict;
use Exception;
use Oauth2Application;
use utils;
use \Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;

class Oauth2AuthorizeController extends Controller
{
	public function OperationOauth2Authorize(): void
	{
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

	public function Oauth2Token(): void {
		$sClientId = utils::ReadPostedParam('client_id', null, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sClientSecret = utils::ReadPostedParam('client_secret', null, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sGrantType = utils::ReadPostedParam('grant_type', null, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sCode = utils::ReadPostedParam('code', null, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sRedirectUri = utils::ReadPostedParam('redirect_uri', null, utils::ENUM_SANITIZATION_FILTER_URL);

		$aParams = Oauth2ApplicationService::GetInstance()->GetTokenFields($sClientId, $sClientSecret, $sCode, $sGrantType, $sRedirectUri);

		echo json_encode($aParams, JSON_PRETTY_PRINT);
	}
}
