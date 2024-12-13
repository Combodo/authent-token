<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Dict;
use Exception;
use Oauth2Application;
use utils;

class Oauth2AuthorizeController extends Controller
{
	public function OperationOauth2Authorize(): void
	{
		$sClientId = utils::ReadParam('client_id', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sState = utils::ReadParam('state', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);
		$sRedirectUri = utils::ReadParam('redirect_uri', '', false, utils::ENUM_SANITIZATION_FILTER_URL);
		$sScope = utils::ReadParam('scope', '', false, utils::ENUM_SANITIZATION_FILTER_STRING);

		$oOauth2Application = Oauth2ApplicationService::GetInstance()->DecodeAuthorizationRequest($sClientId, $sRedirectUri, $sScope);

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
			$sTransactionId = utils::ReadPostedParam('transaction_id', '', 'transaction_id');

			if (!utils::IsTransactionValid($sTransactionId)) {
				throw new TokenAuthException(Dict::S('UI:Error:InvalidTransactionId'), 400);
			}

			$sApplicationId = utils::ReadPostedParam('application_id', '', 'transaction_id');
			$oOauth2Application = \MetaModel::GetObject(Oauth2Application::class,$sApplicationId);
			$sUrl = $oOauth2Application->Get('redirect_url');

			$sScope = utils::ReadPostedParam('scope', '');
			$sState = utils::ReadPostedParam('state', '');
			$aUrlParameters = [
				'state' => $sState,
				'scope' => $sScope,
			];

			// Either allow or disallow
			$sDecision = utils::ReadPostedParam('decision', null);
			if ($sDecision === 'disallow') {
				$aUrlParameters['error'] =  'access_denied';
			} else {
				$sCode = base64_encode(random_bytes(24));
				Oauth2ApplicationService::GetInstance()->SaveCode($oOauth2Application, $sCode);
				$aUrlParameters['code'] = $sCode;
			}

			$aParams = [
				'sURL' => TokenAuthHelper::GenerateUrl($sUrl, $aUrlParameters),
			];

			$this->DisplayPage($aParams);
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException(__FUNCTION__.': failed', 500, $e);
		}
	}
}