<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Dict;
use Exception;
use utils;

class Oauth2AuthorizeController extends Controller
{
	private \Oauth2Application $oOauth2Application;

	public function OperationOauth2Authorize(): void
	{
		$this->oOauth2Application = Oauth2ApplicationService::GetInstance()->DecodeAuthorizationRequest();

		$aParams = [
			'sApplication' => $this->oOauth2Application->Get('application'),
			'iApplicationId' => $this->oOauth2Application->GetKey(),
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
			// Either allow or disallow
			$sDecision = utils::ReadPostedParam('decision', null);

			// Redirect to the client
		} catch (TokenAuthException $e) {
			throw $e;
		} catch (Exception $e) {
			throw new TokenAuthException(__FUNCTION__.': failed', 500, $e);
		}
	}
}