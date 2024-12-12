<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use utils;

class Oauth2AuthorizeController extends Controller
{
	private \Oauth2Application $oOauth2Application;

	public function OperationOauth2Authorize(): void
	{
		$aParams=[
			'sApplication' => $this->oOauth2Application->Get('application'),
			'sTransactionId' => utils::GetNewTransactionId(),
		];
		$this->DisplayPage($aParams);
	}

	public function SetApplication(\Oauth2Application $oOauth2Application)
	{
		$this->oOauth2Application = $oOauth2Application;
	}
}