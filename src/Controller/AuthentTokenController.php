<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\AuthentToken\Service\PersonalTokenService;

class AuthentTokenController extends Controller
{

	public function OperationPersonalToken(): void
	{
		$aParams = [
			'Section' => PersonalTokenService::GetInstance()->ProvideHtmlTokenInfo(\UserRights::GetUserObject()),
		];

		$this->DisplayAjaxPage($aParams, 'personaltokens');
	}
}