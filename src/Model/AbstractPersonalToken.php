<?php

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\iToken;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use Combodo\iTop\AuthentToken\Service\PersonalTokenService;

/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

abstract class AbstractPersonalToken extends cmdbAbstractObject  implements iToken
{
	private $aContext;

	public function GetUser() : \User
	{
		/** @var \User $oUser */
		$oUser = MetaModel::GetObject(\User::class, $this->Get('user_id'));
		$this->aContext = [
			'token' => get_class($this),
			'token_id' => $this->GetKey(),
			'user_class' => get_class($oUser),
			'user_id' => $oUser->GetKey(),
			'login' => $oUser->Get('login'),
		];

		if (MetaModel::GetConfig()->Get('login_debug')) {
			TokenAuthLog::Info("GetUser", null,
				$this->aContext
			);
		}

		return $oUser;
	}

	private function GetContextParams() : array {
		if (is_null($this->aContext)){
			$this->aContext = [
				'token' => get_class($this),
				'token_id' => $this->GetKey(),
			];
		}

		return $this->aContext;
	}

	public function CheckValidity(string $sToken): void
	{
		$oUser = $this->GetUser();
		if (! PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser)){
			if (MetaModel::GetConfig()->Get('login_debug')) {
				$aProfiles = PersonalTokenService::GetInstance()->GetAuthorizedProfiles();
				$sMessage = sprintf('Current user has not the Personal Token allowed profiles (%s).', implode(',', $aProfiles));
				TokenAuthLog::Info($sMessage, null, $this->GetContextParams());
			}
			throw new TokenAuthException("No personal token allowed profile");
		}

		$oPassword = $this->Get('auth_token');
		if (! $oPassword->CheckPassword($sToken)) {
			if (MetaModel::GetConfig()->Get('login_debug')) {
				TokenAuthLog::Info("Invalid token", null, $this->GetContextParams());
			}
			throw new TokenAuthException('Invalid token');
		}

		$sTokenValidity = $this->Get('expiration_date');
		if (! is_null($sTokenValidity)) {
			$oNowDateTime = new DateTime();
			$iNowUnixSeconds = $oNowDateTime->format('U');


			$oDateTimeFormat = new \DateTimeFormat('Y-m-d H:i:s');
			$oLastUseDateTime = $oDateTimeFormat->Parse($sTokenValidity);
			$iExpirationUnixSeconds = $oLastUseDateTime->format('U');

			if ($iNowUnixSeconds > $iExpirationUnixSeconds) {
				// Not valid anymore
				if (MetaModel::GetConfig()->Get('login_debug')) {
					TokenAuthLog::Info("Invalid token validity", null, $this->GetContextParams());
				}
				throw new TokenAuthException('Invalid token validity');
			}
		}

		$this->CheckScopes();
	}


	/**
	 * @return mixed
	 * @throws \ArchivedObjectException
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 */
	public function CheckScopes(): void
	{
		$aScopeValues = explode(' ', $this->Get('scope'));
		foreach ($aScopeValues as $sScope) {
			if (\ContextTag::Check($sScope)) {
				return;
			}
		}

		if (MetaModel::GetConfig()->Get('login_debug')){
			TokenAuthLog::Info(sprintf(
				"Current context (%s) does not match current Token allowed scopes: %s",
				implode(',', \ContextTag::GetStack()),
				implode(",", $aScopeValues)
			),
				null,
				$this->GetContextParams()
			);
		}

		throw new TokenAuthException('Scope not authorized');
	}


	public function UpdateUsage(): void
	{
		$iUseCount = $this->Get('use_count') + 1;
		$this->Set('use_count', $iUseCount);

		$sDateTime = date('Y-m-d H:i:s', time());
		$this->Set('last_use_date', $sDateTime);
		$this->AllowWrite();
		$this->DBUpdate();
		CMDBObject::SetCurrentChange(null);

		if (MetaModel::GetConfig()->Get('allow_rest_services_via_tokens')
			&&
			(ContextTag::Check(ContextTag::TAG_REST) || ContextTag::Check(ContextTag::TAG_SYNCHRO)))
		{
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Info("Rest profiles can be bypassed with 'allow_rest_services_via_tokens' enabled ('secure_rest_services' disabled once).",
					null,
					$this->GetContextParams()
				);
			}

			//let user do rest calls even without rest profiles
			MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
		}
	}

}
