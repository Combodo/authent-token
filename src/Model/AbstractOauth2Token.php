<?php

use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\iToken;
use Combodo\iTop\Application\Helper\Session;

/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

abstract class AbstractOauth2Token extends cmdbAbstractObject  implements iToken
{
	private $aContext;

	public function GetUser() : \User
	{
		try {
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
		} catch(\Exception $e){
			Session::Set('oauth_http_errorcode', 401);
			throw new TokenAuthException("GetUser issue", 401, $e);
		}
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
	}

	/**
	 * @return mixed
	 * @throws \ArchivedObjectException
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 */
	public function CheckScopes(): void
	{
		if (Session::Get('oauth_token_endpoint', false)){
			return;
		}

		$aScopeValues = explode(' ', $this->Get('scope'));
		foreach ($aScopeValues as $sScope) {
			if (ContextTag::Check($sScope)) {
				return;
			}
		}

		if (MetaModel::GetConfig()->Get('login_debug')){
			TokenAuthLog::Info(sprintf(
				"Current context (%s) does not match current Token allowed scopes: %s",
				implode(',', ContextTag::GetStack()),
				implode(",", $aScopeValues)
			),
				null,
				$this->GetContextParams()
			);
		}

		Session::Set('oauth_http_errorcode', 403);
		throw new TokenAuthException('Scope not authorized', 403);
	}


	public function UpdateUsage(): void
	{
		if (Session::Get('oauth_token_endpoint', false)){
			return;
		}

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
