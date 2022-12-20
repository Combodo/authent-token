<?php

namespace Combodo\iTop\AuthentToken\Hook;
use Combodo\iTop\Application\Helper\Session;
use AbstractLoginFSMExtension;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Model\_PersonalToken;
use LoginWebPage;
use utils;
use User;
use DBSearch;
use MetaModel;
use DBObjectSet;
use CMDBObject;
use ormSet;
use IssueLog;

/**
 * Class LoginToken
 *
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TokenLoginExtension extends AbstractLoginFSMExtension
{
	const LOGIN_TYPE = 'token';
	const LEGACY_LOGIN_TYPE = 'rest-token';
	const SUPPORTED_LOGIN_MODES = [ self::LOGIN_TYPE , self::LEGACY_LOGIN_TYPE ];

	/**
	 * @var bool
	 */
	private $bErrorOccurred = false;

	/**
	 * Return the list of supported login modes for this plugin
	 *
	 * @return array of supported login modes
	 */
	public function ListSupportedLoginModes(){
		return self::SUPPORTED_LOGIN_MODES;
	}

	/**
	 * @param string $sLoginMode
	 *
	 * @return bool
	 */
	public function IsLoginModeSupported($sLoginMode)
	{
		return in_array($sLoginMode,self::SUPPORTED_LOGIN_MODES);
	}

	protected function OnModeDetection(&$iErrorCode)
	{
		if (!Session::IsSet('login_mode') && !$this->bErrorOccurred)
		{
			if (isset($_SERVER['HTTP_AUTH_TOKEN'])) {
				$sAuthToken = $_SERVER['HTTP_AUTH_TOKEN'];
			} else {
				$sAuthToken = utils::ReadParam('auth_token', null, false, 'raw_data');
			}
			if (!empty($sAuthToken))
			{
				Session::Start();
				$aAllowedModes = MetaModel::GetConfig()->GetAllowedLoginTypes();
				foreach ($aAllowedModes as $sLoginMode)
				{
					if ($this->IsLoginModeSupported($sLoginMode))
					{
						Session::Set('login_mode', $sLoginMode);
						break;
					}
				}
				Session::Set('login_temp_auth_token', $sAuthToken);
				Session::WriteClose();
			}
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCheckCredentials(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			$sAuthToken = Session::Get('login_temp_auth_token');
			list($oUser, $oPersonalToken) = self::GetUser($sAuthToken);

			if (empty($oUser))
			{
				$iErrorCode = LoginWebPage::EXIT_CODE_WRONGCREDENTIALS;
				return LoginWebPage::LOGIN_FSM_ERROR;
			}

			Session::Set('user_id', $oUser->GetKey());
			if (!empty($oPersonalToken)) {
				Session::Set('personal_token_id', $oPersonalToken->GetKey());
			}
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCredentialsOK(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			$iUserId = Session::Get('user_id');
			$oUser = MetaModel::GetObject('User', $iUserId);

			LoginWebPage::OnLoginSuccess($oUser->Get('login'), 'internal', Session::Get('login_mode'));

			MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');

			$iPersonalTokenId = Session::Get('personal_token_id');
			if (! is_null($iPersonalTokenId)){
				$oPersonalToken = MetaModel::GetObject('PersonalToken', $iPersonalTokenId);
				$iUseCount = $oPersonalToken->Get('use_count') + 1;
				$oPersonalToken->Set('use_count', $iUseCount);
				$oPersonalToken->Set('last_use_date', time());
				$oPersonalToken->DBUpdate();
				CMDBObject::SetCurrentChange(null);
			}

		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnError(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			$this->bErrorOccurred = true;
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnConnected(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			Session::Set('can_logoff', true);

			return LoginWebPage::CheckLoggedUser($iErrorCode);
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	/**
	 * @param $sToken
	 *
	 * @return array
	 */
	public static function GetUser($sToken)
	{
		$aTokenFields = _PersonalToken::DecryptToken($sToken);
		if (!is_array($aTokenFields)) {
			// Not decrypted
			throw new TokenAuthException('invalid_token');
		}

		$sApplication = $aTokenFields[_PersonalToken::APPLICATION_NAME] ?? '';
		if (empty($sApplication)) {
			// Not an access token
			throw new TokenAuthException('invalid_token_application');
		}

		$iUserId = $aTokenFields[_PersonalToken::TOKEN_USER];
		//TODO random field / salt
		$sOQL = <<<OQL
SELECT t,u FROM
PersonalToken AS t
JOIN User AS u
ON t.user_id = u.id
WHERE u.id = $iUserId
AND t.application = "$sApplication"
OQL;
		$oSearch = DBSearch::FromOQL($sOQL);
		/** var \DBObjectSet  $oSet*/
		$oSet = new DBObjectSet($oSearch);

		while ($aObjects = $oSet->FetchAssoc()) {
			if (sizeof($aObjects) === 0){
				continue;
			}
			/** @var PersonalToken $oPersonalToken */
			$oPersonalToken = $aObjects['t'];
			$oUserToken = $oPersonalToken->Get('auth_token');
			if ($oUserToken->CheckPassword($sToken)) {
				$oTokenValidity = $oPersonalToken->Get('expiration_date');
				if (! is_null($oTokenValidity) && time() > $oTokenValidity) {
					// Not valid anymore
					throw new TokenAuthException('invalid_token_validity');
				}

				$sCurrentScope = \Combodo\iTop\Application\Helper\Session::Get("ENDPOINT_CATEGORY");
				if (is_null($sCurrentScope)){
					IssueLog::Error("No scope to current endpoint (no ENDPOINT_CATEGORY in session) ");
					throw new TokenAuthException('no_scope_to_current_endpoint');
				}

				/** @var ormSet $oScope */
				$oScope = $oPersonalToken->Get('scope');
				$aScopeValues = $oScope->GetValues();
				if (! in_array($sCurrentScope, $aScopeValues)){
					IssueLog::Error("Current scope $sCurrentScope does not match current Token allowed scopes: " . implode(",", $aScopeValues));
					throw new TokenAuthException('scope_not_authorized');
				}

				/** @var User $oUser */
				$oUser = $aObjects['u'];
				return [ $oUser, $oPersonalToken ];
			}
		}
		return [];
	}
}
