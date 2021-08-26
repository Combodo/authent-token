<?php

use Combodo\iTop\Application\Helper\Session;

/**
 * Class LoginToken
 *
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class LoginToken extends AbstractLoginFSMExtension
{
	/**
	 * @var bool
	 */
	private $bErrorOccurred = false;

	/**
	 * Return the list of supported login modes for this plugin
	 *
	 * @return array of supported login modes
	 */
	public function ListSupportedLoginModes()
	{
		return array('token');
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
				Session::Set('login_mode', 'token');
				Session::Set('login_temp_auth_token', $sAuthToken);
				Session::WriteClose();
			}
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCheckCredentials(&$iErrorCode)
	{
		if (Session::Get('login_mode') == 'token')
		{
			$sAuthToken = Session::Get('login_temp_auth_token');
			if (!_UserToken::CheckToken($sAuthToken))
			{
				$iErrorCode = LoginWebPage::EXIT_CODE_WRONGCREDENTIALS;
				return LoginWebPage::LOGIN_FSM_ERROR;
			}
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCredentialsOK(&$iErrorCode)
	{
		if (Session::Get('login_mode') == 'token')
		{
			$sAuthToken = Session::Get('login_temp_auth_token');
			$oUser = _UserToken::GetUser($sAuthToken);
			LoginWebPage::OnLoginSuccess($oUser->Get('login'), 'internal', Session::Get('login_mode'));
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnError(&$iErrorCode)
	{
		if (Session::Get('login_mode') == 'token')
		{
			$this->bErrorOccurred = true;
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnConnected(&$iErrorCode)
	{
		if (Session::Get('login_mode') == 'token')
		{
			Session::Set('can_logoff', true);
			return LoginWebPage::CheckLoggedUser($iErrorCode);
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}
}