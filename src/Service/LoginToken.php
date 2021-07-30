<?php

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
		if (!isset($_SESSION['login_mode']) && !$this->bErrorOccurred)
		{
			if (isset($_SERVER['HTTP_AUTH_TOKEN'])) {
				$sAuthToken = $_SERVER['HTTP_AUTH_TOKEN'];
			} else {
				$sAuthToken = utils::ReadParam('auth_token', null, false, 'raw_data');
			}
			if (!empty($sAuthToken))
			{
				$_SESSION['login_mode'] = 'token';
				$_SESSION['login_temp_auth_token'] = $sAuthToken;
			}
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCheckCredentials(&$iErrorCode)
	{
		if ($_SESSION['login_mode'] == 'token')
		{
			$sAuthToken = $_SESSION['login_temp_auth_token'];
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
		if ($_SESSION['login_mode'] == 'token')
		{
			$sAuthToken = $_SESSION['login_temp_auth_token'];
			$oUser = _UserToken::GetUser($sAuthToken);
			LoginWebPage::OnLoginSuccess($oUser->Get('login'), 'internal', $_SESSION['login_mode']);
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnError(&$iErrorCode)
	{
		if ($_SESSION['login_mode'] == 'token')
		{
			$this->bErrorOccurred = true;
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnConnected(&$iErrorCode)
	{
		if ($_SESSION['login_mode'] == 'token')
		{
			$_SESSION['can_logoff'] = true;
			return LoginWebPage::CheckLoggedUser($iErrorCode);
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}
}