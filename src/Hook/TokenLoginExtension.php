<?php

namespace Combodo\iTop\AuthentToken\Hook;
use AbstractApplicationToken;
use AbstractLoginFSMExtension;
use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\iToken;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use LoginWebPage;
use MetaModel;
use utils;


/**
 * Class TokenLoginExtension
 *
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TokenLoginExtension extends AbstractLoginFSMExtension
{
	const LOGIN_TYPE = 'token';
	const LEGACY_LOGIN_TYPE = 'rest-token';
	const SUPPORTED_LOGIN_MODES = [ self::LOGIN_TYPE , self::LEGACY_LOGIN_TYPE ];

	public function __construct()
	{
		TokenAuthLog::Enable(APPROOT.'log/error.log');
	}

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
		return [self::LOGIN_TYPE];
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
			try{
				$oToken = self::GetToken($sAuthToken);
			}
			catch(\Exception $e)
			{
				TokenAuthLog::Error("OnCheckCredentials: " . $e->getMessage());
				$iErrorCode = LoginWebPage::EXIT_CODE_WRONGCREDENTIALS;
				return LoginWebPage::LOGIN_FSM_ERROR;
			}

			Session::Set('token_id', $oToken->GetKey());
			Session::Set('token_class', get_class($oToken));
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCredentialsOK(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			/** @var iToken $oToken */
			$sTokenId = Session::Get('token_id');
			$sTokenClass = Session::Get('token_class');
			$oToken = MetaModel::GetObject($sTokenClass, $sTokenId);
			$oUser = $oToken->GetUser();

			LoginWebPage::OnLoginSuccess($oUser->Get('login'), 'internal', Session::Get('login_mode'));
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

			/** @var iToken $oToken */
			$sTokenId = Session::Get('token_id');
			$sTokenClass = Session::Get('token_class');
			$oToken = MetaModel::GetObject($sTokenClass, $sTokenId);
			try{
				$oToken->CheckScopes();
			}
			catch(\Exception $e)
			{
				TokenAuthLog::Error("OnConnected: " . $e->getMessage());
				$iErrorCode = LoginWebPage::EXIT_CODE_WRONGCREDENTIALS;
				return LoginWebPage::LOGIN_FSM_ERROR;
			}

			$oToken->UpdateUsage();

			return LoginWebPage::CheckLoggedUser($iErrorCode);
		}
		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	/**
	 * @param $sToken
	 *
	 * @return array
	 */
	public static function GetToken($sToken) : iToken
	{
		$oService = new AuthentTokenService();
		$aTokenFields = $oService->DecryptToken($sToken);
		if (!is_array($aTokenFields)) {
			$oToken = AbstractApplicationToken::GetUserLegacy($sToken);
			if (! is_null($oToken)){
				return $oToken;
			}

			// Not decrypted
			throw new TokenAuthException('invalid_token');
		}

		$oToken = $oService->GetToken($aTokenFields);

		$oToken->CheckValidity($sToken);
		return $oToken;
	}
}
