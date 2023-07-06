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

// iTop 2.7 compatibility
if (!class_exists('Combodo\iTop\Application\Helper\Session')) {
	require_once __DIR__ . '/../../legacy/Helper/Session.php';
}

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
	// Avoid saving token into the session, keep it in memory
	private static $sAuthToken = '';

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
	public function ListSupportedLoginModes()
	{
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
		if ($this->bErrorOccurred){
			return LoginWebPage::LOGIN_FSM_CONTINUE;
		}

		if (isset($_SERVER['HTTP_AUTH_TOKEN'])) {
			self::$sAuthToken = $_SERVER['HTTP_AUTH_TOKEN'];
		} else {
			self::$sAuthToken = utils::ReadParam('auth_token', null, false, 'raw_data');
		}

		$sSessionLoginMode = Session::Get('login_mode');
		// Note: We don't use \utils::IsNullOrEmptyString() as it is not available in iTop 2.7
		if (strlen(self::$sAuthToken ?? '') === 0)
		{
			if ($this->IsLoginModeSupported($sSessionLoginMode)){
				//login_mode forced and no token. exit to stop login automata
				throw new \Exception("login_mode '$sSessionLoginMode' forced without any token passed");
			}

			//let other login modes try to handle authentication
			return LoginWebPage::LOGIN_FSM_CONTINUE;
		}

		if (is_null($sSessionLoginMode))
		{
			$aAllowedModes = MetaModel::GetConfig()->GetAllowedLoginTypes();
			foreach ($aAllowedModes as $sLoginMode)
			{
				if ($this->IsLoginModeSupported($sLoginMode))
				{
					Session::Start();
					Session::Set('login_mode', $sLoginMode);
					Session::WriteClose();
					return LoginWebPage::LOGIN_FSM_CONTINUE;
				}
			}
		}

		return LoginWebPage::LOGIN_FSM_CONTINUE;
	}

	protected function OnCheckCredentials(&$iErrorCode)
	{
		if ($this->IsLoginModeSupported(Session::Get('login_mode')))
		{
			try{
				$oToken = self::GetToken(self::$sAuthToken);
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
		Session::Unset('login_temp_auth_token');
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
		if ($this->bErrorOccurred) {
			//N°6443 - Loop when allowed profils missconfigured and token mode forced
			TokenAuthLog::Error("Login via token may have been forced and failed. To avoid infinite loop, access is denied immediately.");
			LoginWebPage::HTTP401Error();
		}

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
	 * @return \Combodo\iTop\AuthentToken\Model\iToken
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 * @throws \MySQLException
	 */
	public static function GetToken($sToken) : iToken
	{
		$oService = new AuthentTokenService();

		$oToken = $oService->DecryptToken($sToken);
		if (! is_null($oToken)) {
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Info("GetToken", null, ["sTokenId" => $oToken->GetKey(), "sTokenClass" => get_class($oToken)]);
			}

			$oToken->CheckValidity($sToken);
			return $oToken;
		}

		$oToken = AbstractApplicationToken::GetUserLegacy($sToken);
		if (! is_null($oToken)){
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Info("GetToken (legacy)", null, ["sTokenId" => $oToken->GetKey(), "sTokenClass" => get_class($oToken)]);
			}
			$oToken->CheckValidity($sToken);
			return $oToken;
		}

		// Not decrypted
		throw new TokenAuthException('invalid_token');
	}
}
