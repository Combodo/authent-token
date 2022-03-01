<?php

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;

/**
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


class _UserToken extends UserInternal
{
	private $sToken;
	/**
	 * @var array[_UserToken]
	 */
	private static $aCurrentUser = [];

	public static function CheckToken($sToken): bool
	{
		$oUser = self::GetUser($sToken);
		return (!is_null($oUser));
	}

	public static function GetUser($sToken)
	{
		if (array_key_exists($sToken, self::$aCurrentUser)) {
			return self::$aCurrentUser[$sToken];
		}

		$oSet = new DBObjectSet(DBSearch::FromOQL("SELECT `UserToken`"));
		while ($oUser = $oSet->Fetch()) {
			$oUserToken = $oUser->Get('auth_token');
			if ($oUserToken->CheckPassword($sToken)) {
				self::$aCurrentUser[$sToken] = $oUser;
				return $oUser;
			}
		}
		return null;
	}

	public function CheckCredentials($sPassword)
	{
		return false;
	}

	public function CanChangePassword()
	{
		return false;
	}

	public function ChangePassword($sOldPassword, $sNewPassword)
	{
		return false;
	}

	public function DisplayBareHeader(WebPage $oPage, $bEditMode = false)
	{
		$bRebuildToken = utils::ReadParam('rebuild_Token', 0);
		if ($bRebuildToken) {
			$this->CreateNewToken();
			$this->DBUpdate();
			$sMessage = Dict::Format('AuthentToken:CopyToken', $this->sToken);
			$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, WebPage::ENUM_SESSION_MESSAGE_SEVERITY_INFO, 1);
		}

		return parent::DisplayBareHeader($oPage, $bEditMode);
	}

	public function DisplayDetails(WebPage $oPage, $bEditMode = false)
	{
		parent::DisplayDetails($oPage, $bEditMode);
		$oPage->SetCurrentTab('UI:PropertiesTab');
		$oForm = FormUIBlockFactory::MakeStandard();
		$oButton = ButtonUIBlockFactory::MakeForDestructiveAction(Dict::S('AuthentToken:RebuildToken'), 'rebuild_Token', 1, true);
		$oButton->SetTooltip(Dict::S('AuthentToken:RebuildToken+'));
		$oForm->AddSubBlock($oButton);
		$oPage->AddSubBlock($oForm);
	}


	public function ComputeValues()
	{
		if ($this->IsNew()) {
			$this->CreateNewToken();
		}
		parent::ComputeValues();
	}

	public function AfterInsert()
	{
		$sMessage = Dict::Format('AuthentToken:CopyToken', $this->sToken);
		$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, WebPage::ENUM_SESSION_MESSAGE_SEVERITY_INFO, 1);
		parent::AfterInsert();
	}

	public function GetInitialStateAttributeFlags($sAttCode, &$aReasons = array())
	{
		if ($sAttCode == 'auth_token') {
			return OPT_ATT_HIDDEN;
		}
		return parent::GetInitialStateAttributeFlags($sAttCode, $aReasons);
	}

	public function GetAttributeFlags($sAttCode, &$aReasons = array(), $sTargetState = '')
	{
		if ($sAttCode == 'auth_token') {
			return OPT_ATT_HIDDEN;
		}
		return parent::GetAttributeFlags($sAttCode, $aReasons, $sTargetState);
	}

	public function TrustWebServerContext()
	{
		return false;
	}

	public function GetAsHTML($sAttCode, $bLocalize = true)
	{
		if ($sAttCode == 'auth_token') {
			return '****';
		}
		return parent::GetAsHTML($sAttCode, $bLocalize);
	}

	private function CreateNewToken(): void {
		// Generate a new token
		$rawToken = random_bytes(32);
		$this->sToken = bin2hex($rawToken);
		$oPassword = new ormPassword();
		$oPassword->SetPassword($this->sToken);
		$this->Set('auth_token', $oPassword);
	}
}