<?php

/**
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


class _UserToken extends UserInternal
{
	private $sToken;

	public static function CheckToken($sToken): bool
	{
		$oSet = self::GetObjectSetFromToken($sToken);
		return ($oSet->Count() == 1);
	}

	public static function GetUser($sToken)
	{
		$oSet = self::GetObjectSetFromToken($sToken);
		return $oSet->Fetch();
	}

	private static function GetObjectSetFromToken($sToken)
	{
		$rawToken = hex2bin($sToken);
		$sHash = hash('sha256', $rawToken);
		$oFilter = DBSearch::FromOQL("SELECT `UserToken` WHERE `UserToken`.`auth_token` LIKE :hash");
		return new DBObjectSet($oFilter, [], ['hash' => $sHash]);
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

	public function DisplayBareHeader(WebPage $oPage, $bEditMode = false, $sMode = self::ENUM_OBJECT_MODE_VIEW)
	{
		return parent::DisplayBareHeader($oPage, $bEditMode, $sMode);
	}

	public function ComputeValues()
	{
		if ($this->IsNew()) {
			// Generate a new token
			$rawToken = random_bytes(32);
			$this->sToken = bin2hex($rawToken);
			$this->Set('auth_token', hash('sha256', $rawToken));
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
}