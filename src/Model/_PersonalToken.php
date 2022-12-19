<?php

namespace Combodo\iTop\Extension\Model;

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;
use cmdbAbstractObject;
use WebPage;
use ormPassword;
use Dict;
use utils;
use DBProperty;
use DBObjectSet;
use DBObjectSearch;
use SimpleCrypt;

/**
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


class _PersonalToken extends cmdbAbstractObject
{
	const APPLICATION_NAME     = 'a';
	const TOKEN_USER     = 'u';
	const PRIVATE_KEY    = 'authent-multi-token-priv-key';

	protected $sToken;

	private function InitPrivateKey()
	{
		return $this->GetPrivateKey();
	}

	public function DisplayBareHeader(WebPage $oPage, $bEditMode = false)
	{
		$bRebuildToken = utils::ReadParam('rebuild_Token', 0);
		if ($bRebuildToken) {
			$this->CreateNewToken();
			$this->DBUpdate();
			$sMessage = Dict::Format('PersonalToken:CopyToken', $this->sToken);
			$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, 'INFO', 1);
		}

		return parent::DisplayBareHeader($oPage, $bEditMode);
	}

	public function DisplayDetails(WebPage $oPage, $bEditMode = false)
	{
		parent::DisplayDetails($oPage, $bEditMode);
		$oPage->SetCurrentTab('UI:PropertiesTab');

		if (version_compare(ITOP_DESIGN_LATEST_VERSION, '2.7', '<=')) {
			$sButtonLabel = Dict::S('PersonalToken:RebuildToken');
			$sHtml = <<<HTML
<form method="post">
	<button type="submit" name="rebuild_Token" value="1">{$sButtonLabel}</button>
</form>
HTML;
			$oPage->add($sHtml);
		} else {
			$oForm = FormUIBlockFactory::MakeStandard();
			$oButton = ButtonUIBlockFactory::MakeForDestructiveAction(Dict::S('PersonalToken:RebuildToken'), 'rebuild_Token', 1, true);
			$oButton->SetTooltip(Dict::S('AuthentToken:RebuildToken+'));
			$oForm->AddSubBlock($oButton);
			$oPage->AddSubBlock($oForm);
		}
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
		$sMessage = Dict::Format('PersonalToken:CopyToken', $this->sToken);
		$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, 'INFO', 1);
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

	public function GetAsHTML($sAttCode, $bLocalize = true)
	{
		if ($sAttCode == 'auth_token') {
			return '****';
		}
		return parent::GetAsHTML($sAttCode, $bLocalize);
	}

	/**
	 * @param $sToken
	 *
	 * @return array|mixed
	 * @throws \CoreException
	 * @throws \MySQLException
	 */
	public static function DecryptToken($sToken)
	{
		$sPrivateKey = self::GetPrivateKey();
		$oCrypt = new SimpleCrypt();

		return json_decode($oCrypt->Decrypt($sPrivateKey, hex2bin($sToken)), true);
	}


	private function CreateNewToken(): void {
		$aToken = [
			self::APPLICATION_NAME     => $this->Get('application'),
			self::TOKEN_USER     => $this->Get('user_id'),
		];
		$sPPrivateKey = self::GetPrivateKey();
		$oCrypt = new SimpleCrypt();
		$this->sToken = bin2hex($oCrypt->Encrypt($sPPrivateKey, json_encode($aToken)));

		$oPassword = new ormPassword();
		$oPassword->SetPassword($this->sToken);
		$this->Set('auth_token', $oPassword);
	}

	/**
	 * @return string
	 * @throws \CoreException
	 * @throws \CoreUnexpectedValue
	 * @throws \MySQLException
	 */
	private static function GetPrivateKey()
	{
		$sPrivateKey = DBProperty::GetProperty(self::PRIVATE_KEY);
		if (is_null($sPrivateKey)) {
			$sPrivateKey = bin2hex(random_bytes(32));
			DBProperty::SetProperty(self::PRIVATE_KEY, $sPrivateKey);

			// Invalidate all the existing refresh tokens
			/*$oSet = new DBObjectSet(new DBObjectSearch('PersonalToken'));
			while ($oPersonalToken = $oSet->Fetch()) {
				self::EraseTokens($oPersonalToken);
			}*/
		}

		return $sPrivateKey;
	}

	/*public static function EraseTokens($oPersonalToken)
	{
		$oPersonalToken->Set('expiration_date', time() - 1);
		$oPersonalToken->AllowWrite();
		$oPersonalToken->DBUpdate();
	}*/
}
