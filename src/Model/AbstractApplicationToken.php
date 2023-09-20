<?php

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\iToken;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;

/**
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

abstract class AbstractApplicationToken extends UserInternal implements iToken
{
	private $sToken;
	/**
	 * @var array[AbstractApplicationToken]
	 */
	private static $aCurrentUser = [];

	public static function GetUserLegacy($sToken)
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
			$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, 'INFO', 1);
		}

		return parent::DisplayBareHeader($oPage, $bEditMode);
	}

	public function DisplayDetails(WebPage $oPage, $bEditMode = false)
	{
		//N°6452 - Auto-lock: 2 regenerate buttons
		static $bBlockReentrance = false;

		parent::DisplayDetails($oPage, $bEditMode);
		$oPage->SetCurrentTab('UI:PropertiesTab');

		if ($bBlockReentrance === false) {
			$bBlockReentrance = true;

			if (version_compare(ITOP_DESIGN_LATEST_VERSION, '2.7', '<=')) {
				$sButtonLabel = Dict::S('AuthentToken:RebuildToken');
				$sHtml = <<<HTML
<form method="post">
	<button type="submit" name="rebuild_Token" value="1">{$sButtonLabel}</button>
</form>
HTML;
				$oPage->add($sHtml);
			} else {
				$oForm = FormUIBlockFactory::MakeStandard();
				$oButton = ButtonUIBlockFactory::MakeForDestructiveAction(Dict::S('AuthentToken:RebuildToken'), 'rebuild_Token', 1, true);
				$oButton->SetTooltip(Dict::S('AuthentToken:RebuildToken+'));
				$oForm->AddSubBlock($oButton);
				$oPage->AddSubBlock($oForm);
			}
		}
	}

	public function AfterInsert()
	{
		$this->CreateNewToken();
		$this->DBWrite();

		$sMessage = Dict::Format('AuthentToken:CopyToken', $this->sToken);
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

	private function CreateNewToken() : void
	{
		$oService = new AuthentTokenService();
		$this->sToken = $oService->CreateNewToken($this);
		$oPassword = $oService->CreatePassword($this->sToken);
		$this->Set('auth_token', $oPassword);
	}

	public function GetUser() : \User
	{
		if (MetaModel::GetConfig()->Get('login_debug')){
			TokenAuthLog::Info("GetUser", null,
				[
					'class' => get_class($this),
					'user_id' => $this->GetKey(),
					'login' => $this->Get('login'),
				]
			);
		}

		return $this;
	}

	public function CheckValidity(string $sToken): void
	{
	}

	public function UpdateUsage(): void
	{
	}

	public function CheckScopes(): void
	{
	}
}
