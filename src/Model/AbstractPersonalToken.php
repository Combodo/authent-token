<?php

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Model\iToken;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;

/**
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

abstract class AbstractPersonalToken extends cmdbAbstractObject  implements iToken
{
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

	private function CreateNewToken(): void
	{
		$oService = new AuthentTokenService();
		$this->sToken = $oService->CreateNewToken($this);
		$oPassword = $oService->CreatePassword($this->sToken);
		$this->Set('auth_token', $oPassword);
	}

	public function AfterInsert()
	{
		$this->CreateNewToken();
		$this->DBWrite();

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

	public function GetUser() : \User
	{
		return MetaModel::GetObject(\User::class, $this->Get('user_id'));
	}

	public function CheckValidity(string $sToken): void
	{
		$oPassword = $this->Get('auth_token');
		if (! $oPassword->CheckPassword($sToken)) {
			throw new TokenAuthException('Invalid token');
		}

		$oTokenValidity = $this->Get('expiration_date');
		if (! is_null($oTokenValidity) && time() > $oTokenValidity) {
			// Not valid anymore
			throw new TokenAuthException('Invalid token validity');
		}

		$this->CheckScopes();
	}


	/**
	 * @return mixed
	 * @throws \ArchivedObjectException
	 * @throws \Combodo\iTop\AuthentToken\Exception\TokenAuthException
	 * @throws \CoreException
	 */
	public function CheckScopes(): void
	{
		/** @var ormSet $oScope */
		$oScope = $this->Get('scope');
		$aScopeValues = $oScope->GetValues();
		foreach ($aScopeValues as $sScope) {
			if (\ContextTag::Check($sScope)) {
				return;
			}
		}

		TokenAuthLog::Error(sprintf(
				"Current context (%s) does not match current Token allowed scopes: %s",
				implode(',', \ContextTag::GetStack()),
				implode(",", $aScopeValues)
			)
		);

		throw new TokenAuthException('Scope not authorized');
	}


	public function UpdateUsage(): void
	{
		$iUseCount = $this->Get('use_count') + 1;
		$this->Set('use_count', $iUseCount);
		$this->Set('last_use_date', time());
		$this->DBUpdate();
		CMDBObject::SetCurrentChange(null);

		if (MetaModel::GetConfig()->Get('allow_rest_services_via_tokens')
			&& \ContextTag::Check(\ContextTag::TAG_REST)){
			//let user do rest calls even without rest profiles
			MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
		}
	}

}
