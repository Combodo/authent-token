<?php

use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Form\FormUIBlockFactory;
use Combodo\iTop\AuthentToken\Controller\MyAccountController;
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
	protected $bCanEditUserId = true;
	private $aContext;

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
			$sMessage = Dict::Format('AuthentToken:CopyToken', $this->sToken);
			$this::SetSessionMessage(get_class($this), $this->GetKey(), 1, $sMessage, 'INFO', 1);
		}

		return parent::DisplayBareHeader($oPage, $bEditMode);
	}

	public function SetCanEditUserId(bool $bCanEdit) : void {
		$this->bCanEditUserId = $bCanEdit;
	}

	public function GetCanEditUserId() : bool {
		return $this->bCanEditUserId;
	}

	/**
	 * @return string : get token value only when refreshing its value
	 */
	public function GetToken() : ?string {
		return $this->sToken;
	}

	public function DisplayDetails(WebPage $oPage, $bEditMode = false)
	{
		//N°6452 - Auto-lock: 2 regenerate buttons
		static $bBlockReentrance = false;
		parent::DisplayDetails($oPage, $bEditMode);

		if ($bBlockReentrance === false) {
			$bBlockReentrance = true;
			$oPage->SetCurrentTab('UI:PropertiesTab');

			if (version_compare(ITOP_DESIGN_LATEST_VERSION, '2.7', '<=')) {
				$sButtonLabel = Dict::S('AuthentToken:RebuildToken');
				$sButtonTooltipLabel = Dict::S('AuthentToken:RebuildToken+');
				$sHtml = <<<HTML
<form method="post">
	<button type="submit" name="rebuild_Token" value="1" title="{$sButtonTooltipLabel}">{$sButtonLabel}</button>
</form>
HTML;
				$oPage->add($sHtml);
			} else {
				$oForm = FormUIBlockFactory::MakeStandard();
				$oButton = ButtonUIBlockFactory::MakeForPositiveAction(Dict::S('AuthentToken:RebuildToken'), 'rebuild_Token', 1, true);
				$oButton->SetTooltip(Dict::S('AuthentToken:RebuildToken+'));
				$oForm->AddSubBlock($oButton);
				$oPage->AddSubBlock($oForm);
			}
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
		if (in_array($sAttCode, [ 'auth_token', 'use_count', 'last_use_date' ])) {
			return OPT_ATT_HIDDEN;
		} else if ($sAttCode == 'user_id' && !$this->GetCanEditUserId()) {
			return OPT_ATT_READONLY;
		}
		return parent::GetInitialStateAttributeFlags($sAttCode, $aReasons);
	}

	public function GetAttributeFlags($sAttCode, &$aReasons = array(), $sTargetState = '')
	{
		if (in_array($sAttCode, [ 'auth_token', 'use_count', 'last_use_date' ])) {
			return OPT_ATT_HIDDEN;
		} else if ($sAttCode == 'user_id' && !$this->GetCanEditUserId()) {
			return OPT_ATT_READONLY;
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
		$oUser = MetaModel::GetObject(\User::class, $this->Get('user_id'));
		$this->aContext = [
			'token' => get_class($this),
			'token_id' => $this->GetKey($oUser),
			'class' => get_class($oUser),
			'user_id' => $oUser->GetKey(),
			'login' => $oUser->Get('login'),
		];

		if (MetaModel::GetConfig()->Get('login_debug')) {
			TokenAuthLog::Info("GetUser", null,
				$this->aContext
			);
		}

		return $oUser;
	}

	private function GetContextParams() : array {
		if (is_null($this->aContext)){
			$this->aContext = [
				'token' => get_class($this),
				'token_id' => $this->GetKey(),
			];
		}

		return $this->aContext;
	}

	public function CheckValidity(string $sToken): void
	{
		$oUser = $this->GetUser();
		if (! MyAccountController::IsPersonalTokenManagementAllowed($oUser)){
			if (MetaModel::GetConfig()->Get('login_debug')) {
				$aProfiles = MyAccountController::GetAuthorizedProfiles();
				$sMessage = sprintf('Current user has not the Personal Token allowed profiles (%s).', implode(',', $aProfiles));
				TokenAuthLog::Info($sMessage, null, $this->GetContextParams());
			}
			throw new TokenAuthException("No personal token allowed profile");
		}

		$oPassword = $this->Get('auth_token');
		if (! $oPassword->CheckPassword($sToken)) {
			if (MetaModel::GetConfig()->Get('login_debug')) {
				TokenAuthLog::Info("Invalid token", null, $this->GetContextParams());
			}
			throw new TokenAuthException('Invalid token');
		}

		$sTokenValidity = $this->Get('expiration_date');
		if (! is_null($sTokenValidity)) {
			$oNowDateTime = new DateTime();
			$iNowUnixSeconds = $oNowDateTime->format('U');


			$oDateTimeFormat = new \DateTimeFormat('Y-m-d H:i:s');
			$oLastUseDateTime = $oDateTimeFormat->Parse($sTokenValidity);
			$iExpirationUnixSeconds = $oLastUseDateTime->format('U');

			if ($iNowUnixSeconds > $iExpirationUnixSeconds) {
				// Not valid anymore
				if (MetaModel::GetConfig()->Get('login_debug')) {
					TokenAuthLog::Info("Invalid token validity", null, $this->GetContextParams());
				}
				throw new TokenAuthException('Invalid token validity');
			}
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

		if (MetaModel::GetConfig()->Get('login_debug')){
			TokenAuthLog::Info(sprintf(
				"Current context (%s) does not match current Token allowed scopes: %s",
				implode(',', \ContextTag::GetStack()),
				implode(",", $aScopeValues)
			),
				null,
				$this->GetContextParams()
			);
		}

		throw new TokenAuthException('Scope not authorized');
	}


	public function UpdateUsage(): void
	{
		$iUseCount = $this->Get('use_count') + 1;
		$this->Set('use_count', $iUseCount);

		$sDateTime = date('Y-m-d H:i:s', time());
		$this->Set('last_use_date', $sDateTime);
		$this->AllowWrite();
		$this->DBUpdate();
		CMDBObject::SetCurrentChange(null);

		if (MetaModel::GetConfig()->Get('allow_rest_services_via_tokens')
			&&
			(ContextTag::Check(ContextTag::TAG_REST) || ContextTag::Check(ContextTag::TAG_SYNCHRO)))
		{
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Info("Rest profiles can be bypassed with 'allow_rest_services_via_tokens' enabled ('secure_rest_services' disabled once).",
					null,
					$this->GetContextParams()
				);
			}

			//let user do rest calls even without rest profiles
			MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
		}
	}

}
