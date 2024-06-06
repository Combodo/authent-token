<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Application\UI\Base\Component\Button\Button;
use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTable\FormTable;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTableRow\FormTableRow;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\Toolbar;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\ToolbarUIBlockFactory;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\Renderer\BlockRenderer;
use DBObjectSearch;
use DBObjectSet;
use Dict;
use MetaModel;
use User;
use UserRights;
use utils;

class PersonalTokenService
{
	private static PersonalTokenService $oInstance;

	private function __construct()
	{
	}

	final public static function GetInstance(): PersonalTokenService
	{
		if (!isset(static::$oInstance)) {
			static::$oInstance = new PersonalTokenService();
		}

		return static::$oInstance;
	}

	public function IsPersonalTokenManagementAllowed(User $oUser) : bool
	{
		if (is_null($oUser)){
			return false;
		}

		if (UserRights::IsAdministrator($oUser)){
			return true;
		}

		foreach ($this->GetAuthorizedProfiles() as $sProfile) {
			if (UserRights::HasProfile($sProfile, $oUser)) {
				return true;
			}
		}

		return false;
	}

	public function GetAuthorizedProfiles() : array
	{
		$aProfiles = utils::GetConfig()->GetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		if (is_array($aProfiles)) {
			return $aProfiles;
		}

		$sType = gettype($aProfiles);
		TokenAuthLog::Error("Itop configuration parameter 'personal_tokens_allowed_profiles' should be an array instead of $sType");
		return [];
	}

	public function ProvideHtmlTokenInfo(): array
	{
		$oUser = UserRights::GetUserObject();
		$aColumns = [];
		foreach ($this->GetFields() as $sField) {
			$aColumns[] = ['label' => MetaModel::GetLabel(\PersonalToken::class, $sField)];
		}

		$oFilter = DBObjectSearch::FromOQL('SELECT PersonalToken WHERE user_id = :id', ['id' => $oUser->GetKey()]);
		$oSet = new DBObjectSet($oFilter);

		$aToken = [];
		if ($oSet->Count() > 0) {
			while ($oToken = $oSet->Fetch()) {
				$aToken[] = $oToken;
			}
		}

		$aRefreshedTokenInfo = Session::Get('AuthentToken:CopyToken', null);
		if ($aRefreshedTokenInfo) {
			$sTokenValue = $aRefreshedTokenInfo['credential_message'];
			$sTokenName = $aRefreshedTokenInfo['token_name'];
			//reset token value in the session for next display
			Session::Unset('AuthentToken:CopyToken');
		} else {
			$sTokenValue = null;
			$sTokenName = '';
		}

		$oDatatableBlock = $this->BuildDatatable('tokens', $aColumns, $aToken);
		return [
			'title' => Dict::S('MyAccount:SubTitle:PersonalTokens'),
			'token_name' => $sTokenName,
			'token_value' => $sTokenValue,
			'oDatatable' => $oDatatableBlock,
			'refresh_token_url' => utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'ajax.php', ['operation' => 'RefreshToken', 'rebuild_Token' => 1]),

			//link to get data before displaying apply_modify form
			'edit_token_url' => utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'ajax.php', ['operation' => 'EditToken']),

			'delete_token_url' => utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'ajax.php', ['operation' => 'DeleteToken']),

			//link used after validating either create or modify popup form: it will reach either Operationapply_new or Operationapply_modify endpoint
			'save_token_link' => utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'ajax.php', []),
		];
	}

	/**
	 * Generate Datapanel with CRUD action button on each row.
	 * this could be replaced by iTop 3.1 build-it twig code. For SaaS it has to work in 3.0
	 *
	 * @param string $sRef
	 * @param array $aColumns
	 * @param array $aData
	 * @param string $sFilter
	 * @param array $aRowActions
	 * @param array $aTokenIds
	 *
	 * @return \Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTable\FormTable
	 * @throws \ReflectionException
	 * @throws \Twig\Error\LoaderError
	 * @throws \Twig\Error\RuntimeError
	 * @throws \Twig\Error\SyntaxError
	 */
	private function BuildDatatable(string $sTableRef, array $aColumns, array $aToken): FormTable
	{
		$oTable = new FormTable('datatable_'.$sTableRef);
		$oTable->SetRef($sTableRef);
		$aColumns[] = [
			'label' => Dict::S('UI:Datatables:Column:RowActions:Label'),
			'description' => Dict::S('UI:Datatables:Column:RowActions:Description'),
		];
		$oTable->SetColumns($aColumns);
		$oTable->SetFilter('');

		foreach ($aToken as $oToken) {
			$oRow = $this->BuildFormTableRow($oToken, $sTableRef, $aColumns);
			$oTable->AddRow($oRow);
		}

		return $oTable;
	}

	private function BuildFormTableRow($oToken, string $sTableRef, array $aColumns): FormTableRow
	{
		$aFields = $this->GetFields();
		$aTokenRowData = [];
		foreach ($aFields as $sField) {
			$aTokenRowData[] = $oToken->GetAsHTML($sField);
		}

		$oToolbar = self::MakeActionRowToolbarTemplate($sTableRef);

		$oBlockRenderer = new BlockRenderer($oToolbar);

		// Double escape 'application' to prevent from XSS, there's also HTML markup in AuthentToken:Message:DeleteTokenConfirmation dict entry that needs to be escaped.
		$sDeletionLabel = utils::HtmlEntities(Dict::Format('AuthentToken:Message:DeleteTokenConfirmation', utils::HtmlEntities($oToken->Get('application'))));
		$sTokenId = $oToken->GetKey();
		$sRowHtml = str_replace('data-role="ibo-button"',
			sprintf('data-role="ibo-button" data-token-id="%s" data-deletion-label="%s"', $sTokenId, $sDeletionLabel),
			$oBlockRenderer->RenderHtml()
		);
		//add toolbar html code as last row field
		$aTokenRowData[] = $sRowHtml;

		return new FormTableRow($sTableRef, $aColumns, $aTokenRowData, $sTokenId);
	}

	private static function MakeActionRowToolbarTemplate(string $sTableId): Toolbar
	{
		$aRowActions = [
			[
				'tooltip' => 'UI:Links:ActionRow:EditToken',
				'icon_classes' => 'fas fa-pen',
				'action-class' => 'token-edit-button',
			],
			[
				'tooltip' => 'AuthentToken:RebuildToken+',
				'icon_classes' => 'fas fa-sync-alt',
				'action-class' => 'token-refresh-button',
			],
			[
				'tooltip' => 'UI:Links:ActionRow:DeleteToken',
				'icon_classes' => 'fas fa-trash',
				'action-class' => 'token-delete-button',
				'color' => Button::ENUM_COLOR_SCHEME_DESTRUCTIVE,
			]
		];

		// row actions toolbar container
		$oToolbar = ToolbarUIBlockFactory::MakeStandard();
		$oToolbar->AddCSSClass('ibo-datatable--row-actions-toolbar');

		// for each action...create an icon button
		foreach ($aRowActions as $iKey => $aAction) {
			$oButton = ButtonUIBlockFactory::MakeAlternativeNeutral('', $aAction['tooltip']);
			$oButton->SetIconClass($aAction['icon_classes'])
				->SetTooltip(Dict::S($aAction['tooltip']))
				->AddCSSClasses([$aAction['action-class'], 'ibo-action-button', 'ibo-regular-action-button']);

			if (array_key_exists('color', $aAction)) {
				$oButton->SetColor($aAction['color']);
			}

			$oButton->SetDataAttributes(['label' => Dict::S($aAction['tooltip']), 'action-id' => $iKey, 'table-id' => $sTableId]);
			$oToolbar->AddSubBlock($oButton);
		}

		return $oToolbar;
	}

	private function GetFields()
	{
		return ['application', 'scope', 'expiration_date', 'use_count', 'last_use_date'];
	}

}