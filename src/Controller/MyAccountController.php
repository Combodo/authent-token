<?php

namespace Combodo\iTop\AuthentToken\Controller;

use AjaxPage;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\Application\UI\Base\Component\Button\Button;
use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTable\FormTable;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTableRow\FormTableRow;
use Combodo\iTop\Application\UI\Base\Component\DataTable\tTableRowActions;
use Combodo\iTop\Application\UI\Base\Component\Input\InputUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Template\TemplateUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Panel\PanelUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Field\FieldUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\ToolbarUIBlockFactory;
use Combodo\iTop\Application\UI\Base\iUIBlock;
use Combodo\iTop\Application\UI\Base\Layout\TabContainer\TabContainer;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\Form\Field\DateTimeField;
use Combodo\iTop\Form\Field\SelectField;
use Combodo\iTop\Form\Field\StringField;
use Combodo\iTop\Renderer\BlockRenderer;
use Combodo\iTop\Renderer\Console\FieldRenderer\ConsoleSimpleFieldRenderer;
use DBObject;
use DBObjectSearch;
use DBObjectSet;
use Dict;
use IssueLog;
use MetaModel;
use UserRights;
use utils;

class MyAccountController extends Controller{
	const EXTENSION_NAME = "authent-token";

	public function OperationMainPage()
	{
		$aParams = [];
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		if (! self::IsMenuAllowed($oUser)){
			//in case someone not allowed try to type full URL...
			http_response_code(401);
			die("User not allowed to access current ressource.");
		}

		$this->ProvideHtmlUserInfo($oUser, $aParams);
		$this->ProvideHtmlContactInfo($oUser, $aParams);

		if (self::IsPersonalTokenManagementAllowed($oUser)){
			$this->ProvideHtmlTokenInfo($oUser, $aParams);
		}

		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/json.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/forms-json-utils.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/wizardhelper.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/wizard.utils.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/linkswidget.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/linksdirectwidget.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/extkeywidget.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/jquery.blockUI.js');

		foreach (TabContainer::DEFAULT_JS_FILES_REL_PATH as $sJsFile){
			$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().$sJsFile);
		}


		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/ui-block.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/components/panel.js');

		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/layouts/tab-container/tab-container.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/layouts/tab-container/regular-tabs.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/layouts/tab-container/scrollable-tabs.js');
		$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().'js/layouts/object/object-details.js');

		$this->DisplayPage(['Params' => $aParams ], 'main');
	}

	public function OperationRefreshToken()
	{
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		if (! self::IsPersonalTokenManagementAllowed($oUser)){
			//in case someone not allowed try to type full URL...
			http_response_code(401);
			die("User not allowed to access current ressource.");
		}

		$sTokenId = utils::ReadParam('token_id', null);

		if ($sTokenId===null){
			IssueLog::error("Cannot refresh token without its id");
			$this->DisplayJSONPage(['result' => 'error'], 200);
			return;
		}

		try {
			$oToken = $this->FetchToken($oUser, $sTokenId);

			$oToken->AllowWrite();
			$oPage = new AjaxPage("");
			$oToken->DisplayBareHeader($oPage, true);

			$sMessage = Dict::Format('AuthentToken:CopyToken', $oToken->getToken());
			$this->DisplayJSONPage(['result' => 'ok', 'message' => $sMessage], 200);
		} catch (\Exception $e){
			IssueLog::error("Cannot refresh token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	public function OperationDeleteToken()
	{
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		if (! self::IsPersonalTokenManagementAllowed($oUser)){
			//in case someone not allowed try to type full URL...
			http_response_code(401);
			die("User not allowed to access current ressource.");
		}

		$sTokenId = utils::ReadParam('token_id', null);

		if ($sTokenId===null){
			IssueLog::error("Cannot delete token without its id");
			$this->DisplayJSONPage(['result' => 'error'], 200);
			return;
		}

		try {
			$oToken = $this->FetchToken($oUser, $sTokenId);

			$oToken->AllowDelete();
			$oToken->DBDelete();

			$this->DisplayJSONPage(['result' => 'ok'], 200);
		} catch (\Exception $e){
			IssueLog::error("Cannot delete token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	public function OperationEditToken()
	{
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		if (! self::IsPersonalTokenManagementAllowed($oUser)){
			//in case someone not allowed try to type full URL...
			http_response_code(401);
			die("User not allowed to access current ressource.");
		}

		$sTokenId = utils::ReadParam('token_id', null);

		if ($sTokenId===null){
			IssueLog::error("Missing token_id for token edition");
			$this->DisplayJSONPage(['result' => 'error'], 200);
			return;
		}

		try {
			if ($sTokenId==="0"){
				$oToken = new \PersonalToken();
				$oToken->Set('user_id', $oUser->GetKey());
			} else {
				$oToken = $this->FetchToken($oUser, $sTokenId);
			}

			$oPage = new AjaxPage('');
			$oToken->DisplayModifyForm($oPage);
			$oPage->output();
		} catch (\Exception $e){
			IssueLog::error("Cannot edit token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	private function FetchToken(\User $oUser, string $sTokenId) : ?\DbObject
	{
		$oSearch = new DBObjectSearch(\PersonalToken::class);
		//keep this or nobody else than admin will be able to perform this action
		$oSearch->AllowAllData();

		$oSearch->Addcondition('id', $sTokenId, '=');
		$sUserId = $oUser->GetKey();
		$oSearch->Addcondition('user_id', $sUserId, '=');
		$oTokens = new DBObjectSet($oSearch);
		$oToken = $oTokens->Fetch();
		if (null === $oToken){
			IssueLog::error(sprintf('Cannot find token with id %s and user_id %s', $sTokenId, ));
			throw new \Exception('Cannot find token');
		}
		return $oToken;
	}

	private function GetEditLink(DBObject $oObject) : string
	{
		return sprintf("%spages/UI.php?operation=modify&class=%s&id=%s",
			utils::GetAbsoluteUrlAppRoot(), get_class($oObject), $oObject->GetKey());
	}

	public function ProvideHtmlUserInfo(\User $oUser, &$aParams): void{
		if (is_null($oUser)){
			return;
		}

		$aParams['user_link']= $this->GetEditLink($oUser);

		$oProfileSet = $oUser->Get('profile_list');
		$aProfiles = [];
		while (($oProfile = $oProfileSet->Fetch()) != null){
			$aProfiles[]= $oProfile->GetAsHTML('profile');
		}
		$sProfileListHtml = implode('<BR>', $aProfiles);

		$oAllowedOrgList = $oUser->Get('allowed_org_list');
		$aAllowedOrgs = [];
		while (($oUserOrg = $oAllowedOrgList->Fetch()) != null){
			$aAllowedOrgs[]= $oUserOrg->GetAsHTML('allowed_org_name');
		}
		$sAllowedOrgHtml = implode('<BR>', $aAllowedOrgs);

		$aUserInfo = [
			'login' => null,
			'profile_list' => $sProfileListHtml,
			'org_id' => null,
			'allowed_org_list' => $sAllowedOrgHtml,
		];

		$this->ConvertToHtml($aParams, $aUserInfo, 'user', $oUser);
	}

	public function ProvideHtmlContactInfo(\User $oUser, &$aParams): void{
		if (is_null($oUser)){
			return;
		}

		$iPersonId = $oUser->Get('contactid');
		if (0 === $iPersonId){
			return;
		}

		$oPerson = MetaModel::GetObject('Person', $iPersonId);

		$aParams['contact_link']= $this->GetEditLink($oPerson);
		$aContactInfo = [
			'first_name' => null,
			'name' => null,
			'email' => null,
			'phone' => null,
			'location_name' => null,
		];

		$aParams['contact']['picture'] = UserRights::GetUserPictureAbsUrl($oUser->Get('login'));//$oPerson->GetAsHTML('picture');
		$this->ConvertToHtml($aParams, $aContactInfo, 'contact', $oPerson);
	}

	public function ConvertToHtml(&$aParams, $aData, $sKey, DBObject $oObject)
	{
		foreach ($aData as $sAttCode => $sAttHtml){
			if ($sAttHtml) {
				$aParams[$sKey][MetaModel::GetLabel(get_class($oObject), $sAttCode)] = $sAttHtml;
			} else {
				$aParams[$sKey][MetaModel::GetLabel(get_class($oObject), $sAttCode)] = $oObject->GetAsHTML($sAttCode);
			}
		}
	}

	public function ProvideHtmlTokenInfo(\User $oUser, &$aParams){
		$aFields = ["application", "scope", "expiration_date", "use_count", "last_use_date"];

		$aColumns=[];
		foreach ($aFields as $sField){
			$aColumns[] = ['label' => MetaModel::GetLabel(\PersonalToken::class, $sField)];
		}

		$aDataValues=[];

		$sOql = sprintf("SELECT PersonalToken WHERE user_id = %s", $oUser->GetKey());
		$oFilter = DBObjectSearch::FromOQL($sOql, []);
		$oSet = new DBObjectSet($oFilter);

		$aTokenIds = [];
		if ($oSet->Count() > 0){
			while($oToken=$oSet->Fetch()){
				$aCurrentTokenData=[];
				foreach ($aFields as $sField) {
					$aCurrentTokenData[] = $oToken->GetAsHTML($sField);
				}
				$aDataValues[]=$aCurrentTokenData;
				$aTokenIds[] = $oToken->GetKey();
			}
		}

		$aRowActions = [
			[
				'tooltip'       => 'UI:Links:ActionRow:EditToken',
				'icon_classes'  => 'fas fa-pen',
				'action-class' => "token-edit-button",
			],
			[
				'tooltip'       => 'AuthentToken:RebuildToken+',
				'icon_classes'  => 'fas fa-sync-alt',
				'action-class' => "token-refresh-button",
			],
			[
				'tooltip'         => 'UI:Links:ActionRow:DeleteToken',
				'icon_classes'  => 'fas fa-trash',
				'action-class' => "token-delete-button",
				'color' => Button::ENUM_COLOR_SCHEME_DESTRUCTIVE,
			]
		];

		$oDatatableBlock = $this->BuildDatatable('tokens', $aColumns, $aDataValues, '', $aRowActions, $aTokenIds);
		$aParams['personaltoken'] = [
			'oDatatable' => $oDatatableBlock,
			'refresh_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'RefreshToken', 'rebuild_Token' => 1]),
			'edit_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'EditToken']),
			'delete_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'DeleteToken']),
			'new_token_link' => sprintf("%spages/UI.php?exec_module=authent-token&exec_page=ajax.php&operation=new", utils::GetAbsoluteUrlAppRoot())
		];
	}

	private function BuildDatatable(string $sRef, array $aColumns, array $aData = [], string $sFilter = '', array $aRowActions, array $aTokenIds) : FormTable
	{
		$oTable = new FormTable("datatable_".$sRef);
		$oTable->SetRef($sRef);
		$aColumns[] = [
			'label'       => Dict::S('UI:Datatables:Column:RowActions:Label'),
			'description' => Dict::S('UI:Datatables:Column:RowActions:Description'),
		];
		$oTable->SetColumns($aColumns);
		$oTable->SetFilter($sFilter);

		foreach ($aData as $iRowId => $aRow) {
			$sTokenId = $aTokenIds[$iRowId];
			$oToolbar = self::MakeActionRowToolbarTemplate($oTable, $aRowActions, $sTokenId);

			$oBlockRenderer = new BlockRenderer($oToolbar);

			//add toolbar html code as last row field
			$sDeletionLabel = Dict::Format("AuthentToken:DeleteTokenConfirmation", "rrrr");
			$sRowHtml = str_replace('data-role="ibo-button"',
				sprintf('data-role="ibo-button" data-token-id="%s" data-deletion-label="%s"', $sTokenId, $sDeletionLabel),
				$oBlockRenderer->RenderHtml()
			);
			$aRow[]= $sRowHtml;
			$oRow = new FormTableRow($sRef, $aColumns, $aRow, $iRowId);
			$oTable->AddRow($oRow);
		}

		return $oTable;
	}

	public static function MakeActionRowToolbarTemplate(iUIBlock $oTable, array $aRowActions, string $sTokenId)
	{
		// row actions toolbar container
		$oToolbar = ToolbarUIBlockFactory::MakeStandard();
		$oToolbar->AddCSSClass('ibo-datatable--row-actions-toolbar');

		// for each action...create an icon button
		foreach ($aRowActions as $iKey => $aAction) {
			$oButton = ButtonUIBlockFactory::MakeAlternativeNeutral('', $aAction['tooltip']);
			$oButton->SetIconClass($aAction['icon_classes'])
				->SetTooltip(Dict::S($aAction['tooltip']))
				//->AddDataAttribute("token-id", $sTokenId)
				->AddCSSClasses([$aAction['action-class'], 'ibo-action-button', 'ibo-regular-action-button']);

			if (array_key_exists('color', $aAction)){
				$oButton->SetColor($aAction['color']);
			}

			$oButton->SetDataAttributes(['label' => Dict::S($aAction['tooltip']), 'action-id' => $iKey, 'table-id' => $oTable->GetId()]);
			$oToolbar->AddSubBlock($oButton);
		}

		return $oToolbar;
	}


	public static function IsMenuAllowed($oUser) : bool
	{
		if (is_null($oUser)){
			return false;
		}

		if (UserRights::IsAdministrator($oUser)){
			return true;
		}

		if (utils::GetConfig()->GetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false)){
			return true;
		}

		return self::IsPersonalTokenManagementAllowed($oUser);
	}

	public static function IsPersonalTokenManagementAllowed($oUser) : bool
	{
		if (is_null($oUser)){
			return false;
		}

		if (UserRights::IsAdministrator($oUser)){
			return true;
		}

		$aProfiles = utils::GetConfig()->GetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);

		foreach($aProfiles as $sProfile)
		{
			if (UserRights::HasProfile($sProfile, $oUser))
			{
				return true;
			}
		}

		return false;
	}
}
