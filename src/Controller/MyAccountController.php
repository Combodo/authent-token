<?php

namespace Combodo\iTop\AuthentToken\Controller;

use AjaxPage;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\Application\UI\Base\Component\Button\Button;
use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTable\FormTable;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTableRow\FormTableRow;
use Combodo\iTop\Application\UI\Base\Component\DataTable\tTableRowActions;
use Combodo\iTop\Application\UI\Base\Component\Template\TemplateUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\ToolbarUIBlockFactory;
use Combodo\iTop\Application\UI\Base\iUIBlock;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\Renderer\BlockRenderer;
use DBObject;
use DBObjectSearch;
use DBObjectSet;
use Dict;
use IssueLog;
use MetaModel;
use UserRights;
use utils;
use WebPage;

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
			$aParams['refresh_token_url']= utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php',
				['operation' => 'RefreshToken', 'rebuild_Token' => 1]);
		}

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
			$oSearch = new DBObjectSearch(\PersonalToken::class);
			$oSearch->AllowAllData();
			$oSearch->Addcondition('id', $sTokenId, '=');
			$oTokens = new DBObjectSet($oSearch);
			$oToken = $oTokens->Fetch();
			$oToken->AllowWrite();

			$oPage = new AjaxPage("");
			$oToken->DisplayBareHeader($oPage, true);

			$sMessage = Dict::Format('PersonalToken:CopyToken', $oToken->getToken());
			$this->DisplayJSONPage(['result' => 'ok', 'message' => $sMessage], 200);
		} catch (\Exception $e){
			IssueLog::error("Cannot refresh token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}


	public function DisplayDetails(WebPage $oPage, DBObject $oObject, $aFields)
	{
		$oPage->add('<h1>'.MetaModel::GetName(get_class($oObject)).': '.$oObject->GetName().'</h1>');
		$aValues = array();
		$aList = MetaModel::FlattenZList(MetaModel::GetZListItems(get_class($oObject), 'details'));
		if (empty($aList))
		{
			$aList = array_keys(MetaModel::ListAttributeDefs(get_class($oObject)));
		}
		foreach($aList as $sAttCode)
		{
			if (in_array($sAttCode, $aFields)){
				$aValues[$sAttCode] = array('label' => MetaModel::GetLabel(get_class($oObject), $sAttCode), 'value' => $oObject->GetAsHTML($sAttCode));
			}
		}
		$oPage->details($aValues);
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
				'label'         => 'UI:Links:ActionRow:Edit',
				'tooltip'       => 'UI:Links:ActionRow:Edit+',
				'icon_classes'  => 'fas fa-pen',
				'js_row_action' => "EditToken(this, 'ID');",
			],
			[
				'label'         => 'AuthentToken:RebuildToken',
				'tooltip'       => 'AuthentToken:RebuildToken+',
				'icon_classes'  => 'fas fa-sync-alt',
				'js_row_action' => "RefreshToken(this, 'ID');",
			],
			[
				'label'         => 'UI:Links:ActionRow:Delete',
				'tooltip'       => 'UI:Links:ActionRow:Delete+',
				'icon_classes'  => 'fas fa-trash',
				'js_row_action' => "DeleteToken(this, 'ID');",
				'color' => Button::ENUM_COLOR_SCHEME_DESTRUCTIVE,
			]
		];

		list($oDatatableBlock, $aButtonBlocks) = $this->BuildDatatable('tokens', $aColumns, $aDataValues, '', $aRowActions, $aTokenIds);
		$aParams['personaltoken'] = [
			'oDatatable' => $oDatatableBlock,
			'aButtonBlocks' => $aButtonBlocks,
			'newtoken_link' => sprintf("%spages/UI.php?exec_module=authent-token&exec_page=ajax.php&operation=new", utils::GetAbsoluteUrlAppRoot())
		];
	}

	private function BuildDatatable(string $sRef, array $aColumns, array $aData = [], string $sFilter = '', array $aRowActions, array $aTokenIds) : array
	{
		$oTable = new FormTable("datatable_".$sRef);
		$oTable->SetRef($sRef);
		$aColumns[] = [
			'label'       => Dict::S('UI:Datatables:Column:RowActions:Label'),
			'description' => Dict::S('UI:Datatables:Column:RowActions:Description'),
		];
		$oTable->SetColumns($aColumns);
		$oTable->SetFilter($sFilter);

		$aButtonBlocks = [];

		foreach ($aData as $iRowId => $aRow) {
			$oToolbar = self::MakeActionRowToolbarTemplate($oTable, $aRowActions, $aTokenIds[$iRowId], $aButtonBlocks);

			$oBlockRenderer = new BlockRenderer($oToolbar);

			//add toolbar html code as last row field
			$aRow[]= $oBlockRenderer->RenderHtml();
			$oRow = new FormTableRow($sRef, $aColumns, $aRow, $iRowId);
			$oTable->AddRow($oRow);
		}

		return [ $oTable, $aButtonBlocks ];
	}

	public static function MakeActionRowToolbarTemplate(iUIBlock $oTable, array $aRowActions, string $sTokenId, &$aButtonBlocks)
	{
		// row actions toolbar container
		$oToolbar = ToolbarUIBlockFactory::MakeStandard();
		$oToolbar->AddCSSClass('ibo-datatable--row-actions-toolbar');

		// for each action...create an icon button
		foreach ($aRowActions as $iKey => $aAction) {
			$oButton = ButtonUIBlockFactory::MakeAlternativeNeutral('', $aAction['label']);
			$sJsCode = str_replace('ID', $sTokenId, $aAction['js_row_action']);
			$oButton->SetIconClass($aAction['icon_classes'])
				->SetOnClickJsCode($sJsCode)
				->SetTooltip(Dict::S($aAction['tooltip']))
				->AddCSSClasses(['ibo-action-button', 'ibo-regular-action-button']);

			if (array_key_exists('color', $aAction)){
				$oButton->SetColor($aAction['color']);
			}

			$oButton->SetDataAttributes(['label' => Dict::S($aAction['label']), 'action-id' => $iKey, 'table-id' => $oTable->GetId()]);
			$oToolbar->AddSubBlock($oButton);

			$aButtonBlocks[] = $oButton;
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
