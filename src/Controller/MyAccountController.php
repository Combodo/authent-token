<?php

namespace Combodo\iTop\AuthentToken\Controller;

use AjaxPage;
use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\Application\TwigBase\Controller\Controller;
use Combodo\iTop\Application\UI\Base\Component\Button\Button;
use Combodo\iTop\Application\UI\Base\Component\Button\ButtonUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTable\FormTable;
use Combodo\iTop\Application\UI\Base\Component\DataTable\StaticTable\FormTableRow\FormTableRow;
use Combodo\iTop\Application\UI\Base\Component\DataTable\tTableRowActions;
use Combodo\iTop\Application\UI\Base\Component\Panel\Panel;
use Combodo\iTop\Application\UI\Base\Component\Template\TemplateUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\Toolbar;
use Combodo\iTop\Application\UI\Base\Component\Toolbar\ToolbarUIBlockFactory;
use Combodo\iTop\Application\UI\Base\Layout\Object\ObjectDetails;
use Combodo\iTop\Application\UI\Base\Layout\TabContainer\TabContainer;
use Combodo\iTop\Application\UI\Base\UIBlock;
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

/**
 * PersonalToken objects are protected and writable only as Administrator
 * Lot of operations are done here as a workaround to bypass the rights to let user handle his own tokens only from MyAccount menu:
 * creation / modification / refresh / deletion
 */
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

		//adding all below js. some in order to avoid a js console error. which is not fonctionnal even when displaying token forms

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

		$aJsFilesArrays = [
			UIBlock::DEFAULT_JS_FILES_REL_PATH,
			Panel::DEFAULT_JS_FILES_REL_PATH,
			TabContainer::DEFAULT_JS_FILES_REL_PATH,
			ObjectDetails::DEFAULT_JS_FILES_REL_PATH,
		];

		foreach ($aJsFilesArrays as $aJsFilesArray){
			foreach ($aJsFilesArray as $sJsRelFile){
				$this->AddLinkedScript(utils::GetAbsoluteUrlAppRoot().$sJsRelFile);
			}
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
			$oToken = $this->FetchToken($oUser, $sTokenId);

			$oToken->AllowWrite();
			$oPage = new AjaxPage("");
			$oToken->DisplayBareHeader($oPage, true);

			$sMessage = Dict::Format('AuthentToken:CopyToken', $oToken->GetToken());
			$this->DisplayJSONPage(['result' => 'ok', 'message' => $sMessage, 'title' => $oToken->Get('application')], 200);
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

	/**
	 * We cannot rely on apply_new persistence mecanism
	 * PersonalToken objects are protected and writable only as Administrator
	 * As a workaround we bypass the rights in this controller to let user handle his own tokens only.
	 * @return void
	 */
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
			$oToken->SetCanEditUserId(false);
			$oToken->DisplayModifyForm($oPage);
			$oPage->output();
		} catch (\Exception $e){
			IssueLog::error("Cannot edit token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	public function Operationapply_modify() {
		try {
			/** @var \User $oUser */
			$oUser = UserRights::GetUserObject();

			$sTokenId = utils::ReadParam('id', null);

			if ($sTokenId===null){
				IssueLog::error("Missing token_id for token edition");
				$this->DisplayJSONPage(['result' => 'error'], 200);
				return;
			}

			$oToken = $this->FetchToken($oUser, $sTokenId);
			$this->OperationSaveToken($oUser, $oToken);
		} catch (\Exception $e){
			IssueLog::error("Cannot modify token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	public function Operationapply_new() {
		try {
			/** @var \User $oUser */
			$oUser = UserRights::GetUserObject();

			$oToken = new \PersonalToken();
			$oToken->Set('user_id', $oUser->GetKey());

			$this->OperationSaveToken($oUser, $oToken);

			//pass token to display after page reload
			$sMessage = Dict::Format('AuthentToken:CopyToken', $oToken->getToken());
			Session::Set('AuthentToken:CopyToken',
				[
					'credential_message' => $sMessage,
					'token_name' => $oToken->Get('application')
				]
			);
		} catch (\Exception $e){
			IssueLog::error("Cannot create token: " + $e->getMessage());
			$this->DisplayJSONPage(['result' => 'error'], 200);
		}
	}

	private function OperationSaveToken(\User $oUser, \PersonalToken $oToken)
	{
		if (! self::IsPersonalTokenManagementAllowed($oUser)){
			//in case someone not allowed try to type full URL...
			http_response_code(401);
			die("User not allowed to access current ressource.");
		}

		$sTransactionId = utils::ReadPostedParam('transaction_id', '', 'transaction_id');
		if (!utils::IsTransactionValid($sTransactionId, false))
		{
			IssueLog::Error(sprintf("OperationSaveToken : invalid transaction_id ! data: user='%s'", $oUser->Get('login')));
			throw new \Exception(Dict::S('UI:Error:ObjectAlreadyCreated'));
		}

		$aErrors = $oToken->UpdateObjectFromPostedForm();

		if (!empty($aErrors))
		{
			$sErrors = implode(',', $aErrors);
			IssueLog::Error(sprintf("OperationSaveToken :  user='%s' errors:", $oUser->Get('login'), $sErrors));
			throw new \CoreCannotSaveObjectException(['issues' => $aErrors, 'id' => $oToken->GetKey(), 'class' => \PersonalToken::class ]);
		}

		//prevent from passing another user id
		$oToken->Set('user_id', $oUser->GetKey());
		$oToken->AllowWrite();
		$oToken->DBWrite();
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
			IssueLog::error(sprintf('Cannot find token with id %s and user_id %s', $sTokenId, $sUserId));
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

	private function GetFields(){
		return ["application", "scope", "expiration_date", "use_count", "last_use_date"];
	}

	public function ProvideHtmlTokenInfo(\User $oUser, &$aParams){
		$aColumns=[];
		foreach ($this->GetFields() as $sField){
			$aColumns[] = ['label' => MetaModel::GetLabel(\PersonalToken::class, $sField)];
		}

		$sOql = sprintf("SELECT PersonalToken WHERE user_id = %s", $oUser->GetKey());
		$oFilter = DBObjectSearch::FromOQL($sOql, []);
		$oSet = new DBObjectSet($oFilter);

		$aToken=[];
		if ($oSet->Count() > 0){
			while($oToken=$oSet->Fetch()){
				$aToken[] = $oToken;
			}
		}

		$aRefreshedTokenInfo = Session::Get('AuthentToken:CopyToken', null);
		if ($aRefreshedTokenInfo){
			$sTokenValue = $aRefreshedTokenInfo['credential_message'];
			$sTokenName = $aRefreshedTokenInfo['token_name'];
			//reset token value in the session for next display
			Session::Unset('AuthentToken:CopyToken');
		} else {
			$sTokenValue = null;
			$sTokenName = "";
		}

		$oDatatableBlock = $this->BuildDatatable('tokens', $aColumns, $aToken);
		$aParams['personaltoken'] = [
			'token_name' => $sTokenName,
			'token_value' => $sTokenValue,
			'oDatatable' => $oDatatableBlock,
			'refresh_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'RefreshToken', 'rebuild_Token' => 1]),
			'edit_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'EditToken']),
			'delete_token_url' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'DeleteToken']),
			'save_token_link' => utils::GetAbsoluteUrlModulePage(self::EXTENSION_NAME, 'ajax.php', ['operation' => 'SaveToken']),
		];
	}

	/**
	 * Generate Datapanel with CRUD action button on each row.
	 * this could be replaced by iTop 3.1 build-it twig code. For SaaS it has to work in 3.0
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
	private function BuildDatatable(string $sTableRef, array $aColumns, array $aToken) : FormTable
	{
		$oTable = new FormTable("datatable_".$sTableRef);
		$oTable->SetRef($sTableRef);
		$aColumns[] = [
			'label'       => Dict::S('UI:Datatables:Column:RowActions:Label'),
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

	private function BuildFormTableRow($oToken, string $sTableRef, array $aColumns) : FormTableRow{
		$aFields = $this->GetFields();
		$aTokenRowData=[];
		foreach ($aFields as $sField) {
			$aTokenRowData[] = $oToken->GetAsHTML($sField);
		}

		$oToolbar = self::MakeActionRowToolbarTemplate($sTableRef);

		$oBlockRenderer = new BlockRenderer($oToolbar);

		$sDeletionLabel = Dict::Format("AuthentToken:Message:DeleteTokenConfirmation", $oToken->Get('application'));
		$sTokenId = $oToken->GetKey();
		$sRowHtml = str_replace('data-role="ibo-button"',
			sprintf('data-role="ibo-button" data-token-id="%s" data-deletion-label="%s"', $sTokenId, $sDeletionLabel),
			$oBlockRenderer->RenderHtml()
		);
		//add toolbar html code as last row field
		$aTokenRowData[]= $sRowHtml;
		return new FormTableRow($sTableRef, $aColumns, $aTokenRowData, $sTokenId);
	}

	public static function MakeActionRowToolbarTemplate(string $sTableId) : Toolbar
	{
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

		// row actions toolbar container
		$oToolbar = ToolbarUIBlockFactory::MakeStandard();
		$oToolbar->AddCSSClass('ibo-datatable--row-actions-toolbar');

		// for each action...create an icon button
		foreach ($aRowActions as $iKey => $aAction) {
			$oButton = ButtonUIBlockFactory::MakeAlternativeNeutral('', $aAction['tooltip']);
			$oButton->SetIconClass($aAction['icon_classes'])
				->SetTooltip(Dict::S($aAction['tooltip']))
				->AddCSSClasses([$aAction['action-class'], 'ibo-action-button', 'ibo-regular-action-button']);

			if (array_key_exists('color', $aAction)){
				$oButton->SetColor($aAction['color']);
			}

			$oButton->SetDataAttributes(['label' => Dict::S($aAction['tooltip']), 'action-id' => $iKey, 'table-id' => $sTableId]);
			$oToolbar->AddSubBlock($oButton);
		}

		return $oToolbar;
	}

	public static function IsMenuAllowed($oUser) : bool
	{
		if (is_null($oUser)){
			return false;
		}

		if (defined(ITOP_VERSION) && version_compare(ITOP_VERSION, '3.0') < 0){
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
