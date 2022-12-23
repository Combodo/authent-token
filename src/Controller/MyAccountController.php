<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use DBObject;
use DBObjectSearch;
use DBObjectSet;
use MetaModel;
use UserRights;
use WebPage;

class MyAccountController extends Controller{
	const EXTENSION_NAME = "authent-token";

	public function OperationMainPage()
	{
		$aParams = [];
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		$this->ProvideHtmlUserInfo($oUser, $aParams);
		$this->ProvideHtmlContactInfo($oUser, $aParams);
		$this->ProvideHtmlTokenInfo($oUser, $aParams);
		$this->DisplayPage(['Params' => $aParams ], 'main');
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

	public function ProvideHtmlUserInfo(\User $oUser, &$aParams): void{
		$aData = [];
		$oUser = $this->ProvideUserInfo($oUser, $aData);

		if (is_null($oUser)){
			return;
		}

		$this->ConvertToHtml($aParams, $aData, 'user', $oUser);
	}

	public function ProvideUserInfo(\User $oUser, &$aParams){
		if (is_null($oUser)){
			return null;
		}

		$aUserInfo = ['login' => $oUser->Get('login')];

		$oProfileSet = $oUser->Get('profile_list');
		$aProfiles = [];
		while (($oProfile = $oProfileSet->Fetch()) != null){
			$aProfiles[]= $oProfile->Get('profile');
		}
		$aUserInfo['profile_list'] = implode(', ', $aProfiles);

		$oAllowedOrgList = $oUser->Get('allowed_org_list');
		$aAllowedOrgs = [];
		while (($oUserOrg = $oAllowedOrgList->Fetch()) != null){
			$aAllowedOrgs[]= $oUserOrg->Get('allowed_org_name');
		}
		$aUserInfo['allowed_org_list'] = implode(', ', $aAllowedOrgs);

		$aParams['user'] = $aUserInfo;
		return $oUser;
	}

	public function ProvideHtmlContactInfo(\User $oUser, &$aParams): void{
		$aData = [];
		$oPerson = $this->ProvideContactInfo($oUser, $aData);

		if (is_null($oPerson)){
			return;
		}

		$this->ConvertToHtml($aParams, $aData, 'contact', $oPerson);
	}

	public function ConvertToHtml(&$aParams, $aData, $sKey, DBObject $oObject)
	{
		foreach ($aData[$sKey] as $sAttCode => $sValue){
			$aParams[$sKey][MetaModel::GetLabel(get_class($oObject), $sAttCode)] = $oObject->GetAsHTML($sAttCode);
		}
	}

	public function ProvideContactInfo(\User $oUser, &$aParams) {
		if (is_null($oUser)){
			return null;
		}

		$iPersonId = $oUser->Get('contactid');
		if (0 === $iPersonId){
			return null;
		}
		$oPerson = MetaModel::GetObject('Person', $iPersonId);

		$aContactInfo = [
			'picture' => $oPerson->Get('picture'),
			'first_name' => $oPerson->Get('first_name'),
			'name' => $oPerson->Get('name'),
			'email' => $oPerson->Get('email'),
			'phone' => $oPerson->Get('phone'),
			'location_name' => $oPerson->Get('location_name'),
		];

		$aParams['contact'] = $aContactInfo;
		return $oPerson;
	}

	public function ProvideTokenInfo(\User $oUser): ?array{
		$oFilter = DBObjectSearch::FromOQL("SELECT PersonalToken", []);
		$oSet = new DBObjectSet($oFilter);

		return $oSet->FetchAssoc();
	}

	public function ProvideHtmlTokenInfo(\User $oUser, &$aParams){
		$aData = $this->ProvideTokenInfo($oUser);
		$aFields = ["application", "scope", "expiration_date", "use_count", "last_use_date"];

		$aColumns=[];
		foreach ($aFields as $sField){
			$aColumns[] = ['label' => MetaModel::GetLabel(\PersonalToken::class, $sField)];
		}
		
		$aDataValues=[];
		if (!is_null($aData)){
			foreach ($aData as $oToken){
				foreach ($aFields as $sField) {
					$aDataValues[] = $oToken->GetAsHTML($sField);
				}
			}
		}
		
		$aParams['personaltoken'] = [
			'aColumns' => $aColumns,
			'aData' => $aDataValues,
		];
	}
}
