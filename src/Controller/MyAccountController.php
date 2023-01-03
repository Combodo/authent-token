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
		if (is_null($oUser)){
			return;
		}

		$aUserInfo = [
			'login' => $oUser->Get('login'),
			'profile_list' => $oUser->Get('profile_list'),
			'allowed_org_list' => $oUser->Get('allowed_org_list'),
			'org_id' => $oUser->Get('org_id'),
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
		$aContactInfo = [
			'picture' => $oPerson->Get('picture'),
			'first_name' => $oPerson->Get('first_name'),
			'name' => $oPerson->Get('name'),
			'email' => $oPerson->Get('email'),
			'phone' => $oPerson->Get('phone'),
			'location_name' => $oPerson->Get('location_name'),
		];

		$this->ConvertToHtml($aParams, $aContactInfo, 'contact', $oPerson);
	}

	public function ConvertToHtml(&$aParams, $aData, $sKey, DBObject $oObject)
	{
		foreach ($aData as $sAttCode => $sValue){
			$aParams[$sKey][MetaModel::GetLabel(get_class($oObject), $sAttCode)] = $oObject->GetAsHTML($sAttCode);
		}
	}

	public function ProvideTokenInfo(\User $oUser): ?array{
		$oFilter = DBObjectSearch::FromOQL("SELECT PersonalToken", []);
		$oSet = new DBObjectSet($oFilter);

		return $oSet->FetchAssoc();
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

		if ($oSet->Count() > 0){
			while($oToken=$oSet->Fetch()){
				$aCurrentTokenData=[];
				foreach ($aFields as $sField) {
					$aCurrentTokenData[] = $oToken->GetAsHTML($sField);
				}
				$aDataValues[]=$aCurrentTokenData;
			}
		}

		$aParams['personaltoken'] = [
			'aColumns' => $aColumns,
			'aData' => $aDataValues,
		];
	}
}
