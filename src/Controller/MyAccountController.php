<?php

namespace Combodo\iTop\AuthentToken\Controller;

use Combodo\iTop\Application\TwigBase\Controller\Controller;
use MetaModel;
use UserRights;

class MyAccountController extends Controller{
	const EXTENSION_NAME = "authent-token";

	public function OperationMainPage()
	{
		$aParams = [];
		/** @var \User $oUser */
		$oUser = UserRights::GetUserObject();

		$this->ProvideUserInfo($oUser, $aParams);
		$this->ProvideContactInfo($oUser, $aParams);
		$this->ProvideTokenInfo($oUser, $aParams);

		$this->DisplayPage(['Params' => $aParams ], 'main');
	}

	public function ProvideUserInfo(\User $oUser, &$aParams): void{
		if (is_null($oUser)){
			return;
		}

		$aUserInfo = ['login' => $oUser->Get('login')];

		$oProfileSet = $oUser->Get('profile_list');
		$aProfiles = [];
		while (($oProfile = $oProfileSet->Fetch()) != null){
			$aProfiles[]= $oProfile->Get('profile');
		}
		$aUserInfo['profiles'] = implode(', ', $aProfiles);

		$oAllowedOrgList = $oUser->Get('allowed_org_list');
		$aAllowedOrgs = [];
		while (($oUserOrg = $oAllowedOrgList->Fetch()) != null){
			$aAllowedOrgs[]= $oUserOrg->Get('allowed_org_name');
		}
		$aUserInfo['allowed_orgs'] = implode(', ', $aAllowedOrgs);

		$aParams['user'] = $aUserInfo;
	}

	public function ProvideContactInfo(\User $oUser, &$aParams): void{
		if (is_null($oUser)){
			return;
		}

		$iPersonId = $oUser->Get('contactid');
		if (0 === $iPersonId){
			return;
		}
		$oPerson = MetaModel::GetObject('Person', $iPersonId);

		$aContactInfo = [
			'firstname' => $oPerson->Get(('first_name')),
			'lastname' => $oPerson->Get(('name')),
			'email' => $oPerson->Get(('email')),
			'phone' => $oPerson->Get(('phone')),
			'location' => $oPerson->Get(('location_name')),
		];

		$aParams['contact'] = $aContactInfo;
	}


	public function ProvideTokenInfo(\User $oUser, &$aParams): void{
	}
}
