<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use DBObjectSet;
use MetaModel;
use URP_UserProfile;
use UserToken;

class AuthentTokenServiceTest extends ItopDataTestCase {
	public function testTokenGeneration()
	{
		$oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);
		$oUserProfile = new URP_UserProfile();
		$oUserProfile->Set('profileid', $oAdminProfile->GetKey());
		$oUserProfile->Set('reason', 'UNIT Tests');
		$oSet = DBObjectSet::FromObject($oUserProfile);
		$oApplicationToken = $this->createObject(UserToken::class, array(
			'login' => uniqid(),
			'language' => 'EN US',
			'profile_list' => $oSet,
		));

		$oAuthentTokenService = new AuthentTokenService();
		$sToken1 = $oAuthentTokenService->CreateNewToken($oApplicationToken);
		$sToken2 = $oAuthentTokenService->CreateNewToken($oApplicationToken);
		$this->assertNotEquals($sToken1,$sToken2, "Make sure we always generate a new token value");
	}
}
