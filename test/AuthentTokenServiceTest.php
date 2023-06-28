<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use DBObjectSet;
use MetaModel;
use URP_UserProfile;
use UserToken;

class AuthentTokenServiceTest extends ItopDataTestCase {
	private function CreateUserToken() : \DBObject {
		$oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);
		$oUserProfile = new URP_UserProfile();
		$oUserProfile->Set('profileid', $oAdminProfile->GetKey());
		$oUserProfile->Set('reason', 'UNIT Tests');
		$oSet = DBObjectSet::FromObject($oUserProfile);
		return  $this->createObject(UserToken::class, array(
			'login' => uniqid(),
			'language' => 'EN US',
			'profile_list' => $oSet,
		));
	}

	public function testTokenGeneration()
	{
		$oApplicationToken = $this->CreateUserToken();

		$oAuthentTokenService = new AuthentTokenService();
		$sToken1 = $oAuthentTokenService->CreateNewToken($oApplicationToken);
		$sToken2 = $oAuthentTokenService->CreateNewToken($oApplicationToken);
		$this->assertNotEquals($sToken1,$sToken2, "Make sure we always generate a new token value");

		//make sure token can stored in AttributeEncryptedString for webhook extension
		$this->assertTrue(strlen($sToken1) < 255);
	}

	public function testEncryptDecrypt(){
		$oApplicationToken = $this->CreateUserToken();
		$oAuthentTokenService = new AuthentTokenService();
		$sToken1 = $oAuthentTokenService->CreateNewToken($oApplicationToken);

		$aTokenFields = $oAuthentTokenService->DecryptToken($sToken1);
		$oToken = $oAuthentTokenService->GetToken($aTokenFields);
		$this->assertNotNull($oToken);
	}

	public function testLegacyEncryptDecrypt(){
		$oApplicationToken = $this->CreateUserToken();

		$aLegacyToken = [
			AuthentTokenService::LEGACY_TOKEN_ID     => $oApplicationToken->GetKey(),
			AuthentTokenService::LEGACY_TOKEN_CLASS => get_class($oApplicationToken),
			AuthentTokenService::TOKEN_SALT => random_int(0, 1000000),
		];

		$oAuthentTokenService = new AuthentTokenService();
		$sPPrivateKey = $this->InvokeNonPublicMethod(AuthentTokenService::class , "GetPrivateKey", $oAuthentTokenService, []);
		$oCrypt = $this->InvokeNonPublicMethod(AuthentTokenService::class , "GetSimpleCryptObject", $oAuthentTokenService, []);
		$sToken1 = bin2hex($oCrypt->Encrypt($sPPrivateKey, json_encode($aLegacyToken)));

		$aTokenFields = $oAuthentTokenService->DecryptToken($sToken1);
		$oToken = $oAuthentTokenService->GetToken($aTokenFields);
		$this->assertNotNull($oToken);
	}
}
