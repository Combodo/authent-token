<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use Combodo\iTop\AuthentToken\Service\MetaModelService;
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
		//real limit is 255 but it is nice to have early notifications
		$this->assertTrue(strlen($sToken1) < 200, "make sure token can stored in AttributeEncryptedString for webhook extension (real limit is 255 but it is nice to have early notifications)");
		var_dump((['new token format length' => strlen($sToken1) ]));
		var_dump((['new format length' => $sToken1 ]));

		//test decrypt
		$oToken = $oAuthentTokenService->DecryptToken($sToken1);
		$this->assertNotNull($oToken);

		//test decrypt with 3.1 alpha/saas format decrypt
		$sToken1 = $this->InvokeNonPublicMethod(AuthentTokenService::class , "CreateLegacyToken", $oAuthentTokenService, [$oToken]);
		var_dump((['old token format length' => strlen($sToken1) ]));
		var_dump((['old format' => $sToken1 ]));
		$oToken = $oAuthentTokenService->DecryptToken($sToken1);
		$this->assertNotNull($oToken);
	}

	public function GetLegacyTokenProvider(){
		return [
			'not an array' => [ 'sToken' => "xxx" ],
			'an array without id' => [ 'sToken' => json_encode(["c" => 'PersonalToken'])],
			'an array without class' => [ 'sToken' => json_encode(["i" => 1])],
			'an array with class not a class' => [ 'sToken' => json_encode(["i" => 1, "c" => "Toto"]) ],
			'an array with class not a token' => [ 'sToken' => json_encode(["i" => 1, "c" => AuthentTokenService::class]) ],
			'an array with id not an integer' => [ 'sToken' => json_encode(["i" => "a", "c" => \PersonalToken::class]) ],
			'PersonalToken' => [ 'sToken' => json_encode(["i" => 2, "c" => \PersonalToken::class]), 'bIsNull' => false, 'sExpectedClass' => \PersonalToken::class, 'sExpectedId' =>2 ],
			'UserToken' => [ 'sToken' => json_encode(["i" => 1, "c" => \UserToken::class]), 'bIsNull' => false, 'sExpectedClass' => \UserToken::class, 'sExpectedId' => 1 ],
		];
	}

	/**
	 * @dataProvider GetLegacyTokenProvider
	 */
	public function testGetLegacyToken($sToken, $bIsNull=true, $sExpectedClass=null, $sExpectedId=null){
		$oMetaModelService = $this->createMock(MetaModelService::class);
		$oAuthentTokenService = new AuthentTokenService($oMetaModelService);

		if ($bIsNull){
			$oMetaModelService->expects($this->never())->method('GetObject');
			$this->assertNull($oAuthentTokenService->GetLegacyToken($sToken));
		} else {
			$oMetaModelService->expects($this->once())->method('GetObject')->with($sExpectedClass, $sExpectedId, true, false, null);
			$oAuthentTokenService->GetLegacyToken($sToken);
		}
	}

	public function GetTokenProvider(){
		return [
			'not enough separators 1' => [ 'sToken' => "xxx" ],
			'not enough separators 2' => [ 'sToken' => "xxx:" ],
			'id not an integer' => [ 'sToken' => "aa:PersonalToken:vorhgiorh" ],
			'class not a class' => [ 'sToken' => "1:Toto:vorhgiorh" ],
			'class not a token' => [ 'sToken' => "1:" . AuthentTokenService::class . ":vorhgiorh" ],
			'PersonalToken' => [ 'sToken' => "1:" . \PersonalToken::class . ":vorhgiorh", 'bIsNull' => false, 'sExpectedClass' => \PersonalToken::class, 'sExpectedId' => 1 ],
			'UserToken' => [ 'sToken' => "2:" . UserToken::class . ":vorhgiorh", 'bIsNull' => false, 'sExpectedClass' => \UserToken::class, 'sExpectedId' => 2 ],
			'UserToken + a separator inside salt' => [ 'sToken' => "2:" . UserToken::class. ":vorh:giorh", 'bIsNull' => false, 'sExpectedClass' => \UserToken::class, 'sExpectedId' => 2 ],
		];
	}

	/**
	 * @dataProvider GetTokenProvider
	 */
	public function testGetToken($sToken, $bIsNull=true, $sExpectedClass=null, $sExpectedId=null){
		$oMetaModelService = $this->createMock(MetaModelService::class);
		$oAuthentTokenService = new AuthentTokenService($oMetaModelService);

		if ($bIsNull){
			$oMetaModelService->expects($this->never())->method('GetObject');
			$this->assertNull($oAuthentTokenService->GetToken($sToken));
		} else {
			$oMetaModelService->expects($this->once())->method('GetObject')->with($sExpectedClass, $sExpectedId, true, false, null);
			$oAuthentTokenService->GetToken($sToken);
		}
	}
}
