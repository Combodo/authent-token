<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Controller\MyAccountController;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use MetaModel;

class MyAccountControllerTest  extends ItopDataTestCase {
	private $oAdminProfile;
	private $oUser;
	private $sLogin;

	protected function setUp(): void {
		parent::setUp();
		@require_once(APPROOT.'env-production/authent-token/vendor/autoload.php');

		$this->sLogin = uniqid();
		echo $this->sLogin."\n";
		$this->oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'),
			true);
		$this->oUser = $this->CreateContactlessUser($this->sLogin, $this->oAdminProfile->GetKey(), '123456abcdeFGTR@');
	}

	public function testProvideUserInfo_OnlyLoginWith1Profile() {
		$aParams = [];
		$oMyAccountController = new MyAccountController('');
		$oMyAccountController->ProvideHtmlUserInfo($this->oUser, $aParams);

		$aExpectedParams = ['user' => [
			'login' => $this->sLogin,
			'profiles' => 'Administrator',
			'allowed_orgs' => '',
			'org_id' => 0
			]
		];
		$this->assertEquals($aExpectedParams, $aParams);
	}

	public function testProvideUserInfo_OnlyLoginWith2Profiles() {
		$aParams = [];
		$oMyAccountController = new MyAccountController('');

		$sProfile = "Configuration Manager";
		$oOtherProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => $sProfile), true);
		$this->AddProfileToUser($this->oUser, $oOtherProfile->GetKey());

		$oMyAccountController->ProvideHtmlUserInfo($this->oUser, $aParams);
		$aExpectedParams = ['user' => [
			'login' => $this->sLogin,
			'profiles' => "Administrator, $sProfile",
			'allowed_orgs' => '',
			'org_id' => 0,
		]
		];

		$this->assertEquals($aExpectedParams, $aParams);
	}

	public function testProvideUserInfo_OnlyLoginAndAllowedOrgs() {
		$aParams = [];
		$oMyAccountController = new MyAccountController('');

		$oAllowedOrgList = $this->oUser->Get('allowed_org_list');

		$oOrg1 = $this->CreateOrganization("org1");
		$oUserOrg = MetaModel::NewObject('URP_UserOrg', ['allowed_org_id' => $oOrg1->GetKey()]);
		$oAllowedOrgList->AddItem($oUserOrg);

		$oOrg2 = $this->CreateOrganization("org2");
		$oUserOrg = MetaModel::NewObject('URP_UserOrg', ['allowed_org_id' => $oOrg2->GetKey()]);
		$oAllowedOrgList->AddItem($oUserOrg);
		$this->oUser->Set('allowed_org_list', $oAllowedOrgList);
		$this->oUser->DBWrite();

		$oMyAccountController->ProvideHtmlUserInfo($this->oUser, $aParams);
		$aExpectedParams = ['user' => [
			'login' => $this->sLogin,
			'profiles' => "Administrator",
			'allowed_orgs' => 'org1, org2',
			'org_id' => 0,
			]
		];

		$this->assertEquals($aExpectedParams, $aParams);
	}

	public function testProvideContactInfo() {
		$oOrg = $this->CreateOrganization("meu");

		$oLocation = $this->createObject('Location', [
				'name' => 'ShadokLand',
				'org_id' => $oOrg->GetKey(),
			]
		);

		$oPerson = $this->createObject('Person', [
				'name' => 'GABU',
				'first_name' => 'zomeu',
				'org_id' => $oOrg->GetKey(),
				'email' => 'shadok@toto.org',
				'phone' => '123456',
				'location_id' => $oLocation->GetKey(),
			]
		);
		$this->oUser->Set('contactid', $oPerson->GetKey());
		$this->oUser->DBWrite();

		$aParams = [];
		$oMyAccountController = new MyAccountController('');
		$oMyAccountController->ProvideHtmlUserInfo($this->oUser, $aParams);
		$oMyAccountController->ProvideHtmlContactInfo($this->oUser, $aParams);

		$aExpectedParams = [
			'user' => [
				'login' => $this->sLogin,
				'profiles' => "Administrator",
				'allowed_orgs' => '',
				'org_id' => 0
			],
			'contact' => [
				'firstname' => 'zomeu',
				'lastname' => 'GABU',
				'email' => 'shadok@toto.org',
				'phone' => '123456',
				'location' => 'ShadokLand',
			],
		];
		$this->assertEquals($aExpectedParams, $aParams);
	}

	public function testProvideContactInfoWithoutLocation() {
		$oOrg = $this->CreateOrganization("meu");

		$oPerson = $this->createObject('Person', [
				'name' => 'GABU',
				'first_name' => 'zomeu',
				'org_id' => $oOrg->GetKey(),
				'email' => 'shadok@toto.org',
				'phone' => '123456',
			]
		);
		$this->oUser->Set('contactid', $oPerson->GetKey());
		$this->oUser->DBWrite();

		$aParams = [];
		$oMyAccountController = new MyAccountController('');
		$oMyAccountController->ProvideHtmlUserInfo($this->oUser, $aParams);
		$oMyAccountController->ProvideHtmlContactInfo($this->oUser, $aParams);

		$aExpectedParams = [
			'user' => [
				'login' => $this->sLogin,
				'profiles' => "Administrator",
				'allowed_orgs' => '',
				'org_id' => 0
			],
			'contact' => [
				'firstname' => 'zomeu',
				'lastname' => 'GABU',
				'email' => 'shadok@toto.org',
				'phone' => '123456',
				'location' => '',
			],
		];
		$this->assertEquals($aExpectedParams, $aParams);
	}
}

