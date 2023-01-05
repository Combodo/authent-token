<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Controller\MyAccountController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
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

	public function testIsPersonalTokenManagementAllowed_Admin($sProfileName='Administrator'){
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oUser = $this->CreateContactlessUser($sLogin, $sProfileName);

		$this->assertEquals(true, MyAccountController::IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		$this->assertEquals(true, MyAccountController::IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_Admin($sProfileName='Administrator'){
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oUser = $this->CreateContactlessUser($sLogin, $sProfileName);

		$this->assertEquals(true, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->assertEquals(true, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsPersonalTokenManagementAllowed_OtherThanAdmin($sProfileName="Configuration Manager"){
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oUser = $this->CreateContactlessUser($sLogin, $sProfileName);

		$this->assertEquals(false, MyAccountController::IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		$this->assertEquals(true, MyAccountController::IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdmin($sProfileName='Configuration Manager'){
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oUser = $this->CreateContactlessUser($sLogin, $sProfileName);

		$this->assertEquals(false, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', true);
		$this->assertEquals(true, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdminAndProfileByPassing($sProfileName='Configuration Manager'){
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oUser = $this->CreateContactlessUser($sLogin, $sProfileName);

		$this->assertEquals(false, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->assertEquals(true, MyAccountController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}
}

