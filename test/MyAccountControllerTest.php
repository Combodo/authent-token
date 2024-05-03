<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\AuthentToken\Controller\AuthentTokenAjaxController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Service\PersonalTokenService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use MetaModel;

/**
 * @myaccount
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 * @backupGlobals disabled
 */
class MyAccountControllerTest  extends ItopDataTestCase {
	protected function setUp(): void {
		parent::setUp();
		@require_once(APPROOT.'env-production/authent-token/vendor/autoload.php');
	}

	protected function tearDown(): void {
		parent::tearDown();
		$_SESSION = [];
	}

	protected function CreateContactlessUserWithProfileName($sProfileName) : \UserLocal {
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => $sProfileName),
			true);
		return $this->CreateContactlessUser($sLogin, $oProfile->GetKey(), '123456abcdeFGTR@');
	}

	public function testIsPersonalTokenManagementAllowed_Admin($sProfileName='Administrator'){
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_Admin($sProfileName='Administrator'){
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsPersonalTokenManagementAllowed_OtherThanAdmin($sProfileName="Configuration Manager"){
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(false, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdmin($sProfileName='Configuration Manager'){
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(false, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', true);
		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdminAndProfileByPassing($sProfileName='Configuration Manager'){
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(false, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		\utils::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}
}

