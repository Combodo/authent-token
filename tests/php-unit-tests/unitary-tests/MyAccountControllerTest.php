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
class MyAccountControllerTest extends ItopDataTestCase
{
	protected function setUp(): void
	{
		parent::setUp();
		$this->BackupConfiguration();
		$this->RequireOnceItopFile('/env-production/authent-token/vendor/autoload.php');
	}

	protected function tearDown(): void
	{
		parent::tearDown();
		$_SESSION = [];
	}

	protected function CreateContactlessUserWithProfileName($sProfileName): \UserLocal
	{
		$sLogin = sprintf("%s-%s", $sProfileName, date('Y-m-d-H:i:s'));
		$oProfile = MetaModel::GetObjectFromOQL(
			"SELECT URP_Profiles WHERE name = :name",
			['name' => $sProfileName],
			true
		);
		return $this->CreateContactlessUser($sLogin, $oProfile->GetKey(), '123456abcdeFGTR@');
	}

	public function testIsPersonalTokenManagementAllowed_Admin($sProfileName = 'Administrator')
	{
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		$this->SaveItopConfFile();

		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_Admin($sProfileName = 'Administrator')
	{
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->SaveItopConfFile();

		$this->assertEquals(true, AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsPersonalTokenManagementAllowed_OtherThanAdmin($sProfileName = "Configuration Manager")
	{
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));

		$this->assertEquals(false, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");

		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		$this->SaveItopConfFile();

		$this->assertEquals(true, PersonalTokenService::GetInstance()->IsPersonalTokenManagementAllowed($oUser), "default conf: IsPersonalTokenManagementAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdmin($sProfileName = 'Configuration Manager')
	{
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));
		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->SaveItopConfFile();

		$this->assertFalse(AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', []);
		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', true);
		$this->SaveItopConfFile();

		$this->assertTrue(AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}

	public function testIsMenuAllowed_OtherThanAdminAndProfileByPassing($sProfileName = 'Configuration Manager')
	{
		$oUser = $this->CreateContactlessUserWithProfileName($sProfileName);
		$_SESSION = [];
		\UserRights::Login($oUser->Get('login'));
		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'enable_myaccount_menu', false);
		$this->SaveItopConfFile();

		$this->assertFalse(AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");

		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', [$sProfileName]);
		$this->SaveItopConfFile();

		$this->assertTrue(AuthentTokenAjaxController::IsMenuAllowed($oUser), "default conf: IsMenuAllowed check on $sProfileName");
	}
}
