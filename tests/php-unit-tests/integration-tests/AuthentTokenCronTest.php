<?php

namespace Combodo\iTop\Test\UnitTest\Webservices;

use AbstractPersonalToken;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use ContextTag;
use Exception;
use iTopMutex;
use MetaModel;
use PersonalToken;
use ReflectionClass;
use utils;

/**
 * @group itopRequestMgmt
 * @group restApi
 * @group defaultProfiles
 */
class AuthentTokenCronTest extends ItopDataTestCase
{
	public const USE_TRANSACTION = false;
	public const CREATE_TEST_ORG = false;

	public static $sLogin;
	public static $sPassword = "Iuytrez9876543ç_è-(";

	/**
	 * @throws Exception
	 */
	protected function setUp(): void
	{
		parent::setUp();
		$this->BackupConfiguration();

		static::$sLogin = "rest-user-";//.date('dmYHis');

		$this->CreateTestOrganization();

		$this->AddLoginModeAndSaveConfiguration(TokenLoginExtension::LOGIN_TYPE);
		$this->oiTopConfig->Set('secure_rest_services', true, 'auth-token');
		$this->oiTopConfig->Set('login_debug', true, 'auth-token');
		$this->oiTopConfig->Set('allow_rest_services_via_tokens', true, 'auth-token');
		$this->oiTopConfig->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', ['Administrator', 'REST Services User']);
		$this->SaveItopConfFile();
	}

	public function testRestWithToken()
	{
		$oUser = $this->CreateUserWithProfiles([self::$aURP_Profiles['Administrator'], self::$aURP_Profiles['REST Services User']]);
		$oPersonalToken = $this->CreatePersonalToken($oUser, "CRONTEST", ContextTag::TAG_REST);

		$aPostFields = [
			'version' => '1.3',
			'auth_token' => $this->GetAuthToken($oPersonalToken),
			'json_data' => '{"operation": "list_operations"}',
		];

		$sJSONResult = $this->CallItopUri("/webservices/rest.php", $aPostFields);

		$this->assertEquals($this->GetExpectedRestResponse(), $sJSONResult);
	}

	public function testLaunchCronWithTokenMode_AuthenticationPassedButNotAuthorizedToRunCronAsNonAdmin()
	{
		$oUser = $this->CreateUserWithProfiles([self::$aURP_Profiles['REST Services User']]);

		$this->SaveItopConfFile();
		$oPersonalToken = $this->CreatePersonalToken($oUser, "CRONTEST", ContextTag::TAG_CRON);

		$sLogFileName = "crontest_".uniqid();
		$aPostFields = [
			'version' => '1.3',
			'auth_token' => $this->GetAuthToken($oPersonalToken),
			'verbose' => 1,
			'debug' => 1,
			'cron_log_file' => $sLogFileName,
		];

		$sJSONResult = $this->CallItopUri("/webservices/asynchronously_cron.php", $aPostFields);

		$this->assertEquals($this->GetExpectedCronResponse(), $sJSONResult);
		$sLogFile = $this->CheckLogFileIsGeneratedAndGetFullPath($sLogFileName);
		$this->CheckAdminAccessIssueWithCron($sLogFile);
	}

	public function testGetUserLoginWithTokenMode_NoAuthorizationDueToTokenScope()
	{
		$oUser = $this->CreateUserWithProfiles([self::$aURP_Profiles['Administrator']]);
		$oPersonalToken = $this->CreatePersonalToken($oUser, "CRONTEST", ContextTag::TAG_REST);

		$oLoginMode = new TokenLoginExtension();

		$this->expectException(TokenAuthException::class);
		$this->expectExceptionMessage("Scope not authorized");
		$oLoginMode->GetUserLogin([$this->GetAuthToken($oPersonalToken)]);
	}

	public function testGetUserLoginWithTokenModeOK()
	{
		$oUser = $this->CreateUserWithProfiles([self::$aURP_Profiles['Administrator']]);
		$oPersonalToken = $this->CreatePersonalToken($oUser, "CRONTEST", ContextTag::TAG_CRON);

		$oLoginMode = new TokenLoginExtension();

		$oCtx = new ContextTag(ContextTag::TAG_CRON);
		$sUserLogin = $oLoginMode->GetUserLogin([$this->GetAuthToken($oPersonalToken)]);
		$this->assertEquals(static::$sLogin, $sUserLogin);
	}

	protected function GetAuthToken($oToken)
	{
		$oReflectionClass = new ReflectionClass(AbstractPersonalToken::class);
		$oProperty = $oReflectionClass->getProperty('sToken');
		$oProperty->setAccessible(true);

		return $oProperty->getValue($oToken);
	}

	private function CreateUserWithProfiles(array $aProfileIds): ?\UserLocal
	{
		if (count($aProfileIds) > 0) {
			$oUser = null;
			foreach ($aProfileIds as $iProfileId) {
				if (is_null($oUser)) {
					$oUser = $this->CreateContactlessUser(static::$sLogin, $iProfileId, static::$sPassword);
				} else {
					$this->AddProfileToUser($oUser, $iProfileId);
				}
				$oUser->DBWrite();
			}

			return $oUser;
		}

		return null;
	}

	public function CreatePersonalToken(\User $oUser, string $sApplication, $sScope = null): PersonalToken
	{
		/** PersonalToken $oPersonalToken */
		$oPersonalToken = $this->createObject(PersonalToken::class, [
			'user_id' => $oUser->GetKey(),
			'application' => $sApplication,
			'scope' => $sScope ?? ContextTag::TAG_REST,
		]);
		return $oPersonalToken;
	}

	private function GetExpectedRestResponse(): string
	{
		return <<<JSON
{"code":0,"message":"Operations: 7","version":"1.3","operations":[{"verb":"core\/create","description":"Create an object","extension":"CoreServices"},{"verb":"core\/update","description":"Update an object","extension":"CoreServices"},{"verb":"core\/apply_stimulus","description":"Apply a stimulus to change the state of an object","extension":"CoreServices"},{"verb":"core\/get","description":"Search for objects","extension":"CoreServices"},{"verb":"core\/delete","description":"Delete objects","extension":"CoreServices"},{"verb":"core\/get_related","description":"Get related objects through the specified relation","extension":"CoreServices"},{"verb":"core\/check_credentials","description":"Check user credentials","extension":"CoreServices"}]}
JSON;
	}

	private function GetExpectedCronResponse(): string
	{
		return '{"message":"OK"}';
	}

	private function CheckLogFileIsGeneratedAndGetFullPath(string $sLogFileName): string
	{
		$sLogFile = APPROOT."log/$sLogFileName";
		$this->assertTrue(is_file($sLogFile));
		$this->aFileToClean[] = $sLogFile;
		return $sLogFile;
	}

	private function CheckAdminAccessIssueWithCron(string $sLogFile)
	{
		$aLines = Utils::ReadTail($sLogFile);
		$sLastLine = array_shift($aLines);
		$this->assertMatchesRegularExpression('/^Access restricted to administrators/', $sLastLine, "@$sLastLine@");
	}
}
