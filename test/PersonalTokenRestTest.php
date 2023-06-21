<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
require_once __DIR__.'/AbstractTokenRestTest.php';

use AbstractPersonalToken;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;
use Exception;
use MetaModel;
use PersonalToken;


/**
 * @group itopRequestMgmt
 * @group multiTokenRestApi
 * @group defaultProfiles
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 * @backupGlobals disabled
 */
class PersonalTokenRestTest extends AbstractTokenRestTest
{
	protected $oPersonalToken;
	protected $oAdminToken;
	protected $bEmptyToken = false;

	/**
	 * @throws Exception
	 */
	protected function setUp(): void
	{
		parent::setUp();

		//Disabling those tests until the issue is fixed
		if (version_compare(PHP_VERSION, '8.1.0', '>=')) {
			$this->markTestSkipped('Disabled until N°6434 is resolved');
		}

		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
		$this->InitLoginMode(TokenLoginExtension::LOGIN_TYPE);

		MetaModel::GetConfig()->Set('secure_rest_services', true, 'auth-token');
		MetaModel::GetConfig()->Set('allow_rest_services_via_tokens', true, 'auth-token');
		MetaModel::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', ['Administrator', 'Service Desk Agent']);

		MetaModel::GetConfig()->WriteToFile();
		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);

		//create admin only to read cmdbchangop
		$oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);
		$sLogin = $this->sLogin . "-Admin";
		$oAdminUser = $this->CreateContactlessUser($sLogin, $oAdminProfile->GetKey(), $this->sPassword);
		$this->oAdminToken = $this->CreatePersonalToken($oAdminUser, "ADMINACCESS");

		$oProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Service Desk Agent'), true);
		$this->sLogin = $this->sLogin . "-ServiceDeskAgent";
		$this->oUser = $this->CreateContactlessUser($this->sLogin, $oProfile->GetKey(), $this->sPassword);
		$this->oPersonalToken = $this->CreatePersonalToken($this->oUser, "RESTTEST");
	}

	public function CreatePersonalToken(\User $oUser, string $sApplication, $sScope=null) : PersonalToken{
		if (is_null($sScope)) {
			/** PersonalToken $oPersonalToken */
			$oPersonalToken = $this->createObject(PersonalToken::class, [
				'user_id' => $oUser->GetKey(),
				'application' => $sApplication,
				'scope' => \ContextTag::TAG_REST
			]);
			return $oPersonalToken;
		}
		throw \Exception("not implemented nor used yet");
	}

	private function CheckToken($oToken, $sNow, $iExpectedUsedCount){
		$oLastPersonalToken = MetaModel::GetObject(PersonalToken::class, $oToken->GetKey());
		$this->assertEquals($iExpectedUsedCount, $oLastPersonalToken->Get('use_count'));

		$sLastUseDate = $oLastPersonalToken->Get('last_use_date');
		if (is_null($sNow)){
			$this->assertEquals(null, $sLastUseDate);
		} else{
			$oDateTimeFormat = new \DateTimeFormat('Y-m-d H:i:s');
			$oLastUseDateTime = $oDateTimeFormat->Parse($sLastUseDate);
			$iRefreshExpiration = $oLastUseDateTime->format('U');

			$iNowMinusXseconds = $sNow - 60;
			$this->assertTrue(($iNowMinusXseconds < $iRefreshExpiration), "$sLastUseDate ($iRefreshExpiration) should be newer than last 60s timestamp ($iNowMinusXseconds)");
		}
	}

	protected function GetAuthToken($sContext=null){
		if ($this->bEmptyToken){
			return '';
		}

		$oReflectionClass = new \ReflectionClass(AbstractPersonalToken::class);
		$oProperty = $oReflectionClass->getProperty('sToken');
		$oProperty->setAccessible(true);

		if ('CMDBChangeOp' === $sContext || 'delete' === $sContext){
			//only admin can see CMDBChangeOp or delete UR
			$sTokenCredential = $oProperty->getValue($this->oAdminToken);
		} else {
			$sTokenCredential = $oProperty->getValue($this->oPersonalToken);
		}

		var_dump(['context' => $sContext, 'sToken' => $sTokenCredential]);
		return $sTokenCredential;
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testCreateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testCreateApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken($this->oPersonalToken, time(), 2);
		$this->CheckToken($this->oAdminToken, time(), 2);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testUpdateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testUpdateApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken($this->oPersonalToken, time(), 2);
		$this->CheckToken($this->oAdminToken, time(), 2);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testDeleteApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testDeleteApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken($this->oPersonalToken, time(), 2);
		$this->CheckToken($this->oAdminToken, time(), 1);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testApiWithExpirationTimeIntheFuture($iJsonDataMode, $bTokenInPost)
	{
		$iUnixSeconds = time() + 20;
		$sDateTime = date('Y-m-d H:i:s', $iUnixSeconds);
		$this->oPersonalToken->Set('expiration_date', $sDateTime);
		$this->oPersonalToken->DBWrite();

		parent::testCreateApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken($this->oPersonalToken, time(), 2);
		$this->CheckToken($this->oAdminToken, time(), 2);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testApiWithExpiredToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		$this->iJsonDataMode = $iJsonDataMode;

		$iUnixSeconds = time() - 20;
		$sDateTime = date('Y-m-d H:i:s', $iUnixSeconds);
		$this->oPersonalToken->Set('expiration_date', $sDateTime);
		$this->oPersonalToken->DBWrite();

		//create ticket
		$description = date('dmY H:i:s');

		$sExpectedOutput = <<<JSON
{"code":1,"message":"Error: Invalid login"}
JSON;

		$sOuputJson = $this->CreateTicketViaApi($description);
		$this->assertEquals($sExpectedOutput, $sOuputJson, "should be html login form instead of any json : " .  $sOuputJson);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testApiWithAnotherScope($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		$this->iJsonDataMode = $iJsonDataMode;

		$this->oPersonalToken->Set('scope', 'OTHERS');
		$this->oPersonalToken->DBWrite();


		//create ticket
		$description = date('dmY H:i:s');

		$sExpectedOutput = <<<JSON
{"code":1,"message":"Error: Invalid login"}
JSON;

		$sOuputJson = $this->CreateTicketViaApi($description);
		$this->assertEquals($sExpectedOutput, $sOuputJson, "should be html login form instead of any json : " .  $sOuputJson);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testApiShouldFailWithACorrectTokenAssociatedToAUserWithoutAuthorizedProfileInConf($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		$this->iJsonDataMode = $iJsonDataMode;

		MetaModel::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', ['Configuration Manager']);
		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
		MetaModel::GetConfig()->WriteToFile();
		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);

		//create ticket
		$description = date('dmY H:i:s');

		$sExpectedOutput = <<<JSON
{"code":1,"message":"Error: Invalid login"}
JSON;

		$sOuputJson = $this->CreateTicketViaApi($description);
		$this->assertEquals($sExpectedOutput, $sOuputJson, "should be html login form instead of any json : " .  $sOuputJson);
	}

	public function SynchroProvider(){
		$sSynchroExecAuthenticationOkNeedle = <<<HTML
The parameter 'data_sources' is mandatory
HTML;
		$sSynchroImportAuthenticationOkNeedle = <<<HTML
Missing argument 'data_source_id'
HTML;
		$sLoginModeNeedle = <<<HTML
<p>Invalid login</p>
HTML;

		return [
			'synchro_exec.php / authentication OK' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sNeedle' => $sSynchroExecAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_exec.php / authentication KO (json scope)' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
			'synchro_import.php / authentication OK' => [
				'sUri' => 'synchro/synchro_import.php',
				'sNeedle' => $sSynchroImportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_import.php / authentication KO (json scope)' => [
				'sUri' => 'synchro/synchro_import.php',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
		];
	}

	/**
	 * @dataProvider SynchroProvider
	 */
	public function testSynchroScript($sUri, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess, $sScope=null) {
		$sScope = (is_null($sScope)) ? \ContextTag::TAG_SYNCHRO : $sScope;
		$this->bTokenInPost = true;
		$this->iJsonDataMode = self::MODE['JSONDATA_AS_STRING'];

		if($bSetSynchroScope){
			$this->oPersonalToken->Set('scope', $sScope);
			$this->oPersonalToken->DBWrite();
		}

		$sOutput =  $this->CallRestApi(json_encode(["fake symport"]), null, $sUri);

		$this->assertTrue(false !== strpos($sOutput, $sNeedle), $sOutput);

		if($bAuthenticationSuccess){
			$this->CheckToken($this->oPersonalToken, time(), 1);
		} else {
			$this->CheckToken($this->oPersonalToken, null, 0);
		}
	}

	public function ImportProvider(){
		$sImportAuthenticationOkNeedle = <<<HTML
ERROR: Missing argument 'class'
HTML;
		$sLoginModeNeedle = <<<HTML
Invalid login
HTML;

		return [
			'import.php / authentication OK' => [
				'sUri' => 'webservices/import.php',
				'sNeedle' => $sImportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'import.php / authentication KO (json scope)' => [
				'sUri' => 'webservices/import.php',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
		];
	}
	/**
	 * @dataProvider ImportProvider
	 */
	public function testImportScript($sUri, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess) {
		$this->testSynchroScript($sUri, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess, \ContextTag::TAG_IMPORT);
	}

	public function ExportProvider(){
		$sExportv2AuthenticationOkNeedle = <<<HTML
<p>ERROR: Missing parameter. The parameter 'expression' or 'query' must be specified.</p>
HTML;

		$sExportAuthenticationOkNeedle = <<<HTML
<p>General purpose export page.</p><p>Parameters:</p><p> * expression: an OQL expression (URL encoded if needed)</p>
HTML;
		$sLoginModeNeedle = <<<HTML
<div id="login-body">
HTML;

		return [
			'export.php / authentication OK' => [
				'sUri' => 'webservices/export.php',
				'sNeedle' => $sExportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'export.php / authentication KO (json scope)' => [
				'sUri' => 'webservices/export.php',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
			'export-v2.php / authentication OK' => [
				'sUri' => 'webservices/export-v2.php',
				'sNeedle' => $sExportv2AuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'export-v2.php / authentication KO (json scope)' => [
				'sUri' => 'webservices/export-v2.php',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
		];
	}
	/**
	 * @dataProvider ExportProvider
	 */
	public function testExportScript($sUri, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess) {
		$this->testSynchroScript($sUri, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess, \ContextTag::TAG_EXPORT);
	}

	public function TokenLoginExtensionProvider(){
		$sRestOkNeedle = <<<HTML
{"code":100,"message":"Error: Missing parameter 'operation'"}
HTML;
		$sInvalidLoginNeedle = <<<HTML
{"code":1,"message":"Error: Invalid login"}
HTML;

		return [
			'rest.php / token login_mode forced and empty token / exception raised' => [
				'sLoginMode' => 'token',
				'sNeedle' => "login_mode 'token' forced without any token passed",
				'bAuthenticationSuccess' => false,
				'empty token' => true,
				'bTokenLoginModesNotConfigured' => false
			],
			'rest.php / no login_mode and empty token / login page returned for other login modes trials' => [
				'sLoginMode' => null,
				'sNeedle' => $sInvalidLoginNeedle,
				'bAuthenticationSuccess' => false,
				'empty token' => true,
				'bTokenLoginModesNotConfigured' => false
			],
			'rest.php / no login_mode passed / authentication OK' => [
				'sLoginMode' => null,
				'sNeedle' => $sRestOkNeedle,
				'bAuthenticationSuccess' => true,
				'empty token' => false,
				'bTokenLoginModesNotConfigured' => false
			],
			'rest.php / token login_mode forced / authentication OK' => [
				'sLoginMode' => 'token',
				'sNeedle' => $sRestOkNeedle,
				'bAuthenticationSuccess' => true,
				'empty token' => false,
				'bTokenLoginModesNotConfigured' => false
			],
			'rest.php / rest-token login_mode forced / authentication OK' => [
				'sLoginMode' => 'rest-token',
				'sNeedle' => $sRestOkNeedle,
				'bAuthenticationSuccess' => true,
				'empty token' => false,
				'bTokenLoginModesNotConfigured' => false
			],
			'rest.php / login_mode passed / token passed but login_modes not configured' => [
				'sLoginMode' => 'token',
				'sNeedle' => $sInvalidLoginNeedle,
				'bAuthenticationSuccess' => false,
				'empty token' => false,
				'bTokenLoginModesNotConfigured' => true
			],
			'rest.php / no login_mode / token passed but login_modes not configured / login page to let other login mode authenticate' => [
				'sLoginMode' => null,
				'sNeedle' => $sInvalidLoginNeedle,
				'bAuthenticationSuccess' => false,
				'empty token' => false,
				'bTokenLoginModesNotConfigured' => true
			],

		];
	}

	/**
	 * @dataProvider TokenLoginExtensionProvider
	 */
	public function testTokenLoginExtension($sLoginMode, $sNeedle, $bAuthenticationSuccess, $bEmptyToken, $bTokenLoginModesNotConfigured) {
		$this->bTokenInPost = true;
		$this->iJsonDataMode = self::MODE['JSONDATA_AS_STRING'];

		if ($bEmptyToken){
			$this->bEmptyToken = true;
		}

		if ($bTokenLoginModesNotConfigured) {
			$aAllowedLoginTypes = MetaModel::GetConfig()->GetAllowedLoginTypes();
			$aNewAllowedLoginTypes = [];
			$bConfigToUpdate = false;
			$oTokenLoginExtension = new TokenLoginExtension();
			foreach ($aAllowedLoginTypes as $sConfiguredLoginMode) {
				if ($oTokenLoginExtension->IsLoginModeSupported($sConfiguredLoginMode)) {
					$bConfigToUpdate=true;
				} else {
					$aNewAllowedLoginTypes []= $sConfiguredLoginMode;
				}
			}

			var_dump($aNewAllowedLoginTypes);
			if ($bConfigToUpdate){
				MetaModel::GetConfig()->SetAllowedLoginTypes($aNewAllowedLoginTypes);
				@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
				MetaModel::GetConfig()->WriteToFile();
				@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);
			}
		}

		$sUrl = "webservices/rest.php";
		if (! is_null($sLoginMode)){
			$sUrl = "$sUrl?login_mode=$sLoginMode";
		}
		$sOutput =  $this->CallRestApi(json_encode(["fake symport"]), null, $sUrl);
		var_dump($sOutput);

		$this->assertTrue(false !== strpos($sOutput, $sNeedle), $sOutput);

		if($bAuthenticationSuccess){
			$this->CheckToken($this->oPersonalToken, time(), 1);
		} else {
			$this->CheckToken($this->oPersonalToken, null, 0);
		}
	}
}
