<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
require_once __DIR__.'/AbstractTokenRestTest.php';

use AbstractPersonalToken;
use AttributeDateTime;
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

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();

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
			$iRefreshExpiration = AttributeDateTime::GetAsUnixSeconds($sLastUseDate);
			$iNowMinusXseconds = $sNow - 60;
			$this->assertTrue(($iNowMinusXseconds < $iRefreshExpiration), "$sLastUseDate ($iRefreshExpiration) should be newer than last 60s timestamp ($iNowMinusXseconds)");
		}
	}

	protected function GetAuthToken($sContext=null){
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
		$sDateTime = AttributeDateTime::GetFormat()->Format($iUnixSeconds);
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
		$sDateTime = AttributeDateTime::GetFormat()->Format($iUnixSeconds);
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
<div id="login-body">
HTML;

		return [
			'synchro_exec.php / no login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sLoginMode' => null,
				'sNeedle' => $sSynchroExecAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_exec.php / token login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sLoginMode' => 'token',
				'sNeedle' => $sSynchroExecAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_exec.php / rest-token login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sLoginMode' => 'rest-token',
				'sNeedle' => $sSynchroExecAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_exec.php / no login_mode / authentication KO (json scope)' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sLoginMode' => null,
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
			/*'synchro_exec.php / form login_mode / authentication KO ' => [
				'sUri' => 'synchro/synchro_exec.php',
				'sLoginMode' => 'form',
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => false,
			],*/
			'synchro_import.php / no login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_import.php',
				'sLoginMode' => null,
				'sNeedle' => $sSynchroImportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_import.php / token login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_import.php',
				'sLoginMode' => 'token',
				'sNeedle' => $sSynchroImportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_import.php / rest-token login_mode / authentication OK' => [
				'sUri' => 'synchro/synchro_import.php',
				'sLoginMode' => 'rest-token',
				'sNeedle' => $sSynchroImportAuthenticationOkNeedle,
				'bSetSynchroScope' => true,
				'bAuthenticationSuccess' => true,
			],
			'synchro_import.php / no login_mode / authentication KO (json scope)' => [
				'sUri' => 'synchro/synchro_import.php',
				'sLoginMode' => null,
				'sNeedle' => $sLoginModeNeedle,
				'bSetSynchroScope' => false,
				'bAuthenticationSuccess' => false,
			],
		];
	}

	/**
	 * @dataProvider SynchroProvider
	 */
	public function testSynchroScript($sUri, $sLoginMode, $sNeedle, $bSetSynchroScope, $bAuthenticationSuccess) {
		$this->bTokenInPost = true;
		$this->iJsonDataMode = self::MODE['JSONDATA_AS_STRING'];

		if($bSetSynchroScope){
			$this->oPersonalToken->Set('scope', \ContextTag::TAG_SYNCHRO);
			$this->oPersonalToken->DBWrite();
		}

		if (is_null($sLoginMode)){
			$sUrl = $sUri;
		} else {
			$sUrl = "$sUri?login_mode=$sLoginMode";
		}
		$sOutput =  $this->CallRestApi(json_encode(["fake symport"]), null, $sUrl);

		$this->assertTrue(false !== strpos($sOutput, $sNeedle), $sOutput);

		if($bAuthenticationSuccess){
			$this->CheckToken($this->oPersonalToken, time(), 1);
		} else {
			$this->CheckToken($this->oPersonalToken, null, 0);
		}
	}
}
