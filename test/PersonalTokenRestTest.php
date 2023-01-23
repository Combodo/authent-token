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
			    'scope' => 'REST/JSON'
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
	public function testApiWithExpiredToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		$this->iJsonDataMode = $iJsonDataMode;

		$this->oPersonalToken->Set('expiration_date', time() - 1);
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
}
