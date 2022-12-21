<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
require_once __DIR__.'/AbstractTokenRestTest.php';

use AbstractPersonalToken;
use AttributeDateTime;
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

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();

	    $this->InitLoginMode(TokenLoginExtension::LOGIN_TYPE);

	    $this->CreatePersonalToken("RESTTEST");
	}

	public function CreatePersonalToken(string $sApplication, $sScope=null){
    	if (is_null($sScope)) {
		    $this->oPersonalToken = $this->createObject(PersonalToken::class, [
			    'user_id' => $this->oUser->GetKey(),
			    'application' => $sApplication,
			    'scope' => 'REST/JSON'
		    ]);
	    }
	}



	private function CheckToken($sNow, $iExpectedUsedCount){
		$oLastPersonalToken = MetaModel::GetObject(PersonalToken::class, $this->oPersonalToken->GetKey());
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

	protected function GetAuthToken(){
		$oReflectionClass = new \ReflectionClass(AbstractPersonalToken::class);
		$oProperty = $oReflectionClass->getProperty('sToken');
		$oProperty->setAccessible(true);

		var_dump(['sToken' => $oProperty->getValue($this->oPersonalToken)]);
		return $oProperty->getValue($this->oPersonalToken);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testCreateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testCreateApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken(time(), 4);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testUpdateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testUpdateApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken(time(), 4);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testDeleteApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		parent::testDeleteApiViaToken($iJsonDataMode, $bTokenInPost);
		$this->CheckToken(time(), 3);
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
}
