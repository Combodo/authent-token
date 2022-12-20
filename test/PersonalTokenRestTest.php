<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
require_once __DIR__.'/AbstractTokenRestTest.php';
use Exception;
use MetaModel;
use AttributeDateTime;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;


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
		    $this->oPersonalToken = $this->createObject('PersonalToken', [
			    'user_id' => $this->oUser->GetKey(),
			    'application' => $sApplication,
			    'scope' => 'WEBSERVICE'
		    ]);
	    }
	}



	private function CheckToken($sNow, $iExpectedUsedCount){
		$oLastPersonalToken = MetaModel::GetObject("PersonalToken", $this->oPersonalToken->GetKey());
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
		$oReflectionClass = new \ReflectionClass("PersonalToken");
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

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		$this->assertTrue(is_null($aJson), "should be html login form instead of any json : " .  $sOuputJson);
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

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		$this->assertTrue(is_null($aJson), "should be html login form instead of any json : " .  $sOuputJson);
	}

	/**
	 * @dataProvider BasicProvider
	 */
	public function testCreateApi($iJsonDataMode)
	{
		$this->markTestSkipped('');
	}

	/**
	 * @dataProvider BasicProvider
	 */
	public function testUpdateApi($iJsonDataMode)
	{
		$this->markTestSkipped('');
	}

	/**
	 * @dataProvider BasicProvider
	 */
	public function testDeleteApi($iJsonDataMode)
	{
		$this->markTestSkipped('');
	}
}
