<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
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
class PersonalTokenRestTest extends AbstractRestTest
{
	const USE_TRANSACTION = false;

	protected $oPersonalToken;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
	    @require_once(APPROOT . 'env-production/authent-token/vendor/autoload.php');

	    $this->CreatePersonalToken("RESTTEST");

	    $aAllowedLoginTypes = MetaModel::GetConfig()->GetAllowedLoginTypes();
	    if (! in_array(TokenLoginExtension::LOGIN_TYPE, $aAllowedLoginTypes)){
		    $aAllowedLoginTypes[] = TokenLoginExtension::LOGIN_TYPE;
		    MetaModel::GetConfig()->SetAllowedLoginTypes($aAllowedLoginTypes);
		    MetaModel::GetConfig()->WriteToFile();
	    }
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

	public function BasicProvider(){
		return [
			'pass json_data as file' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_FILE']],
		];
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

	private function GetAuthToken(){
		$oReflectionClass = new \ReflectionClass("PersonalToken");
		$oProperty = $oReflectionClass->getProperty('sToken');
		$oProperty->setAccessible(true);

		var_dump(['sToken' => $oProperty->getValue($this->oPersonalToken)]);
		return $oProperty->getValue($this->oPersonalToken);
	}

	protected function GetPostParameters(){
		return [
			'version' => '1.3',
			'auth_token' => $this->GetAuthToken(),
		];
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testCreateApi($iJsonDataMode)
	{
		parent::testCreateApi($iJsonDataMode);
		$this->CheckToken(time(), 4);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testUpdateApi($iJsonDataMode)
	{
		parent::testUpdateApi($iJsonDataMode);
		$this->CheckToken(time(), 4);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testDeleteApi($iJsonDataMode)
	{
		parent::testDeleteApi($iJsonDataMode);
		$this->CheckToken(time(), 3);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testApiWithExpiredToken($iJsonDataMode)
	{
		$this->oPersonalToken->Set('expiration_date', time() - 1);
		$this->oPersonalToken->DBWrite();

		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		$this->assertTrue(is_null($aJson), "should be html login form instead of any json : " .  $sOuputJson);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testApiWithAnotherScope($iJsonDataMode)
	{
		$this->oPersonalToken->Set('scope', 'OTHERS');
		$this->oPersonalToken->DBWrite();

		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		$this->assertTrue(is_null($aJson), "should be html login form instead of any json : " .  $sOuputJson);
	}
}
