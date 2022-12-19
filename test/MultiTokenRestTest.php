<?php
namespace Combodo\iTop\Extension\Test;

require_once __DIR__.'/AbstractRestTest.php';
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Exception;
use MetaModel;
use AttributeDateTime;
use Combodo\iTop\Extension\Service\TokenLoginExtension;


/**
 * @group itopRequestMgmt
 * @group multiTokenRestApi
 * @group defaultProfiles
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 * @backupGlobals disabled
 */
class MultiTokenRestTest extends AbstractRestTest
{
	protected $oPersonalToken;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
	    @require_once(APPROOT . 'env-production/authent-multi-token/vendor/autoload.php');

	    $this->CreateUserToken("RESTTEST");

	    $aAllowedLoginTypes = MetaModel::GetConfig()->GetAllowedLoginTypes();
	    if (! in_array(TokenLoginExtension::LOGIN_TYPE, $aAllowedLoginTypes)){
		    $aAllowedLoginTypes[] = TokenLoginExtension::LOGIN_TYPE;
		    MetaModel::GetConfig()->SetAllowedLoginTypes($aAllowedLoginTypes);
		    MetaModel::GetConfig()->WriteToFile();
	    }
	}

	public function CreateUserToken(string $sApplication, $sScope=null){
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
			'call rest call' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_STRING']],
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
		return $oProperty->getValue($this->oPersonalToken);
	}

	protected function CallRestApi($sJsonDataContent){
    	$aJson = json_decode($sJsonDataContent, true);
    	if (! is_null($aJson) && array_key_exists('operation', $aJson)){
		    echo "call api " . $aJson['operation'] . ' \n';
	    } else {
		    echo "call api \n";
	    }
		$ch = curl_init();
		$aPostFields = [
			'version' => '1.3',
			'auth_token' => $this->GetAuthToken(),
		];
		//curl_setopt($ch, CURLOPT_COOKIE, "XDEBUG_SESSION=phpstorm");

		if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_STRING']){
			$this->sTmpFile = tempnam(sys_get_temp_dir(), 'jsondata_');
			file_put_contents($this->sTmpFile, $sJsonDataContent);

			$oCurlFile = curl_file_create($this->sTmpFile);
			$aPostFields['json_data'] = $oCurlFile;
		}else if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_FILE']){
			$aPostFields['json_data'] = $sJsonDataContent;
		}

		curl_setopt($ch, CURLOPT_URL, "$this->sUrl/webservices/rest.php");
		curl_setopt($ch, CURLOPT_POST, 1);// set post data to true
		curl_setopt($ch, CURLOPT_POSTFIELDS, $aPostFields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$sJson = curl_exec($ch);
		curl_close ($ch);
		return $sJson;
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
