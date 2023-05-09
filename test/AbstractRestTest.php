<?php
namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Config;
use Exception;
use MetaModel;


abstract class AbstractRestTest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;

	const MODE = [ 'JSONDATA_AS_STRING' => 0, 'JSONDATA_AS_FILE' => 1 , 'NO_JSONDATA' => 2 ];

	protected $sTmpFile = "";
	/** @var int $iJsonDataMode */
	protected $iJsonDataMode;
	protected $sJsonDataMode;
	protected $sUrl;
	protected $sLogin;
	protected $sPassword = "Iuytrez9876543ç_è-(";
	protected $sConfigTmpBackupFile;
	protected $oUser;
	protected $sOrgName;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();

	    $sConfigPath = MetaModel::GetConfig()->GetLoadedFile();

	    clearstatcache();
	    echo sprintf("rights via ls on %s:\n %s \n", $sConfigPath, exec("ls -al $sConfigPath"));
	    $sFilePermOutput = substr(sprintf('%o', fileperms('/etc/passwd')), -4);
	    echo sprintf("rights via fileperms on %s:\n %s \n", $sConfigPath, $sFilePermOutput);

	    $sUid = date('dmYHis');
	    $this->sLogin = "rest-user-".$sUid;
	    $this->sOrgName = "Org-$sUid";
	    $this->CreateOrganization($this->sOrgName);

	    if (0 !== strlen($this->sTmpFile)) {
		    unlink($this->sTmpFile);
	    }

		$this->sUrl = MetaModel::GetConfig()->Get('app_root_url');

	    $this->sConfigTmpBackupFile = tempnam(sys_get_temp_dir(), "config_");
	    MetaModel::GetConfig()->WriteToFile($this->sConfigTmpBackupFile);

	    $oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);

	    if (is_object($oAdminProfile)) {
		    $this->oUser = $this->CreateContactlessUser($this->sLogin, $oAdminProfile->GetKey(), $this->sPassword);
	    }
	}

	/**
	 * @throws Exception
	 */
	protected function tearDown(): void {
		parent::tearDown();

		if (! is_null($this->sConfigTmpBackupFile) && is_file($this->sConfigTmpBackupFile)){
			//put config back
			$sConfigPath = MetaModel::GetConfig()->GetLoadedFile();
			@chmod($sConfigPath, 0770);
			$oConfig = new Config($this->sConfigTmpBackupFile);
			$oConfig->WriteToFile($sConfigPath);
			@chmod($sConfigPath, 0440);
		}
	}

	abstract protected function GetPostParameters($sContext=null);

	protected function GetHeadersParam($sContext=null){
		return [];
	}

	protected function CallRestApi($sJsonDataContent, $sContext=null, $sUri='webservices/rest.php'){
		$ch = curl_init();
		$aPostFields = $this->GetPostParameters($sContext);
		var_dump($aPostFields);

		if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_STRING']){
			$this->sTmpFile = tempnam(sys_get_temp_dir(), 'jsondata_');
			file_put_contents($this->sTmpFile, $sJsonDataContent);

			$oCurlFile = curl_file_create($this->sTmpFile);
			$aPostFields['json_data'] = $oCurlFile;
		}else if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_FILE']){
			$aPostFields['json_data'] = $sJsonDataContent;
		}

		//curl_setopt($ch, CURLOPT_COOKIE, "XDEBUG_SESSION=phpstorm");

		curl_setopt($ch, CURLOPT_HTTPHEADER, $this->GetHeadersParam($sContext));
		curl_setopt($ch, CURLOPT_URL, "$this->sUrl/$sUri");
		curl_setopt($ch, CURLOPT_POST, 1);// set post data to true
		curl_setopt($ch, CURLOPT_POSTFIELDS, $aPostFields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$sJson = curl_exec($ch);
		curl_close ($ch);

		return $sJson;
	}

	/**
	 * array_key_first comes with PHP7.3
	 * itop should also work with previous PHP versions
	 */
	private function array_key_first($aTab){
		if (!is_array($aTab) || empty($aTab)){
			return false;
		}

		foreach ($aTab as $sKey => $sVal){
			return $sKey;
		}
	}


	public function CreateApiTest($iJsonDataMode)
	{
		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		if (is_null($aJson)){
			var_dump($sOuputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']){
			$this->assertStringContainsString("3", "".$aJson['code'], $sOuputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];
		$sExpectedJsonOuput=<<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"created","class":"UserRequest","key":"$iId","fields":{"id":"$iId"}}},"code":0,"message":null}
JSON;
		$this->assertEquals($sExpectedJsonOuput, $sOuputJson);

		$sExpectedJsonOuput=<<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"","class":"UserRequest","key":"$iId","fields":{"id":"$iId","description":"<p>$description<\/p>"}}},"code":0,"message":"Found: 1"}
JSON;
		$this->assertEquals($sExpectedJsonOuput, $this->GetTicketViaRest($iId));

		$aCmdbChangeUserInfo = $this->GetCmdbChangeUserInfo($iId);
		var_dump($aCmdbChangeUserInfo);
		$this->assertEquals(['CMDBChangeOpCreate' => 'test'], $aCmdbChangeUserInfo);

		//delete ticket
		$this->DeleteTicketFromApi($iId);
	}

	public function UpdateApiTest($iJsonDataMode)
	{
		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		if (is_null($aJson)){
			var_dump($sOuputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']){
			$this->assertStringContainsString("3", "".$aJson['code'], $sOuputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];

		//update ticket
		$description = date('Ymd H:i:s');
		$sExpectedJsonOuput=<<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"updated","class":"UserRequest","key":"$iId","fields":{"description":"<p>$description<\/p>"}}},"code":0,"message":null}
JSON;
		$this->assertEquals($sExpectedJsonOuput, $this->UpdateTicketViaApi($iId, $description));

		$aCmdbChangeUserInfo = $this->GetCmdbChangeUserInfo($iId);
		var_dump($aCmdbChangeUserInfo);
		$this->assertEquals(['CMDBChangeOpCreate' => 'test', 'CMDBChangeOpSetAttributeHTML' => 'test'], $aCmdbChangeUserInfo);


		//delete ticket
		$this->DeleteTicketFromApi($iId);
	}

	public function DeleteApiTest($iJsonDataMode)
	{
		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		if (is_null($aJson)){
			var_dump($sOuputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']){
			$this->assertStringContainsString("3", "".$aJson['code'], $sOuputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];

		//delete ticket
		$sExpectedJsonOuput=<<<JSON
{"objects":{"UserRequest::$iId"
JSON;
		$this->assertStringContainsString($sExpectedJsonOuput, $this->DeleteTicketFromApi($iId));

		$sExpectedJsonOuput=<<<JSON
{"objects":null,"code":0,"message":"Found: 0"}
JSON;
		$this->assertEquals($sExpectedJsonOuput, $this->GetTicketViaRest($iId));
	}

	private function GetTicketViaRest($iId){
		$sJsonGetContent = <<<JSON
{
   "operation": "core/get",
   "class": "UserRequest",
   "key": "SELECT UserRequest WHERE id=$iId",
   "output_fields": "id, description"
}
JSON;

		return $this->CallRestApi($sJsonGetContent);
	}

	private function UpdateTicketViaApi($iId, $description){
		$sJsonUpdateContent = <<<JSON
{"operation": "core/update","comment": "test","class": "UserRequest","key":"$iId","output_fields": "description","fields":{"description": "$description"}}
JSON;

		return $this->CallRestApi($sJsonUpdateContent);
	}

	protected function CreateTicketViaApi($description){
		$sJsonCreateContent = <<<JSON
{
   "operation": "core/create",
   "comment": "test",
   "class": "UserRequest",
   "output_fields": "id",
   "fields":
   {
      "org_id": "SELECT Organization WHERE name = \"$this->sOrgName\"",
      
      "title": "Houston, got a problem",
      "description": "$description"
   }
}
JSON;

		return $this->CallRestApi($sJsonCreateContent);
	}

	private function DeleteTicketFromApi($iId){
    	$sJson = <<<JSON
{
   "operation": "core/delete",
   "comment": "Cleanup",
   "class": "UserRequest",
   "key":$iId,
   "simulate": false
}
JSON;
		return $this->CallRestApi($sJson, 'delete');

	}

	/**
	 * @param $iId
	 * Get CMDBChangeOp info to test
	 * @return array
	 */
	private function GetCmdbChangeUserInfo($iId){
		$sJsonGetContent = <<<JSON
{
   "operation": "core/get",
   "class": "CMDBChangeOp",
   "key": "SELECT CMDBChangeOp WHERE objclass='UserRequest' AND objkey=$iId",
   "output_fields": "userinfo"
}
JSON;

		$aUserInfo = [];
		$sOutput = $this->CallRestApi($sJsonGetContent, 'CMDBChangeOp');
		$aJson = json_decode($sOutput, true);
		var_dump($aJson);
		if (is_array($aJson) && array_key_exists('objects', $aJson)){
			$aObjects = $aJson['objects'];
			if (!empty($aObjects)){
				foreach ($aObjects as $aObject){
					$sClass = $aObject['class'];
					$sUserInfo = $aObject['fields']['userinfo'];
					$aUserInfo[$sClass] = $sUserInfo;
				}
			}
		}
		return $aUserInfo;
	}
}
