<?php
namespace Combodo\iTop\Extension\AuthentToken\Test;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Exception;
use Config;
use MetaModel;
use utils;


abstract class AbstractRestTest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;

	const MODE = [ 'JSONDATA_AS_STRING' => 0, 'JSONDATA_AS_FILE' => 1 , 'NO_JSONDATA' => 2 ];

	protected $sTmpFile = "";
	/** @var int $iJsonDataMode */
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

	    $sUid = date('dmYHis');
	    $this->sLogin = "rest-user-".$sUid;
	    $this->sOrgName = "Org-$sUid";
	    $this->CreateOrganization($this->sOrgName);

	    if (!empty($this->sTmpFile)) {
		    unlink($this->sTmpFile);
	    }

		$sConfigFile = utils::GetConfig()->GetLoadedFile();
		@chmod($sConfigFile, 0770);
		$this->sUrl = MetaModel::GetConfig()->Get('app_root_url');
		@chmod($sConfigFile, 0444); // Read-only

		$oRestProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'REST Services User'), true);
		$oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);

	    if (is_object($oAdminProfile))
	    {
		    $this->oUser = $this->CreateContactlessUser($this->sLogin, $oAdminProfile->GetKey(), $this->sPassword);

		    if (is_object($oRestProfile))
		    {
			    $this->AddProfileToUser($this->oUser, $oRestProfile->GetKey());
		    } else {
			    $this->sConfigTmpBackupFile = tempnam(sys_get_temp_dir(), "config_");
			    MetaModel::GetConfig()->WriteToFile($this->sConfigTmpBackupFile);

			    MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-multi-token');
			    MetaModel::GetConfig()->WriteToFile();
		    }
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
			$oConfig = new Config($this->sConfigTmpBackupFile);
			$oConfig->WriteToFile($sConfigPath);
		}
	}

	abstract protected function CallRestApi($sJsonDataContent);

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testCreateApi($iJsonDataMode)
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
			$this->assertContains("3", "".$aJson['code'], $sOuputJson);
			$this->assertContains("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertContains('UserRequest::', $sUserRequestKey);
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

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testUpdateApi($iJsonDataMode)
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
			$this->assertContains("3", "".$aJson['code'], $sOuputJson);
			$this->assertContains("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertContains('UserRequest::', $sUserRequestKey);
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

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testDeleteApi($iJsonDataMode)
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
			$this->assertContains("3", "".$aJson['code'], $sOuputJson);
			$this->assertContains("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOuputJson);
			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOuputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOuputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertContains('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];

		//delete ticket
		$sExpectedJsonOuput=<<<JSON
{"objects":{"UserRequest::$iId"
JSON;
		$this->assertContains($sExpectedJsonOuput, $this->DeleteTicketFromApi($iId));

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

	public function BasicProvider(){
		return [
			'call rest call' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_STRING']],
			'pass json_data as file' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_FILE']],
			'no json data' => [ 'sJsonDataMode' => self::MODE['NO_JSONDATA']]
		];
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
		return $this->CallRestApi($sJson);

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
		$sOutput = $this->CallRestApi($sJsonGetContent);
		$aJson = json_decode($sOutput, true);
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
