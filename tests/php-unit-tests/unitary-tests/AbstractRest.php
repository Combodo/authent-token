<?php

namespace Combodo\iTop\AuthentToken\Test;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Config;
use Exception;
use MetaModel;


abstract class AbstractRest extends ItopDataTestCase
{
	const USE_TRANSACTION = false;

	const MODE = ['JSONDATA_AS_STRING' => 0, 'JSONDATA_AS_FILE' => 1, 'NO_JSONDATA' => 2];

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
		echo sprintf("\nrights via ls on %s:\n %s \n", $sConfigPath, exec("ls -al $sConfigPath"));
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
}

	/**
	 * @throws Exception
	 */
	protected function tearDown(): void
	{
		parent::tearDown();

		if (!is_null($this->sConfigTmpBackupFile) && is_file($this->sConfigTmpBackupFile)) {
			//put config back
			$sConfigPath = MetaModel::GetConfig()->GetLoadedFile();
			@chmod($sConfigPath, 0770);
			$oConfig = new Config($this->sConfigTmpBackupFile);
			$oConfig->WriteToFile($sConfigPath);
			@chmod($sConfigPath, 0440);
		}
	}

	abstract protected function GetPostParameters($sContext = null);

	protected function GetHeadersParam($sContext = null)
	{
		return [];
	}

	protected function CallRestApi($sJsonDataContent, $sContext = null, $sUri = 'webservices/rest.php')
	{
		$ch = curl_init();
		$aPostFields = $this->GetPostParameters($sContext);
		var_dump($aPostFields);

		if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_STRING']) {
			$this->sTmpFile = tempnam(sys_get_temp_dir(), 'jsondata_');
			file_put_contents($this->sTmpFile, $sJsonDataContent);

			$oCurlFile = curl_file_create($this->sTmpFile);
			$aPostFields['json_data'] = $oCurlFile;
		} else {
			if ($this->iJsonDataMode === self::MODE['JSONDATA_AS_FILE']) {
				$aPostFields['json_data'] = $sJsonDataContent;
			}
		}

		//curl_setopt($ch, CURLOPT_COOKIE, "XDEBUG_SESSION=phpstorm");

		curl_setopt($ch, CURLOPT_HTTPHEADER, $this->GetHeadersParam($sContext));
		curl_setopt($ch, CURLOPT_URL, "$this->sUrl/$sUri");
		curl_setopt($ch, CURLOPT_POST, 1);// set post data to true
		curl_setopt($ch, CURLOPT_POSTFIELDS, $aPostFields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		$sJson = curl_exec($ch);
		if (curl_errno($ch)) {
			echo 'Curl error: '.curl_error($ch);
		}
		curl_close($ch);

		return $sJson;
	}

	/**
	 * array_key_first comes with PHP7.3
	 * itop should also work with previous PHP versions
	 */
	private function array_key_first($aTab)
	{
		if (!is_array($aTab) || empty($aTab)) {
			return false;
		}

		foreach ($aTab as $sKey => $sVal) {
			return $sKey;
		}

		return false;
	}


	public function CreateApiTest($iJsonDataMode)
	{
		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOutputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOutputJson, true);
		if (is_null($aJson)) {
			var_dump($sOutputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']) {
			$this->assertStringContainsString("3", "".$aJson['code'], $sOutputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOutputJson);

			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOutputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOutputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];
		$sExpectedJsonOutput = <<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"created","class":"UserRequest","key":"$iId","fields":{"id":"$iId"}}},"code":0,"message":null}
JSON;

		$this->ValidateJsonAreTheSameEvenInOtherOrders($sExpectedJsonOutput, $sOutputJson);

		$sExpectedJsonOutput = <<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"","class":"UserRequest","key":"$iId","fields":{"id":"$iId","description":"<p>$description<\/p>"}}},"code":0,"message":"Found: 1"}
JSON;
		$this->ValidateJsonAreTheSameEvenInOtherOrders($sExpectedJsonOutput, $this->GetTicketViaRest($iId));

		$aCmdbChangeUserInfo = $this->GetCmdbChangeUserInfo($iId);
		var_dump($aCmdbChangeUserInfo);
		$this->assertEquals(['CMDBChangeOpCreate' => 'test'], $aCmdbChangeUserInfo);

		//delete ticket
		$this->DeleteTicketFromApi($iId);
	}

	protected function ReOrderJsonFields(string $sJson): string
	{
		$aJson = json_decode($sJson, true);
		ksort($aJson);

		return json_encode($aJson);
	}

	protected function ValidateJsonAreTheSameEvenInOtherOrders(string $sExpectedJson, string $sJson)
	{
		$this->assertEquals($this->ReOrderJsonFields($sExpectedJson), $this->ReOrderJsonFields($sJson));
	}

	public function UpdateApiTest($iJsonDataMode)
	{
		$this->iJsonDataMode = $iJsonDataMode;

		//create ticket
		$description = date('dmY H:i:s');

		$sOutputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOutputJson, true);
		if (is_null($aJson)) {
			var_dump($sOutputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']) {
			$this->assertStringContainsString("3", "".$aJson['code'], $sOutputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOutputJson);

			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOutputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOutputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];

		//update ticket
		$description = date('Ymd H:i:s');
		$sExpectedJsonOutput = <<<JSON
{"objects":{"UserRequest::$iId":{"code":0,"message":"updated","class":"UserRequest","key":"$iId","fields":{"description":"<p>$description<\/p>"}}},"code":0,"message":null}
JSON;
		$this->ValidateJsonAreTheSameEvenInOtherOrders($sExpectedJsonOutput, $this->UpdateTicketViaApi($iId, $description));

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

		$sOutputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOutputJson, true);
		if (is_null($aJson)) {
			var_dump($sOutputJson);
			throw new \Exception("Not a json output. this is surely the login html form.");
		}

		if ($this->iJsonDataMode === self::MODE['NO_JSONDATA']) {
			$this->assertStringContainsString("3", "".$aJson['code'], $sOutputJson);
			$this->assertStringContainsString("Error: Missing parameter 'json_data'", "".$aJson['message'], $sOutputJson);

			return;
		}

		$this->assertEquals("0", "".$aJson['code'], $sOutputJson);
		$this->assertTrue(array_key_exists('objects', $aJson), $sOutputJson);
		$sUserRequestKey = $this->array_key_first($aJson['objects']);
		$this->assertStringContainsString('UserRequest::', $sUserRequestKey);
		$iId = $aJson['objects'][$sUserRequestKey]['key'];

		//delete ticket
		$sExpectedJsonOutput = <<<JSON
"objects":{"UserRequest::$iId"
JSON;
		$this->assertStringContainsString($sExpectedJsonOutput, $this->DeleteTicketFromApi($iId));

		$sExpectedJsonOutput = <<<JSON
{"objects":null,"code":0,"message":"Found: 0"}
JSON;
		$this->ValidateJsonAreTheSameEvenInOtherOrders($sExpectedJsonOutput, $this->GetTicketViaRest($iId));
	}

	private function GetTicketViaRest($iId)
	{
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

	private function UpdateTicketViaApi($iId, $description)
	{
		$sJsonUpdateContent = <<<JSON
{"operation": "core/update","comment": "test","class": "UserRequest","key":"$iId","output_fields": "description","fields":{"description": "$description"}}
JSON;

		return $this->CallRestApi($sJsonUpdateContent);
	}

	protected function CreateTicketViaApi($description)
	{
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

	private function DeleteTicketFromApi($iId)
	{
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
	 *
	 * @return array
	 */
	private function GetCmdbChangeUserInfo($iId)
	{
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
		if (is_array($aJson) && array_key_exists('objects', $aJson)) {
			$aObjects = $aJson['objects'];
			if (!empty($aObjects)) {
				foreach ($aObjects as $aObject) {
					$sClass = $aObject['class'];
					$sUserInfo = $aObject['fields']['userinfo'];
					$aUserInfo[$sClass] = $sUserInfo;
				}
			}
		}

		return $aUserInfo;
	}
}
