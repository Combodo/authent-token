<?php
namespace Combodo\iTop\Extension\Test;

use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Exception;
require_once __DIR__.'/AbstractRestTest.php';

/**
 * @group itopRequestMgmt
 * @group multiTokenRestApi
 * @group defaultProfiles
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 * @backupGlobals disabled
 */
class RestTest extends AbstractRestTest
{
	protected function CallRestApi($sJsonDataContent){
		$ch = curl_init();
		$aPostFields = [
			'version' => '1.3',
			'auth_user' => $this->sLogin,
			'auth_pwd' => $this->sPassword,
		];

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
}
