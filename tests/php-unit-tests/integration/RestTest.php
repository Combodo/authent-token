<?php
namespace Combodo\iTop\AuthentToken\Test\integration;

require_once __DIR__.'/AbstractRestTest.php';

use Combodo\iTop\AuthentToken\Test\Exception;
use MetaModel;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;


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
	/**
	 * @throws Exception
	 */
	protected function setUp(): void {
		parent::setUp();


		clearstatcache();

		/** @var \User oUser */
		$this->oUser = $this->CreateContactlessUser($this->sLogin,
			ItopDataTestCase::$aURP_Profiles['Administrator'],
			$this->sPassword
		);

		$this->AddProfileToUser($this->oUser, ItopDataTestCase::$aURP_Profiles['REST Services User']);
	}

	protected function GetPostParameters($sContext=null){
		return [
			'auth_user' => $this->sLogin,
			'auth_pwd' => $this->sPassword,
		];
	}

	public function BasicProvider(){
		return [
			'call rest call' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_STRING']],
			'pass json_data as file' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_FILE']],
			'no json data' => [ 'sJsonDataMode' => self::MODE['NO_JSONDATA']]
		];
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testCreateApiTest($iJsonDataMode)
	{
		$this->CreateApiTest($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testUpdateApi($iJsonDataMode)
	{
		$this->UpdateApiTest($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testDeleteApi($iJsonDataMode)
	{
		$this->DeleteApiTest($iJsonDataMode);
	}
}
