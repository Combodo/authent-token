<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';

use MetaModel;

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

		$oRestProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'REST Services User'),
			true);

		if (is_object($this->oUser)) {
			if (is_object($oRestProfile)) {
				$this->AddProfileToUser($this->oUser, $oRestProfile->GetKey());
			} else {
				MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
				MetaModel::GetConfig()->WriteToFile();
			}
		}
	}

	protected function GetPostParameters($sContext=null){
		return [
			'version' => '1.3',
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
