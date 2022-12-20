<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
use Exception;
use MetaModel;
use URP_UserProfile;
use DBObjectSet;


/**
 * @mark
 * @group itopRequestMgmt
 * @group multiTokenRestApi
 * @group defaultProfiles
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 * @backupGlobals disabled
 */
class ApplicationTokenRestTest extends AbstractRestTest
{
	protected $oApplicationToken;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
	    @require_once(APPROOT . 'env-production/authent-token/vendor/autoload.php');

	    $oRestProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'REST Services User'), true);
	    $oAdminProfile = MetaModel::GetObjectFromOQL("SELECT URP_Profiles WHERE name = :name", array('name' => 'Administrator'), true);

	    if (is_object($oAdminProfile))
	    {
		    $oUserProfile = new URP_UserProfile();
		    $oUserProfile->Set('profileid', $oAdminProfile->GetKey());
		    $oUserProfile->Set('reason', 'UNIT Tests');
		    $oSet = DBObjectSet::FromObject($oUserProfile);

		    $this->sLogin = uniqid('applicationtoken_',  true);

		    /** @var \UserLocal $oUser */
		    $this->oApplicationToken = $this->createObject('UserToken', array(
			    'login' => $this->sLogin,
			    'language' => 'EN US',
			    'profile_list' => $oSet,
		    ));
		    $this->debug("Created {$this->oApplicationToken->GetName()} ({$this->oApplicationToken->GetKey()})");

		    if (is_object($oRestProfile))
		    {
			    $this->AddProfileToUser($this->oApplicationToken, $oRestProfile->GetKey());
		    } else {
			    $this->sConfigTmpBackupFile = tempnam(sys_get_temp_dir(), "config_");
			    MetaModel::GetConfig()->WriteToFile($this->sConfigTmpBackupFile);

			    MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-multi-token');
			    MetaModel::GetConfig()->WriteToFile();
		    }
	    }
	}

	public function BasicProvider(){
		return [
			'pass json_data as file' => [ 'sJsonDataMode' => self::MODE['JSONDATA_AS_FILE']],
		];
	}

	private function GetAuthToken(){
		$oReflectionClass = new \ReflectionClass("_UserToken");
		$oProperty = $oReflectionClass->getProperty('sToken');
		$oProperty->setAccessible(true);
		return $oProperty->getValue($this->oApplicationToken);
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
		$this->markTestSkipped('for now');
		parent::testCreateApi($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testUpdateApi($iJsonDataMode)
	{
		$this->markTestSkipped('for now');
		parent::testUpdateApi($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicProvider
	 * @param int $iJsonDataMode
	 */
	public function testDeleteApi($iJsonDataMode)
	{
		$this->markTestSkipped('for now');
		parent::testDeleteApi($iJsonDataMode);
	}
}
