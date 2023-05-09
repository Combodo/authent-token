<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';

use Exception;
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
abstract class AbstractTokenRestTest extends AbstractRestTest
{
	const USE_TRANSACTION = false;

	protected $bTokenInPost;
	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
	    @require_once(APPROOT . 'env-production/authent-token/vendor/autoload.php');
	}

	protected function InitLoginMode($sLoginMode){
		$aAllowedLoginTypes = MetaModel::GetConfig()->GetAllowedLoginTypes();
		if (! in_array($sLoginMode, $aAllowedLoginTypes)){
			$aAllowedLoginTypes[] = $sLoginMode;
			MetaModel::GetConfig()->SetAllowedLoginTypes($aAllowedLoginTypes);
			MetaModel::GetConfig()->WriteToFile();
		}
	}

	public function BasicTokenProvider(){
		return [
			'pass json_data as file/ token in POST' => [
				'sJsonDataMode' => self::MODE['JSONDATA_AS_STRING'],
				'tokenInPost' => true,
			],
			'pass json_data as file/ token in header' => [
				'sJsonDataMode' => self::MODE['JSONDATA_AS_STRING'],
				'tokenInPost' => false,
			],
		];
	}

	abstract protected function GetAuthToken($sContext=null);

	protected function GetPostParameters($sContext=null){
		$aParams = [
			'version' => '1.3',
		];

		if ($this->bTokenInPost) {
			$aParams ['auth_token'] = $this->GetAuthToken($sContext);
		}

		return $aParams;
	}

	protected function GetHeadersParam($sContext=null){
		if ($this->bTokenInPost) {
			return [];
		}

		return [
			//'Content-Type: application/x-www-form-urlencoded',
			"Auth-Token: " . $this->GetAuthToken($sContext),
		];
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testCreateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		parent::CreateApiTest($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testUpdateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		parent::UpdateApiTest($iJsonDataMode);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testDeleteApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		parent::DeleteApiTest($iJsonDataMode);
	}
}
