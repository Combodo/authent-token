<?php
namespace Combodo\iTop\AuthentToken\Test;

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
	protected function GetPostParameters(){
		return [
			'version' => '1.3',
			'auth_user' => $this->sLogin,
			'auth_pwd' => $this->sPassword,
		];
	}
}
