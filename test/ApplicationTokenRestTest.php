<?php
namespace Combodo\iTop\AuthentToken\Test;

require_once __DIR__.'/AbstractRestTest.php';
require_once __DIR__.'/AbstractTokenRestTest.php';

use AbstractApplicationToken;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use DBObjectSet;
use Exception;
use MetaModel;
use URP_UserProfile;
use UserToken;


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
class ApplicationTokenRestTest extends AbstractTokenRestTest
{
	protected $oApplicationToken;
	protected $sToken;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
	    @require_once(APPROOT . 'env-production/authent-token/vendor/autoload.php');

	    @chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
	    $this->InitLoginMode(TokenLoginExtension::LEGACY_LOGIN_TYPE);

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
		    $this->oApplicationToken = $this->createObject(UserToken::class, array(
			    'login' => $this->sLogin,
			    'language' => 'EN US',
			    'profile_list' => $oSet,
		    ));
		    $this->debug("Created {$this->oApplicationToken->GetName()} ({$this->oApplicationToken->GetKey()})");

		    if (is_object($oRestProfile))
		    {
			    $this->AddProfileToUser($this->oApplicationToken, $oRestProfile->GetKey());
		    } else {
			    MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
			    MetaModel::GetConfig()->WriteToFile();
		    }
	    }
	    @chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);

	    $oReflectionClass = new \ReflectionClass(AbstractApplicationToken::class);
	    $oProperty = $oReflectionClass->getProperty('sToken');
	    $oProperty->setAccessible(true);
	    $this->sToken = $oProperty->getValue($this->oApplicationToken);
	}

	protected function GetAuthToken(){
		return $this->sToken;
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testApiViaLegacyToken($iJsonDataMode, $bTokenInPost)
	{
		$this->bTokenInPost = $bTokenInPost;
		$this->iJsonDataMode = $iJsonDataMode;

		$oService = new AuthentTokenService();
		$this->sToken = bin2hex(random_bytes(16));
		$oPassword = $oService->CreatePassword($this->sToken);
		$this->oApplicationToken->Set('auth_token', $oPassword);
		$this->oApplicationToken->DBWrite();

		//create ticket
		$description = date('dmY H:i:s');

		$sOuputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOuputJson, true);
		$this->assertFalse(is_null($aJson), "should be json (and not html login form): " .  $sOuputJson);
	}

}
