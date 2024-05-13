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
	protected $sToken;

	/**
     * @throws Exception
     */
    protected function setUp(): void
    {
	    parent::setUp();
		self::$DEBUG_UNIT_TEST = true;

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
		    $this->oUser = $this->createObject(UserToken::class, array(
			    'login' => $this->sLogin,
			    'language' => 'EN US',
			    'profile_list' => $oSet,
		    ));
		    $this->debug("Created {$this->oUser->GetName()} ({$this->oUser->GetKey()})");

		    if (is_object($oRestProfile))
		    {
			    $this->oUser = $this->AddProfileToUser($this->oUser, $oRestProfile->GetKey());
		    } else {
			    MetaModel::GetConfig()->Set('secure_rest_services', false, 'auth-token');
			    MetaModel::GetConfig()->WriteToFile();
		    }
	    }
	    @chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);
	    $oReflectionClass = new \ReflectionClass(AbstractApplicationToken::class);
	    $oProperty = $oReflectionClass->getProperty('sToken');
	    $oProperty->setAccessible(true);
	    $this->sToken = $oProperty->getValue($this->oUser);	}

	protected function GetAuthToken($sContext=null){
		return $this->sToken;
	}

	protected function GetHeadersParam($sContext = null)
	{
		if ($this->bTokenInPost) {
			return [];
		}

		return [
			//'Content-Type: application/x-www-form-urlencoded',
			'Auth-Token: '.$this->GetAuthToken($sContext),
		];
	}

	/**
	 * @param \DBObject $oUser
	 * @param int $iProfileId
	 *
	 * @return \DBObject
	 * @throws Exception
	 */
	protected function AddProfileToUser($oUser, $iProfileId)
	{
		$oUserProfile = new \URP_UserProfile();
		$oUserProfile->Set('profileid', $iProfileId);
		$oUserProfile->Set('reason', 'UNIT Tests');
		/** @var \ormLinkSet $oSet */
		$oSet = $oUser->Get('profile_list');
		$oSet->AddItem($oUserProfile);
		$oUser = $this->updateObject(\User::class, $oUser->GetKey(), array(
			'profile_list' => $oSet,
		));
		$this->debug("Updated {$oUser->GetName()} ({$oUser->GetKey()})");

		return $oUser;
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
		$this->oUser->Set('auth_token', $oPassword);
		$this->oUser->DBWrite();

		//create ticket
		$description = date('dmY H:i:s');

		// Allow legacy tokens in configuration
		$oConfig = MetaModel::GetConfig();
		$aParamsByTokenType = $oConfig->GetModuleSetting('authent-token', 'application_token', array());
		$aParamsByTokenType['allow_fallback_token'] = true;
		$oConfig->SetModuleSetting('authent-token', 'application_token', $aParamsByTokenType);
		$sConfigFile = $oConfig->GetLoadedFile();
		@chmod($sConfigFile, 0770); // Allow overwriting the file
		$oConfig->WriteToFile();
		@chmod($sConfigFile, 0440); // Deny overwriting the file

		$sOutputJson = $this->CreateTicketViaApi($description);
		$aJson = json_decode($sOutputJson, true);
		$this->assertFalse(is_null($aJson), "should be json (and not html login form): " .  $sOutputJson);
	}

}
