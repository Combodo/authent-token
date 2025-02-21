<?php

namespace Combodo\iTop\AuthentToken\Test\Service;

use AttributeDateTime;
use Combodo\iTop\AuthentToken\Controller\Oauth2AuthorizeController;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthConfig;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use Combodo\iTop\AuthentToken\Service\AuthentTokenService;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use User;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use UserRights;
use Combodo\iTop\Application\Helper\Session;

class Oauth2AuthorizeControllerTest extends ItopDataTestCase
{
	protected string $sUniqId;
	protected string $sLogin;
	protected User $oUser;
	protected $sPassword = "Iuytrez9876543ç_è-(";

	protected function setUp(): void
	{
		parent::setUp();
		$this->RequireOnceItopFile('env-production/authent-token/vendor/autoload.php');

		$this->sUniqId = "AUTHENTTOKEN_". uniqid();
		$this->sLogin = "oauth-user-".$this->sUniqId;

		/** @var \User $oUser */
		$this->oUser = $this->CreateContactlessUser($this->sLogin,
			ItopDataTestCase::$aURP_Profiles['Service Desk Agent'],
			$this->sPassword
		);
	}

	protected function tearDown() : void
	{
		parent::tearDown();
		$this->SetNonPublicProperty(Oauth2AuthorizeController::GetInstance(), 'aFakeAllHeadersForTest', null);
	}

	protected function CreateOauth2UserApplication(): Oauth2UserApplication
	{
		$oOrg = $this->CreateOrganization("org-".$this->sUniqId);

		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id'       => $oOrg->GetKey(),
			"application"  => "test",
			"redirect_uri" => "https://testu.rd",
		]);

		/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
		$oLnkOauth2ApplicationToUser = $this->createObject(lnkOauth2ApplicationToUser::class, [
			'application_id' => $oOauth2Application->GetKey(),
			'user_id'        => $this->oUser->GetKey(),
		]);

		return new Oauth2UserApplication($oOauth2Application, $oLnkOauth2ApplicationToUser);
	}

	public function testIsOauthToken_BearerTokenPassedInHeader()
	{
		$_SESSION=[];
		$aHeaders = [
			'Authorization' => 'Bearer gabuzomeu',
		];

		$this>$this->SetNonPublicProperty(Oauth2AuthorizeController::GetInstance(), 'aFakeAllHeadersForTest', $aHeaders);

		$this->assertTrue(Oauth2AuthorizeController::GetInstance()->IsOauthToken());
		$this->assertTrue(Session::Get('oauth_authentication', false));
	}

	public function testIsOauthToken_Oauth2EndPoint()
	{
		$_SESSION=[];
		Session::Set('oauth_authentication', true);

		$this->assertTrue(Oauth2AuthorizeController::GetInstance()->IsOauthToken());
	}

	public function testAuthenticateViaOauth_NoToken()
	{
		$this->expectException(TokenAuthException::class);
		Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
	}

	public function testAuthenticateViaOauth_BearerTokenPassedInHeader()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		$sAccessToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
		$aHeaders = [
			'Authorization' => 'Bearer '.$sAccessToken,
		];
		$this>$this->SetNonPublicProperty(Oauth2AuthorizeController::GetInstance(), 'aFakeAllHeadersForTest', $aHeaders);

		$oFoundLnkOauth2ApplicationToUser = Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
		$this->assertEquals($oLnkOauth2ApplicationToUser->GetKey(), $oFoundLnkOauth2ApplicationToUser->GetKey());
	}

	public function testAuthenticateViaOauth_BearerExpiredTokenPassedInHeader()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() - 10);
		$oLnkOauth2ApplicationToUser->Set('access_token_expiration', $sExpireAt);
		$oLnkOauth2ApplicationToUser->DBWrite();

		$sAccessToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
		$aHeaders = [
			'Authorization' => 'Bearer '.$sAccessToken,
		];
		$this>$this->SetNonPublicProperty(Oauth2AuthorizeController::GetInstance(), 'aFakeAllHeadersForTest', $aHeaders);

		$this->expectException(TokenAuthException::class);
		$this->expectExceptionMessage("Expired access_token must be refreshed");

		try{
			Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
		} catch(TokenAuthException $e) {
			$this->assertEquals(498, $e->getCode());
			throw $e;
		}
	}

	public function testAuthenticateViaOauth_AuthorizeOk()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sCode = Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		$_SESSION=[];
		$_POST = [
			'client_id'     => $oOauth2Application->Get('client_id'),
			'client_secret' => $oOauth2Application->Get('client_secret')->GetPassword(),
			'grant_type'    => 'authorization_code',
			'redirect_uri'  => $oOauth2Application->Get('redirect_uri'),
			'code'          => $sCode,
		];
		$oFoundLnkOauth2ApplicationToUser = Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
		$this->assertEquals($oLnkOauth2ApplicationToUser->GetKey(), $oFoundLnkOauth2ApplicationToUser->GetKey());
	}

	public function testAuthenticateViaOauth_RefreshTokenOk()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
		$oLnkOauth2ApplicationToUser = $this->updateObject(lnkOauth2ApplicationToUser::class, $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(),
			[
				'access_token_expiration' => date(AttributeDateTime::GetSQLFormat(), time()-1),
			]
		);

		$oLnkOauth2ApplicationToUser->Reload();
		$iAccessTokenExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'access_token_expiration');
		$this->assertEquals(0, $iAccessTokenExpiredIn);

		$_SESSION=[];
		$sRefreshToken = $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword();
		$sOldRefreshTokenExpirationDate = $oLnkOauth2ApplicationToUser->Get('refresh_token_expiration');
		$sOldAccessToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
		$_POST = [
			'client_id'     => $oOauth2Application->Get('client_id'),
			'client_secret' => $oOauth2Application->Get('client_secret')->GetPassword(),
			'grant_type'    => 'refresh_token',
			'redirect_uri'  => $oOauth2Application->Get('redirect_uri'),
			'refresh_token' => $sRefreshToken,
		];
		$oFoundLnkOauth2ApplicationToUser = Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
		$this->assertEquals($oLnkOauth2ApplicationToUser->GetKey(), $oFoundLnkOauth2ApplicationToUser->GetKey());

		$this->assertEquals($sRefreshToken, $oFoundLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword());
		$this->assertEquals($sOldRefreshTokenExpirationDate, $oFoundLnkOauth2ApplicationToUser->Get('refresh_token_expiration'));
		$sNewAccessToken = $oFoundLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();
		$this->assertNotEquals($sOldAccessToken, $sNewAccessToken, "refresh_token should have changed");

		$iAccessTokenExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oFoundLnkOauth2ApplicationToUser, 'access_token_expiration');
		$this->assertTrue($iAccessTokenExpiredIn + 5 > TokenAuthConfig::OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS, "(modulo 5s) $iAccessTokenExpiredIn  . > ".TokenAuthConfig::OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS);

		$this->assertNotNull(AuthentTokenService::GetInstance()->DecryptToken($sNewAccessToken), "renewed access token should work to fetch Oauth2 token again afterwhile");

	}

	public function testAuthenticateViaOauth_ExpiredRefreshTokenOk()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() - 10);
		$oLnkOauth2ApplicationToUser->Set('refresh_token_expiration', $sExpireAt);
		$oLnkOauth2ApplicationToUser->DBWrite();

		$_SESSION=[];
		$_POST = [
			'client_id'     => $oOauth2Application->Get('client_id'),
			'client_secret' => $oOauth2Application->Get('client_secret')->GetPassword(),
			'grant_type'    => 'refresh_token',
			'redirect_uri'  => $oOauth2Application->Get('redirect_uri'),
			'refresh_token' => $oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
		];

		$this->expectException(TokenAuthException::class);
		$this->expectExceptionMessage("Expired refresh_token");

		try{
			Oauth2AuthorizeController::GetInstance()->AuthenticateViaOauth();
		} catch(TokenAuthException $e) {
			$this->assertEquals(498, $e->getCode());
			throw $e;
		}
	}

	public function testOperationOauth2Token()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sState);

		$sJson = Oauth2AuthorizeController::GetInstance()->OperationOauth2Token($oLnkOauth2ApplicationToUser->GetKey());
		$aJson = json_decode($sJson, true);
		$this->assertNotEquals(false, $aJson);
		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(), $aJson['access_token'] ?? null, 'access_token');
		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(), $aJson['refresh_token'] ?? null, 'refresh_token');
		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('token_type'), $aJson['token_type'] ?? null, 'token_type');

		$iAccessTokenExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'access_token_expiration');
		$this->assertTrue($iAccessTokenExpiredIn + 5 > TokenAuthConfig::OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS, "(modulo 5s) $iAccessTokenExpiredIn  . > ".TokenAuthConfig::OAUTH2_ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
	}

	public static function GetExpiredInSecondsProvider()
	{
		return [
			'access_token_expiration'  => ['access_token_expiration'],
			'refresh_token_expiration' => ['refresh_token_expiration'],
		];
	}

	/**
	 * @param $sField
	 *
	 * @dataProvider GetExpiredInSecondsProvider
	 */
	public function testGetExpiredInSeconds_UpToDate($sField)
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() + 10);
		$oLnkOauth2ApplicationToUser->Set($sField, $sExpireAt);
		$oLnkOauth2ApplicationToUser->DBWrite();

		$iExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, $sField);
		$this->assertTrue($iExpiredIn <= 10, "$sField <= 10 (modulo 8)");
		$this->assertTrue($iExpiredIn > 8, "$sField > 8 ");
	}

	/**
	 * @param $sField
	 *
	 * @dataProvider GetExpiredInSecondsProvider
	 */
	public function testGetExpiredInSeconds_Expired($sField)
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;

		$sExpireAt = date(AttributeDateTime::GetSQLFormat(), time() );
		$oLnkOauth2ApplicationToUser->Set($sField, $sExpireAt);
		$oLnkOauth2ApplicationToUser->DBWrite();

		$iExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, $sField);
		$this->assertEquals(0, $iExpiredIn);
	}

	public function testGetUserFields_UserOnly()
	{
		$_SESSION = [];
		UserRights::Login($this->sLogin);

		$aParams = $this->InvokeNonPublicMethod(Oauth2AuthorizeController::GetInstance(), 'GetUserFields', Oauth2AuthorizeController::GetInstance());

		$aExpected = [
			'email' => '',
			'firstName' => '',
			'organization' => '',
			'lastName' => '',
			'displayName' => $this->sLogin,
			'identifier' => $this->sLogin,
			'language' => 'EN US',
		];
		$this->assertEquals($aExpected, $aParams);
	}

	public function testGetUserFields_UserWithContact()
	{
		$sOrgName = "org-".$this->sUniqId;
		$oOrg = $this->CreateOrganization($sOrgName);
		$sEmail = "gabu@zomeu.fr";
		/** @var Person $oPerson */
		$oPerson = $this->createObject('Person', array(
			'name' => 'name123',
			'first_name' => 'first_name123',
			'org_id' => $oOrg->GetKey(),
			'email' => $sEmail,
		));
		/** @var \User $oUser */
		$sUserLogin = "userwithcontact-".$this->sUniqId;
		$oUser = $this->CreateUser($sUserLogin,
			ItopDataTestCase::$aURP_Profiles['Service Desk Agent'],
			$this->sPassword, $oPerson->GetKey());

		$_SESSION = [];
		UserRights::Login($sUserLogin);

		$aParams = $this->InvokeNonPublicMethod(Oauth2AuthorizeController::GetInstance(), 'GetUserFields', Oauth2AuthorizeController::GetInstance());

		$aExpected = [
			'email' => $sEmail,
			'firstName' => 'first_name123',
			'organization' => $sOrgName,
			'lastName' => 'name123',
			'displayName' => "first_name123 name123",
			'identifier' => $sUserLogin,
			'language' => 'EN US',
		];
		$this->assertEquals($aExpected, $aParams);
	}
}
