<?php

namespace Combodo\iTop\AuthentToken\Test\Service;

use Combodo\iTop\AuthentToken\Controller\Oauth2AuthorizeController;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Oauth2Application;
use lnkOauth2ApplicationToUser;
use \Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use User;
use UserRights;

class Oauth2ApplicationServiceTest extends ItopDataTestCase {
	protected string $sUniqId;
	protected string $sLogin;
	protected User $oUser;
	protected $sPassword = "Iuytrez9876543ç_è-(";

	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/authent-token/vendor/autoload.php');

		$this->sUniqId = "AUTHENTTOKEN_" . uniqid();
		$this->sLogin = "oauth-user-".$this->sUniqId;

		/** @var \User $oUser */
		$this->oUser = $this->CreateContactlessUser($this->sLogin,
			ItopDataTestCase::$aURP_Profiles['Service Desk Agent'],
			$this->sPassword
		);
	}

	protected function CreateOauth2UserApplication() : Oauth2UserApplication
	{
		$oOrg = $this->CreateOrganization("org-" . $this->sUniqId);

		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id' => $oOrg->GetKey(),
			"application" => "test",
			"redirect_uri" => "https://testu.rd",
		]);

		/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
		$oLnkOauth2ApplicationToUser = $this->createObject(lnkOauth2ApplicationToUser::class, [
			'application_id' => $oOauth2Application->GetKey(),
			'user_id' => $this->oUser->GetKey(),
		]);

		return new Oauth2UserApplication($oOauth2Application, $oLnkOauth2ApplicationToUser);
	}

	public function testGetOauth2UserApplication_SearchWithAnotherUserLoggedIn()
	{
		$oOauth2UserApplication = $this->CreateOauth2UserApplication();

		/** @var \User $oAnotherUser */
		$sAnotherLogin = "anotheruser-".$this->sLogin;$this->CreateContactlessUser($sAnotherLogin,
			ItopDataTestCase::$aURP_Profiles['Service Desk Agent'],
			$this->sPassword
		);

		$_SESSION = [];
		UserRights::Login($sAnotherLogin);
		$this->expectException(TokenAuthException::class);
		Oauth2ApplicationService::GetInstance()->GetOauth2UserApplication($oOauth2UserApplication->oOauth2Application->GetKey());
	}

	public function testGetOauth2UserApplication_UnknownApplicationId()
	{
		$this->CreateOauth2UserApplication();

		$_SESSION = [];
		UserRights::Login($this->sLogin);
		$this->expectException(TokenAuthException::class);
		Oauth2ApplicationService::GetInstance()->GetOauth2UserApplication("666");
	}

	public function testGetOauth2UserApplication_OK()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$_SESSION = [];
		UserRights::Login($this->sLogin);
		$oOauth2UserApplication= Oauth2ApplicationService::GetInstance()->GetOauth2UserApplication($oExpectedOauth2UserApplication->oOauth2Application->GetKey());

		$this->assertEquals($oExpectedOauth2UserApplication->oOauth2Application->GetKey(), $oOauth2UserApplication->oOauth2Application->GetKey());
		$this->assertEquals($oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(), $oOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey());
	}

	public function testDecodeAuthorizationRequest_OK()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$_SESSION = [];
		UserRights::Login($this->sLogin);

		$sClientId = $oExpectedOauth2UserApplication->oOauth2Application->Get('client_id');
		$sRedirectUri = $oExpectedOauth2UserApplication->oOauth2Application->Get('redirect_uri');
		$oOauth2UserApplication= Oauth2ApplicationService::GetInstance()->DecodeAuthorizationRequest($sClientId, $sRedirectUri);

		$this->assertEquals($oExpectedOauth2UserApplication->oOauth2Application->GetKey(), $oOauth2UserApplication->oOauth2Application->GetKey());
		$this->assertEquals($oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(), $oOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey());
	}

	public function testSaveCode_OK()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$_SESSION = [];
		UserRights::Login($this->sLogin);

		$sState = "STATE-123";
		$sCode = "CODE-456";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sCode, $sState);

		$oLnkOauth2ApplicationToUser->Reload();

		$this->assertEquals($sCode, $oLnkOauth2ApplicationToUser->Get('code'));
		$this->assertEquals($sState, $oLnkOauth2ApplicationToUser->Get('authorization_state'));
		$this->assertNotEmpty($oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword());
		$this->assertNotEmpty($oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword());

		$iAccessTokenExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'access_token_expiration');
		$this->assertTrue($iAccessTokenExpiredIn + 5 > Oauth2ApplicationService::ACCESS_TOKEN_EXPIRATION_IN_SECONDS, "(modulo 5s) $iAccessTokenExpiredIn  . > " . Oauth2ApplicationService::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);

		$iRefreshTokenExpiredIn = Oauth2AuthorizeController::GetInstance()->GetExpiredInSeconds($oLnkOauth2ApplicationToUser, 'refresh_token_expiration');
		$this->assertTrue($iRefreshTokenExpiredIn + 5 > Oauth2ApplicationService::REFRESH_TOKEN_EXPIRATION_IN_SECONDS, "(modulo 5s) $iRefreshTokenExpiredIn > " . Oauth2ApplicationService::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
	}

	public function testGetLnkOauth2ApplicationToUserByCode_OK()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$sCode = "CODE-456";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sCode, $sState);
		$oLnkOauth2ApplicationToUser->Reload();

		$oFoundLnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByCode(
			$oExpectedOauth2UserApplication->oOauth2Application->Get('client_id'),
			$oExpectedOauth2UserApplication->oOauth2Application->Get('client_secret')->GetPassword(),
			$oExpectedOauth2UserApplication->oOauth2Application->Get('redirect_uri'),
			$oLnkOauth2ApplicationToUser->Get('code')
		);

		$this->assertEquals($oLnkOauth2ApplicationToUser->GetKey(), $oFoundLnkOauth2ApplicationToUser->GetKey());
	}

	public function testGetLnkOauth2ApplicationToUserByRefreshToken_OK()
	{
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();

		$sState = "STATE-123";
		$sCode = "CODE-456";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sCode, $sState);
		$oLnkOauth2ApplicationToUser->Reload();

		$oFoundLnkOauth2ApplicationToUser = Oauth2ApplicationService::GetInstance()->GetLnkOauth2ApplicationToUserByRefreshToken(
			$oExpectedOauth2UserApplication->oOauth2Application->Get('client_id'),
			$oExpectedOauth2UserApplication->oOauth2Application->Get('client_secret')->GetPassword(),
			$oExpectedOauth2UserApplication->oOauth2Application->Get('redirect_uri'),
			$oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword()
		);

		$this->assertEquals($oLnkOauth2ApplicationToUser->GetKey(), $oFoundLnkOauth2ApplicationToUser->GetKey());
	}
}
