<?php

namespace Combodo\iTop\AuthentToken\Test\integration;

use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Service\MetaModelService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use Oauth2Application;
use MetaModel;
use Dict;
use User;
use ApplicationContext;

class Oauth2ServerTest extends ItopDataTestCase {
	//iTop called from outside
	//users need to be persisted in DB
	const USE_TRANSACTION = false;

	protected string $sPassword;
	protected User $oUser;
	protected string $sUniqId;

	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/authent-token/vendor/autoload.php');

		clearstatcache();

		$this->sUniqId = "OAUTH2_AUTHENTTOKEN_" . uniqid();
		$this->sPassword = "abCDEF12345@";
		/** @var User oUser */
		$this->oUser = $this->CreateContactlessUser($this->sUniqId,
			ItopDataTestCase::$aURP_Profiles['Service Desk Agent'],
			$this->sPassword
		);
	}

	protected function CallItopUrl($sUrl, ?array $aPostFields = null, $bIsPost=true)
	{
		$ch = curl_init();

		curl_setopt($ch, CURLOPT_URL, $sUrl);
		curl_setopt($ch, CURLOPT_POST, $bIsPost ? 1 : 0);// set post data to true
		curl_setopt($ch, CURLOPT_POSTFIELDS, $aPostFields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		$sOutput = curl_exec($ch);

		//echo "$sUrl curl_error:".curl_error($ch);
		//echo "$sUrl curl_errno:".curl_errno($ch);
		//echo curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
		//var_dump(curl_get($ch, CURLOPT_HEADER));

		curl_close($ch);

		return $sOutput;
	}

	public function testDisplayOauth2AuthorizeForm() {
		$oOrg = $this->CreateOrganization($this->sUniqId);

		$sRedirectUri = "https://testu.rd";

		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id' => $oOrg->GetKey(),
			"application" => "test",
			"redirect_uri" => $sRedirectUri,
		]);
		$oOauth2Application->Reload();
		$sClientId = $oOauth2Application->Get('client_id');

		$sState = 'state_' . $this->sUniqId;
		$sScope = 'scope_' . $this->sUniqId;
		$aAuthorizeArgs = [
			"client_id" => $sClientId,
			"redirect_uri" => $sRedirectUri,
			'state' => $sState,
			'scope' => $sScope,
		] ;

		//$sUrl = \utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'authorize.php', $aAuthorizeArgs);
		$sUrl = TokenAuthHelper::GenerateUrl(\utils::GetAbsoluteUrlModulesRoot() . TokenAuthHelper::MODULE_NAME . '/authorize.php', $aAuthorizeArgs);

		$aPostParams = [
			'auth_user' => $this->oUser->Get('login'),
			'auth_pwd' => $this->sPassword,
		];
		$sOutput = $this->CallItopUrl($sUrl, $aPostParams);

		$this->AssertStringContains(Dict::S('AuthentToken:Oauth2:Authorize:Title'), $sOutput, "$sUrl should contain oauth2 authorize form");
		$this->AssertStringContains($sState, $sOutput, "$sUrl should contain provided state");
		$this->AssertStringContains($sScope, $sOutput, "$sUrl should contain provided scope");
	}

	public function testDoAuthorizeOk() {
		$oOrg = $this->CreateOrganization($this->sUniqId);

		$sRedirectUri = "https://testu.rd";

		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id' => $oOrg->GetKey(),
			"application" => "test",
			"redirect_uri" => $sRedirectUri,
		]);

		$sRedirectUri = ApplicationContext::MakeObjectUrl(Oauth2Application::class, $oOauth2Application->GetKey());
		$oOauth2Application = $this->updateObject(Oauth2Application::class, $oOauth2Application->GetKey(), [
			"redirect_uri" => $sRedirectUri,
		]);

		$oOauth2Application->Reload();
		$this->assertEquals('', $oOauth2Application->Get('code'), 'code should be empty');


		$aAuthorizeArgs = [
			"operation" => "DoAuthorize",
		] ;

		//$sUrl = \utils::GetAbsoluteUrlModulePage(TokenAuthHelper::MODULE_NAME, 'authorize.php', $aAuthorizeArgs);
		$sUrl = TokenAuthHelper::GenerateUrl(\utils::GetAbsoluteUrlModulesRoot() . TokenAuthHelper::MODULE_NAME . '/authorize.php', $aAuthorizeArgs);

		$sState = "state_".$this->sUniqId;
		$aPostParams = [
			'auth_user' => $this->oUser->Get('login'),
			'auth_pwd' => $this->sPassword,
			"application_id" => $oOauth2Application->GetKey(),
			"state" => $sState,
			"scope" => "scope_" . $this->sUniqId,
			'transaction_id' => $this->GetNewGeneratedTransId(),
			'decision' => 'allow',
		];
		$sOutput = $this->CallItopUrl($sUrl, $aPostParams);

		$oOauth2Application->Reload();
		$sClientId = $oOauth2Application->Get('client_id');

		$this->assertNotEquals('', $oOauth2Application->Get('code'), 'code should have been filled in (and returned when redirecting)');
		$this->assertEquals($sState, $oOauth2Application->Get('authorization_state'), 'authorization_state should have been saved');
	}

	protected function AssertStringContains($sNeedle, $sHaystack, $sMessage): void
	{
		$this->assertNotNull($sNeedle, $sMessage);
		$this->assertNotNull($sHaystack, $sMessage);

		$this->assertTrue(false !== strpos($sHaystack, $sNeedle), $sMessage . PHP_EOL . "needle: '$sNeedle' not found in content below:" . PHP_EOL . PHP_EOL . $sHaystack);
	}

	protected function AssertStringNotContains($sNeedle, $sHaystack, $sMessage): void
	{
		$this->assertNotNull($sNeedle, $sMessage);
		$this->assertNotNull($sHaystack, $sMessage);

		$this->assertFalse(false !== strpos($sHaystack, $sNeedle), $sMessage. PHP_EOL . "needle: '$sNeedle' should not be found in content below:" . PHP_EOL . PHP_EOL . $sHaystack);
	}

	private function GetNewGeneratedTransId() {
		\UserRights::Login($this->oUser->Get('login'));
		$sTransId = \utils::GetNewTransactionId();
		\UserRights::_ResetSessionCache();

		return $sTransId;
	}
}
