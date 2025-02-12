<?php

namespace Combodo\iTop\AuthentToken\Test\integration;

require_once __DIR__.'/AbstractTokenRest.php';
use AttributeDateTime;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Hook\TokenLoginExtension;
use Combodo\iTop\AuthentToken\Model\Oauth2UserApplication;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;
use Combodo\iTop\Test\UnitTest\ItopDataTestCase;
use DateTime;
use Oauth2Application;
use MetaModel;
use Dict;
use User;
use ApplicationContext;
use lnkOauth2ApplicationToUser;

class Oauth2ServerTest extends AbstractTokenRest {
	//iTop called from outside
	//users need to be persisted in DB
	const USE_TRANSACTION = false;

	private ?string $sToken;
	protected $sPassword = "Iuytrez9876543ç_è-(";

	protected function setUp(): void {
		parent::setUp();
		$this->RequireOnceItopFile('env-production/authent-token/vendor/autoload.php');

		clearstatcache();

		/** @var User oUser */
		$this->oUser = $this->CreateContactlessUser($this->sLogin,
			ItopDataTestCase::$aURP_Profiles['Administrator'],
			$this->sPassword
		);

		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0770);
		$this->InitLoginMode(TokenLoginExtension::LOGIN_TYPE);

		MetaModel::GetConfig()->Set('secure_rest_services', true, 'auth-token');
		MetaModel::GetConfig()->Set('allow_rest_services_via_tokens', true, 'auth-token');
		MetaModel::GetConfig()->SetModuleSetting(TokenAuthHelper::MODULE_NAME, 'personal_tokens_allowed_profiles', ['Administrator', 'Service Desk Agent']);

		//\MetaModel::GetConfig()->Set('log_level_min', ['Token' => 'Debug']);
		//\MetaModel::GetConfig()->Set('login_debug', true);

		MetaModel::GetConfig()->WriteToFile();
		@chmod(MetaModel::GetConfig()->GetLoadedFile(), 0440);

		$this->sToken = null;
	}

	protected function CreateOauth2UserApplication(): Oauth2UserApplication
	{
		/** @var Oauth2Application $oOauth2Application */
		$oOauth2Application = $this->createObject(Oauth2Application::class, [
			'org_id'       => $this->sOrgId,
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

	protected function GetHeadersParam($sContext = null)
	{
		if (is_null($this->sToken) || $this->bTokenInPost) {
			return [];
		}

		return [
			//'Content-Type: application/json',
			'Authorization: Bearer '. $this->sToken,
		];
	}

	protected function GetAuthToken($sContext=null){
		return $this->sToken;
	}

	private function CallItopUrl($sUrl, ?array $aPostFields = null, $bIsPost=true)
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
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$oOauth2Application->Reload();
		$sClientId = $oOauth2Application->Get('client_id');

		$sState = 'state_' . $this->sUniqId;
		$sScope = 'scope_' . $this->sUniqId;
		$aAuthorizeArgs = [
			"client_id" => $sClientId,
			"redirect_uri" => $oOauth2Application->Get('redirect_uri'),
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
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		$oLnkOauth2ApplicationToUser->Reload();
		$aEmptyFields = [
			"refresh_token_expiration",
			"access_token_expiration",
			"code",
			"authorization_state",
		];
		foreach ($aEmptyFields as $sField){
			$this->assertEquals('', $oLnkOauth2ApplicationToUser->Get($sField), "$sField should be empty");
		}

		$aPwdFields = [
			"refresh_token",
			"access_token",
		];
		foreach ($aPwdFields as $sField){
			$this->assertEquals('', $oLnkOauth2ApplicationToUser->Get($sField)->GetPassword(), "$sField should be empty");
		}

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

		$this->CallItopUrl($sUrl, $aPostParams);
		$oLnkOauth2ApplicationToUser->Reload();

		foreach ($aEmptyFields as $sField){
			$this->assertNotEquals('', $oLnkOauth2ApplicationToUser->Get($sField), "$sField should NOT be empty");
		}
		foreach ($aPwdFields as $sField){
			$this->assertNotEquals('', $oLnkOauth2ApplicationToUser->Get($sField), "$sField should NOT be empty");
		}

		$this->assertNotEquals(
			$oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(),
			$oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(),
			"access_token / refresh_token should NOT be the same");

		$this->CheckExpirationField($oLnkOauth2ApplicationToUser, 'access_token_expiration', Oauth2ApplicationService::ACCESS_TOKEN_EXPIRATION_IN_SECONDS);
		$this->CheckExpirationField($oLnkOauth2ApplicationToUser, 'refresh_token_expiration', Oauth2ApplicationService::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);

		$this->assertEquals($sState, $oLnkOauth2ApplicationToUser->Get('authorization_state'), 'authorization_state should have been saved');
	}

	public function testFetchAccessTokenByCodeAfterAuthorize() {
		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$oOauth2Application->Reload();
		$sClientId = $oOauth2Application->Get('client_id');
		$sClientSecret = $oOauth2Application->Get('client_secret')->GetPassword();

		$sAccessTokenExpiration = date(AttributeDateTime::GetSQLFormat(), time()+60);
		$sRefreshTokenExpiration = date(AttributeDateTime::GetSQLFormat(), time() + Oauth2ApplicationService::REFRESH_TOKEN_EXPIRATION_IN_SECONDS);
		/** @var lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser */
		$oLnkOauth2ApplicationToUser = $this->updateObject(lnkOauth2ApplicationToUser::class, $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser->GetKey(),
			[
				'application_id' => $oOauth2Application->GetKey(),
				'user_id' => $this->oUser->GetKey(),
				'access_token' => 'access_token123',
				'code' => 'code123',
				'refresh_token' => 'refresh_token123',
				'access_token_expiration' => $sAccessTokenExpiration,
				'refresh_token_expiration' => $sRefreshTokenExpiration,
			]
		);


		$sUrl = TokenAuthHelper::GenerateUrl(\utils::GetAbsoluteUrlModulesRoot() . TokenAuthHelper::MODULE_NAME . '/token.php', []);

		$aPostParams = [
			"application_id" => $oOauth2Application->GetKey(),
			"scope" => "scope_" . $this->sUniqId,
			"client_id" => $sClientId,
			'code' => 'code123',
			"client_secret" => $sClientSecret,
			"grant_type" => 'authorization_code',
			"redirect_uri" => $oOauth2Application->Get('redirect_uri'),
		];

		$sOutput = $this->CallItopUrl($sUrl, $aPostParams);
		$aJson = json_decode($sOutput, true);
		$this->assertNotEquals(false, $aJson, $sOutput);
		var_dump($aJson);

		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('token_type'), $aJson['token_type'] ?? null, 'check token_type');
		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword(), $aJson['access_token'] ?? null, 'check access_token');
		$this->assertEquals($oLnkOauth2ApplicationToUser->Get('refresh_token')->GetPassword(), $aJson['refresh_token'] ?? null, 'check refresh_token');

		$this->assertNotNull($aJson['expires_in'] ?? null, 'check expires_in');
		$siExpireIn = (int) $aJson['expires_in'];
		$this->assertTrue($siExpireIn > 50, 'check expires_in value > 50');
		$this->assertTrue($siExpireIn < 61, 'check expires_in value < 61');
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

	private function CheckExpirationField(lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser, string $sField,
		int $iExpirationInSeconds) : void {

		$oAttDateTime = $oLnkOauth2ApplicationToUser->Get($sField);
		$this->assertNotNull($oAttDateTime, "$sField not null");
		$oExpirationFieldDateTime = DateTime::createFromFormat(AttributeDateTime::GetSQLFormat(), $oAttDateTime);

		$iExpirationTime = strtotime("+$iExpirationInSeconds SECONDS") - 10;
		$oExpirationTimeDateTimeCheck = date(AttributeDateTime::GetSQLFormat(), $iExpirationTime);

		$this->assertTrue($iExpirationTime < $oExpirationFieldDateTime->getTimestamp(), "expiration check $iExpirationInSeconds: $oExpirationTimeDateTimeCheck < $oAttDateTime");
	}


	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testCreateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		if ($bTokenInPost){
			$this->markTestSkipped();
		}


		$oExpectedOauth2UserApplication = $this->CreateOauth2UserApplication();
		$oOauth2Application = $oExpectedOauth2UserApplication->oOauth2Application;
		$sState = "STATE-123";
		$sCode = "CODE-456";
		$oLnkOauth2ApplicationToUser = $oExpectedOauth2UserApplication->oLnkOauth2ApplicationToUser;
		Oauth2ApplicationService::GetInstance()->SaveCode($oLnkOauth2ApplicationToUser, $sCode, $sState);
		$oLnkOauth2ApplicationToUser->Reload();
		$this->sToken = $oLnkOauth2ApplicationToUser->Get('access_token')->GetPassword();

		$oLnkOauth2ApplicationToUser->Set('scope', \ContextTag::TAG_REST);
		$this->updateObject(lnkOauth2ApplicationToUser::class, $oLnkOauth2ApplicationToUser->GetKey(), ['scope' => \ContextTag::TAG_REST] );

		parent::testCreateApiViaToken($iJsonDataMode, false);
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testUpdateApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		//if ($bTokenInPost){
			$this->markTestSkipped();
		//}
	}

	/**
	 * @dataProvider BasicTokenProvider
	 */
	public function testDeleteApiViaToken($iJsonDataMode, $bTokenInPost)
	{
		//if ($bTokenInPost){
			$this->markTestSkipped();
		//}
	}
}
