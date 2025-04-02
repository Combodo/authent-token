<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

use Combodo\iTop\AuthentToken\Controller\Oauth2AuthorizeController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\Application\Helper\Session;

//require_once('../../approot.inc.php');
require_once(APPROOT.'bootstrap.inc.php');
require_once(APPROOT.'application/startup.inc.php');

TokenAuthLog::Enable();

Session::Set('oauth_authentication', true);
Session::Set('oauth_token_endpoint', true);

LoginWebPage::ResetSession(true);
$iRet = LoginWebPage::DoLogin(false, false, LoginWebPage::EXIT_RETURN);

if ($iRet === LoginWebPage::EXIT_CODE_OK) {
	$oController = new Oauth2AuthorizeController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
	$oController->SetDefaultOperation('Oauth2Token');
	$oController->HandleOperation();
} else {
	$iHttpCode = Session::Get('oauth_http_errorcode', 200);
	http_response_code($iHttpCode);
	$oP = new JsonPage();
	$oP->add_header('Access-Control-Allow-Origin: *');
	$oP->SetData(['code' => $iRet]);
	$oP->SetOutputDataOnly(true);
	$oP->Output();
}
