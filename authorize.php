<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

use Combodo\iTop\Application\Helper\Session;
use Combodo\iTop\AuthentToken\Exception\TokenAuthException;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Combodo\iTop\AuthentToken\Service\Oauth2ApplicationService;

require_once('../../approot.inc.php');
require_once(APPROOT.'bootstrap.inc.php');
require_once(APPROOT.'application/startup.inc.php');

TokenAuthLog::Enable();
$oP = new JsonPage();

$sAppId = Session::Get(Oauth2ApplicationService::APPLICATION_ID, null);

try{
	if (is_null($sAppId)){
		if ($_SERVER['CONTENT_TYPE'] == 'application/json') {
			$sEntityBody = file_get_contents('php://input');
			$oOauth2Application = Oauth2ApplicationService::GetInstance()->DecodeAutorizationRequest($sEntityBody);

			Session::Set(Oauth2ApplicationService::APPLICATION_ID, $oOauth2Application->GetKey());
		} else {
			throw new TokenAuthException();
		}
	}

	LoginWebPage::DoLogin();
	//LoginWebPage::HTTPRedirect("pagedeconsentement");
	//generer les tokens
	//formater la reponse
	//envoyer à la redirect_url
} catch (TokenAuthException $e) {
	$oJsonIssue = new RestResult();
	$oJsonIssue->code = $e->getCode();
	$oJsonIssue->message = $e->getMessage();
	$aResponse = json_decode(json_encode($oJsonIssue), true);
	http_response_code($e->getCode());
	foreach ($e->GetHeaders() as $sHeader) {
		header($sHeader);
	}
} catch (Exception $e) {
	$oJsonIssue = new RestResult();
	$oJsonIssue->code = $e->getCode();
	$oJsonIssue->message = $e->getMessage();
	$aResponse = json_decode(json_encode($oJsonIssue), true);
	http_response_code(500);
}

$oP->add_header('Access-Control-Allow-Origin: *');
$oP->SetContentType('application/json');
$oP->SetData($aResponse);
$oP->Output();