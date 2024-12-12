<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     https://www.combodo.com/documentation/combodo-software-license.html
 *
 */

use Combodo\iTop\AuthentToken\Controller\Oauth2AuthorizeController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;

require_once('../../approot.inc.php');
require_once(APPROOT.'bootstrap.inc.php');
require_once(APPROOT.'application/startup.inc.php');

TokenAuthLog::Enable();
$oP = new JsonPage();


LoginWebPage::DoLogin();

$oController = new Oauth2AuthorizeController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
$oController->SetDefaultOperation('Oauth2Authorize');
$oController->HandleOperation();
