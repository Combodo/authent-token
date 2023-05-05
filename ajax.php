<?php

use Combodo\iTop\AuthentToken\Controller\MyAccountController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\Application\Helper\Session;

require_once(APPROOT.'application/startup.inc.php');

require_once(APPROOT.'/application/loginwebpage.class.inc.php');
LoginWebPage::DoLoginEx(null, false, LoginWebPage::EXIT_HTTP_401); // Check user rights and exits with "401 Not authorized" if not already logged in

$oController = new MyAccountController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
$oController->SetDefaultOperation('Ajax');
$oController->HandleAjaxOperation();
