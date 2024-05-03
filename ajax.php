<?php

use Combodo\iTop\AuthentToken\Controller\AuthentTokenAjaxController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;

require_once(APPROOT.'application/startup.inc.php');

require_once(APPROOT.'/application/loginwebpage.class.inc.php');
LoginWebPage::DoLoginEx(null, false, LoginWebPage::EXIT_HTTP_401); // Check user rights and exits with "401 Not authorized" if not already logged in

$oController = new AuthentTokenAjaxController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
$oController->HandleAjaxOperation();
