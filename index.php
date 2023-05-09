<?php

use Combodo\iTop\AuthentToken\Controller\MyAccountController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;

require_once(APPROOT.'application/startup.inc.php');

$oController = new MyAccountController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
$oController->SetDefaultOperation('MainPage');
$oController->HandleOperation();
