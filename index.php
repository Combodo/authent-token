<?php

use Combodo\iTop\AuthentToken\Controller\MyAccountController;

require_once(APPROOT.'application/startup.inc.php');

$oController = new MyAccountController(__DIR__.'/templates', 'authent-token');
$oController->SetDefaultOperation('MainPage');
$oController->HandleOperation();
