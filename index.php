<?php

use Combodo\iTop\AuthentToken\Controller\AuthentTokenController;
use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;

require_once(APPROOT.'application/startup.inc.php');

$oController = new AuthentTokenController(__DIR__.'/templates', TokenAuthHelper::MODULE_NAME);
$oController->SetDefaultOperation('PersonalToken');
$oController->HandleOperation();
