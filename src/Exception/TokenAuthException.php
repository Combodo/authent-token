<?php
namespace Combodo\iTop\AuthentToken\Exception;

use Combodo\iTop\AuthentToken\Helper\TokenAuthHelper;
use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
use Exception;

class TokenAuthException extends Exception
{
	/**
	 * OAuthException constructor.
	 *
	 * @param string $sMessage
	 * @param int $iHttpCode
	 * @param Exception|null $oPrevious
	 */
	public function __construct($sMessage = "Unauthorized", $iHttpCode = 400, Exception $oPrevious = null, array $aContext = [])
	{
		if (!is_null($oPrevious)) {
			$sStack = $oPrevious->getTraceAsString();
			$sError = $oPrevious->getMessage();
		} else {
			$sStack = $this->getTraceAsString();
			$sError = '';
		}

		$aContext['code'] = $iHttpCode;
		$aContext['error'] = $sError;
		$aContext['stack'] = $sStack;

		TokenAuthLog::Enable();
		TokenAuthLog::Error($sMessage, null, $aContext);
		parent::__construct($sMessage, $iHttpCode, $oPrevious);
	}
}
