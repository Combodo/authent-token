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
	public function __construct($sMessage = "Unauthorized", $iHttpCode = 400, Exception $oPrevious = null)
	{
		TokenAuthLog::Error(TokenAuthHelper::MODULE_NAME.": $sMessage code: $iHttpCode");
		parent::__construct($sMessage, $iHttpCode, $oPrevious);
	}
}
