<?php
/**
 * @copyright   Copyright (C) 2010-2022 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

namespace Combodo\iTop\AuthentToken\Helper;

class TokenAuthHelper
{
	const MODULE_NAME = 'authent-token';

	public function __construct()
	{
		TokenAuthLog::Enable(APPROOT.'log/error.log');
	}
}
