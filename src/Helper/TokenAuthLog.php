<?php
/**
 * @copyright   Copyright (C) 2010-2024 Combodo SAS
 * @license     http://opensource.org/licenses/AGPL-3.0
 */


namespace Combodo\iTop\AuthentToken\Helper;

use LogAPI;

class TokenAuthLog extends LogAPI
{
	const CHANNEL_DEFAULT = 'TokenAuthLog';

	protected static $m_oFileLog = null;
}
