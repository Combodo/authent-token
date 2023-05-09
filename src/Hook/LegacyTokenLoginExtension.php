<?php

namespace Combodo\iTop\AuthentToken\Hook;

/**
 * Class LegacyTokenLoginExtension
 * duplicate of TokenLoginExtension due to a limitation in LoginWebPage::GetLoginPluginList
 * a iLoginExtension cannot register twice...
 *
 * @copyright   Copyright (C) 2010-2021 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */
class LegacyTokenLoginExtension extends TokenLoginExtension
{
	/**
	 * Return the list of supported login modes for this plugin
	 *
	 * @return array of supported login modes
	 */
	public function ListSupportedLoginModes(){
		return [self::LEGACY_LOGIN_TYPE];
	}
}
