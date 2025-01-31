<?php

namespace Combodo\iTop\AuthentToken\Model;

use lnkOauth2ApplicationToUser;
use Oauth2Application;

class Oauth2UserApplication {
	public Oauth2Application $oOauth2Application;
	public lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser;

	public function __construct(Oauth2Application $oOauth2Application, lnkOauth2ApplicationToUser $oLnkOauth2ApplicationToUser) {
		$this->oOauth2Application = $oOauth2Application;
		$this->oLnkOauth2ApplicationToUser = $oLnkOauth2ApplicationToUser;
	}
}
