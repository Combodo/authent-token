<?php

namespace Combodo\iTop\AuthentToken\Model;

interface iToken {

	public function GetUser(): \User;
	public function GetKey();
	public function CheckValidity(string $sToken): void;
	public function UpdateUsage(): void;
	public function CheckScopes(): void;
}
