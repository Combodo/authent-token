<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Model\iToken;
use DBObject;
use DBProperty;
use MetaModel;
use ormPassword;
use SimpleCrypt;

class AuthentTokenService {
	const TOKEN_APPLICATION_NAME     = 'a';
	const TOKEN_ID     = 'i';
	const TOKEN_CLASS     = 'c';
	const TOKEN_SALT     = 's';
	const PRIVATE_KEY    = 'authent-token-priv-key';

	/**
	 * @param $sToken
	 *
	 * @return array|mixed
	 * @throws \CoreException
	 * @throws \MySQLException
	 */
	public function DecryptToken($sToken)
	{
		$sPrivateKey = $this->GetPrivateKey();
		$oCrypt = new SimpleCrypt();

		return json_decode($oCrypt->Decrypt($sPrivateKey, hex2bin($sToken)), true);
	}

	public function GetToken(array $aTokenFields) : iToken
	{
		$sClass = $aTokenFields[self::TOKEN_CLASS];
		$sId = $aTokenFields[self::TOKEN_ID];
		return MetaModel::GetObject($sClass, $sId);
	}

	public function CreateNewToken(DBObject $oObject): string
	{
		$aToken = [
			self::TOKEN_ID     => $oObject->GetKey(),
			self::TOKEN_CLASS     => get_class($oObject),
			self::TOKEN_SALT => bin2hex(random_bytes(8)),
		];

		$sPPrivateKey = $this->GetPrivateKey();
		$oCrypt = new SimpleCrypt();
		return bin2hex($oCrypt->Encrypt($sPPrivateKey, json_encode($aToken)));
	}

	public function CreatePassword($sToken) : ormPassword
	{
		$oPassword = new ormPassword();
		$oPassword->SetPassword($sToken);
		return $oPassword;
	}

	/**
	 * @return string
	 * @throws \CoreException
	 * @throws \CoreUnexpectedValue
	 * @throws \MySQLException
	 */
	private function GetPrivateKey()
	{
		$sPrivateKey = DBProperty::GetProperty(self::PRIVATE_KEY);
		if (is_null($sPrivateKey)) {
			$sPrivateKey = bin2hex(random_bytes(32));
			DBProperty::SetProperty(self::PRIVATE_KEY, $sPrivateKey);
		}

		return $sPrivateKey;
	}
}
