<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Model\iToken;
use DBObject;
use DBProperty;
use MetaModel;
use ormPassword;
use SimpleCrypt;

class AuthentTokenService {
	const LEGACY_TOKEN_CLASS     = 'c';
	const LEGACY_TOKEN_ID     = 'i';
	const LEGACY_TOKEN_SALT     = 's';
	const PRIVATE_KEY    = 'authent-token-priv-key';

	/** @var \Combodo\iTop\AuthentToken\Service\MetaModelService $oMetaModelService */
	private $oMetaModelService;

	public function __construct(?MetaModelService $oMetaModelService=null)
	{
		$this->oMetaModelService = is_null($oMetaModelService) ? new MetaModelService() : $oMetaModelService;
	}

	/**
	 * @param $sToken
	 *
	 * @return array|mixed
	 * @throws \CoreException
	 * @throws \MySQLException
	 */
	public function DecryptToken($sToken) : ?iToken
	{
		$sPrivateKey = $this->GetPrivateKey();
		$oCrypt = $this->GetSimpleCryptObject();

		try{
			$sDecryptedToken = $oCrypt->Decrypt($sPrivateKey, base64_decode($sToken, true));
			$oToken = $this->GetToken($sDecryptedToken);
			if (! is_null($oToken)){
				return $oToken;
			}
		} catch(\Exception $e){}

		$sDecryptedToken = $oCrypt->Decrypt($sPrivateKey, hex2bin($sToken));
		$oToken = $this->GetLegacyToken($sDecryptedToken);
		if (! is_null($oToken)){
			return $oToken;
		}

		return null;
	}

	private function GetSimpleCryptObject() : SimpleCrypt
	{
		return new SimpleCrypt(MetaModel::GetConfig()->GetEncryptionLibrary());
	}

	public function GetToken(string $sDecryptedToken) : ?iToken
	{
		$aFields = explode(':', $sDecryptedToken);
		if (count($aFields) < 2){
			return null;
		}

		$sId = $aFields[0];
		$sClassName = $aFields[1];

		if ( ! preg_match('/^\d+$/', $sId) ) {
			return null;
		}

		try{
			$oReflectionClass = new \ReflectionClass($sClassName);
			if ($oReflectionClass->implementsInterface(iToken::class)){
				return $this->oMetaModelService->GetObject($sClassName, $sId);
			}
		} catch(\ReflectionException $e){
		}

		return null;
	}

	public function GetLegacyToken(string $sDecryptedToken) : ?iToken
	{
		$aTokenData = json_decode($sDecryptedToken, true);
		if (! is_array($aTokenData)){
			return null;
		}

		$sClassName = (array_key_exists(self::LEGACY_TOKEN_CLASS, $aTokenData)) ? $aTokenData[self::LEGACY_TOKEN_CLASS] : null;
		$sId = (array_key_exists(self::LEGACY_TOKEN_ID, $aTokenData)) ? $aTokenData[self::LEGACY_TOKEN_ID] : null;

		if (is_null($sClassName) || is_null($sId)){
			return null;
		}

		if ( ! preg_match('/^\d+$/', $sId) ) {
			return null;
		}

		try {
			$oReflectionClass = new \ReflectionClass($sClassName);
			if ($oReflectionClass->implementsInterface(iToken::class)) {
				return $this->oMetaModelService->GetObject($sClassName, $sId);
			}
		}catch(\Exception $e){

		}

		return null;
	}

	public function CreateNewToken(DBObject $oObject): string
	{
		$sTokenBeforeEncryption = sprintf("%s:%s:%s",
			$oObject->GetKey(), get_class($oObject), random_bytes(8)
		);

		$sPPrivateKey = $this->GetPrivateKey();
		$oCrypt = $this->GetSimpleCryptObject();
		return base64_encode($oCrypt->Encrypt($sPPrivateKey, $sTokenBeforeEncryption));
	}

	/**
	 * for backward compatibility test only
	 */
	private function CreateLegacyNewToken(DBObject $oObject): string
	{
		$aToken = [
			self::LEGACY_TOKEN_ID     => $oObject->GetKey(),
			self::LEGACY_TOKEN_CLASS     => get_class($oObject),
			self::LEGACY_TOKEN_SALT => bin2hex(random_bytes(8)),
		];

		$sPPrivateKey = $this->GetPrivateKey();
		$oCrypt = $this->GetSimpleCryptObject();
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
