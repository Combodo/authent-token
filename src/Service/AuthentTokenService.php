<?php

namespace Combodo\iTop\AuthentToken\Service;

use Combodo\iTop\AuthentToken\Helper\TokenAuthLog;
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
	 * N°5921: decrypt both short and old big token format
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
		} catch(\Exception $e){
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Debug("DecryptToken could not decrypt or base64_decode token.", null, [ 'exception_message' => $e->getMessage() ]);
			}
		}

		try{
			$oCrypt = new SimpleCrypt();
			$sDecryptedToken = $oCrypt->Decrypt($sPrivateKey, hex2bin($sToken));
			$oToken = $this->GetLegacyToken($sDecryptedToken);
			if (! is_null($oToken)){
				return $oToken;
			}
		} catch(\Exception $e){
			if (MetaModel::GetConfig()->Get('login_debug')){
				TokenAuthLog::Debug("DecryptToken (legacy) could not decrypt or hex2bin token.", null, [ 'exception_message' => $e->getMessage() ]);
			}
		}

		return null;
	}

	private function GetSimpleCryptObject() : SimpleCrypt
	{
		return new SimpleCrypt(MetaModel::GetConfig()->GetEncryptionLibrary());
	}

	public function GetToken(string $sDecryptedToken) : ?iToken
	{
		$bLoginDebug = MetaModel::GetConfig()->Get('login_debug');

		$aFields = explode(':', $sDecryptedToken);
		if (count($aFields) < 2){
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetToken not enough separators.", null, [ 'sDecryptedToken' => $sDecryptedToken ]);
			}
			return null;
		}

		$sId = $aFields[0];
		$sClassName = $aFields[1];

		if ( ! preg_match('/^\d+$/', $sId) ) {
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetToken id not an iTop key.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sId' => $sId ]);
			}
			return null;
		}

		try{
			$oReflectionClass = new \ReflectionClass($sClassName);
			if ($oReflectionClass->implementsInterface(iToken::class)){
				return $this->oMetaModelService->GetObject($sClassName, $sId);
			}

			if ($bLoginDebug){
				TokenAuthLog::Debug("GetToken class not an iToken interface.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sClassName' => $sClassName ]);
			}
		} catch(\ReflectionException $e){
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetToken class not  real class.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sClassName' => $sClassName ]);
			}
		}

		return null;
	}

	public function GetLegacyToken(string $sDecryptedToken) : ?iToken
	{
		$bLoginDebug = MetaModel::GetConfig()->Get('login_debug');

		$aTokenData = json_decode($sDecryptedToken, true);
		if (! is_array($aTokenData)){
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetLegacyToken not a proper json structure.", null, [ 'sDecryptedToken' => $sDecryptedToken ]);
			}
			return null;
		}

		$sClassName = (array_key_exists(self::LEGACY_TOKEN_CLASS, $aTokenData)) ? $aTokenData[self::LEGACY_TOKEN_CLASS] : null;
		$sId = (array_key_exists(self::LEGACY_TOKEN_ID, $aTokenData)) ? $aTokenData[self::LEGACY_TOKEN_ID] : null;

		if (is_null($sClassName) || is_null($sId)){
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetLegacyToken missing class or id in json structure.", null, [ 'sDecryptedToken' => $sDecryptedToken ]);
			}
			return null;
		}

		if ( ! preg_match('/^\d+$/', $sId) ) {
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetLegacyToken id not an iTop key.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sId' => $sId ]);
			}
			return null;
		}

		try {
			$oReflectionClass = new \ReflectionClass($sClassName);
			if ($oReflectionClass->implementsInterface(iToken::class)) {
				return $this->oMetaModelService->GetObject($sClassName, $sId);
			}

			if ($bLoginDebug){
				TokenAuthLog::Debug("GetLegacyToken class not an iToken interface.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sClassName' => $sClassName ]);
			}
		}catch(\ReflectionException $e){
			if ($bLoginDebug){
				TokenAuthLog::Debug("GetLegacyToken class not  real class.", null, [ 'sDecryptedToken' => $sDecryptedToken, 'sClassName' => $sClassName ]);
			}
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
	private function CreateLegacyToken(DBObject $oObject): string
	{
		$aToken = [
			self::LEGACY_TOKEN_ID     => $oObject->GetKey(),
			self::LEGACY_TOKEN_CLASS     => get_class($oObject),
			self::LEGACY_TOKEN_SALT => bin2hex(random_bytes(8)),
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
