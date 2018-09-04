<?php
/**
 * This code is licensed under AGPLv3 license or AfterLogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */
 
namespace Aurora\Modules\LdapAuth;

/**
 * This module adds ability to login to the admin panel as a Super Administrator.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing AfterLogic Software License
 * @copyright Copyright (c) 2018, Afterlogic Corp.
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
	/***** private functions *****/
	/**
	 * @return array
	 */
	public function init()
	{
		$oMailModule = \Aurora\System\Api::getModule('Mail');

		$this->oApiAccountsManager = $oMailModule->oApiAccountsManager;
		$this->oApiServersManager = $oMailModule->oApiServersManager;
		$this->oApiMailManager = $oMailModule->oApiMailManager;

		$this->subscribeEvent('Login', array($this, 'onLogin'), 10);
	}
	
	/**
	 * 
	 * @param type $oAccount
	 * @param type $sDn
	 * @param type $sPassword
	 * @return boolean
	 */
	private function GetLdap($sDn, $sPassword)
	{
		$oLdap = new \Aurora\System\Utils\Ldap((string)$this->getConfig('UsersDn', ''));
		return $oLdap->Connect(
			(string) $this->getConfig('Host', '127.0.0.1'),
			(int) $this->getConfig('Port', 389),
			(string) $sDn,
			(string) $sPassword
		) ? $oLdap : false;
	}	

	/**
	 * Checks if superadmin has specified login.
	 * 
	 * @param string $sLogin Login for checking.
	 * 
	 * @throws \Aurora\System\Exceptions\ApiException
	 */
	public function onCheckAccountExists($aArgs)
	{
		$oSettings =&\Aurora\System\Api::GetSettings();
		if ($aArgs['Login'] === $oSettings->GetConf('AdminLogin'))
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AccountExists);
		}
	}
	
	protected function validateAccount($sLogin, $sPassword)
	{
		$mResult = false;
		
		if (function_exists('ldap_connect'))
		{
			if (0 < strlen($sLogin) && 0 < strlen($sPassword))
			{
				$sLoginField = (string) $this->getConfig('LoginField', '');
				$sEmailField = (string) $this->getConfig('EmailField', '');
				
				
				$oLdap = $this->GetLdap(
					(string) $this->getConfig('BindDn', ''),
					(string) $this->getConfig('BindPassword', '')
				);
				if ($oLdap)
				{
					if ($oLdap->Search('('. $sLoginField .'='.$sLogin.')') && 1 === $oLdap->ResultCount())
					{
						$aData = $oLdap->ResultItem();
						$sDn = !empty($aData['dn']) ? $aData['dn'] : '';
						if (!empty($sDn) && $oLdap->ReBind($sDn, $sPassword))
						{
							if (isset($aData[$sEmailField]))
							{
								if (isset($aData[$sEmailField]['count']))
								{
									$sEmail = !empty($aData[$sEmailField][0]) ? $aData[$sEmailField][0] : '';
								}
								else
								{
									$sEmail = $aData[$sEmailField];
								}
							}
							$mResult = true;
						}
						else
						{
							\Aurora\System\Api::Log('Bad credentials fo user: ' . $sLogin, \Aurora\System\Enums\LogLevel::Full, 'ldap-');
						}
					}
					else
					{
						\Aurora\System\Api::Log('Can`t find user ' . $sLogin . ' on LDAP-server', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
					}
				}
				else
				{
					\Aurora\System\Api::Log('Can`t connect to LDAP-server', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
				}
			}			
		}		
		else
		{
			\Aurora\System\Api::Log('ldap_connect not found', \Aurora\System\Enums\LogLevel::Full, 'ldap-');
		}
		
		return $mResult;
	}

	/**
	 * Tries to log in with specified credentials.
	 * 
	 * @param array $aParams Parameters contain the required credentials.
	 * @param array|mixed $mResult Parameter is passed by reference for further filling with result. Result is the array with data for authentication token.
	 */
	public function onLogin(&$aArgs, &$mResult)
	{
		$sLogin = $aArgs['Login'];
		$sPassword = $aArgs['Password'];
		$iUserId = 0;
		
		$oAccount = $this->oApiAccountsManager->getAccountUsedToAuthorize($sLogin);

		$bNewAccount = false;
		$bAutocreateMailAccountOnNewUserFirstLogin = \Aurora\Modules\Mail\Module::Decorator()->getConfig('AutocreateMailAccountOnNewUserFirstLogin', false);
		
		if ($bAutocreateMailAccountOnNewUserFirstLogin && !$oAccount)
		{
			$sEmail = $sLogin;
			$sDomain = \MailSo\Base\Utils::GetDomainFromEmail($sEmail);
			$oServer = $this->oApiServersManager->GetServerByDomain(strtolower($sDomain));
			if (!$oServer)
			{
				$oServer = $this->oApiServersManager->GetServerByDomain('*');
			}
			if ($oServer)
			{
				$oAccount = \Aurora\System\EAV\Entity::createInstance(\Aurora\System\Api::GetModule('Mail')->getNamespace() . '\Classes\Account', $this->GetName());
				$oAccount->Email = $sLogin;
				$oAccount->IncomingLogin = $sLogin;
				$oAccount->IncomingPassword = $sPassword;
				$oAccount->ServerId = $oServer->EntityId;
				$bNewAccount = true;
			}
		}

		if ($oAccount instanceof \Aurora\Modules\Mail\Classes\Account)
		{
			try
			{
				if ($bAutocreateMailAccountOnNewUserFirstLogin || !$bNewAccount)
				{
					$bNeedToUpdatePasswordOrLogin = $sPassword !== $oAccount->IncomingPassword || $sLogin !== $oAccount->IncomingLogin;
					$oAccount->IncomingPassword = $sPassword;
					$oAccount->IncomingLogin = $sLogin;

					if (!$this->validateAccount($sLogin, $sPassword))
					{
						return false;
					}

					if ($bNeedToUpdatePasswordOrLogin)
					{
						$this->oApiAccountsManager->updateAccount($oAccount);
					}

					$bResult =  true;
				}

				if ($bAutocreateMailAccountOnNewUserFirstLogin && $bNewAccount)
				{
					$oUser = null;
					$aSubArgs = array(
						'UserName' => $sEmail,
						'Email' => $sEmail,
						'UserId' => $iUserId
					);
					$this->broadcastEvent(
						'CreateAccount',
						$aSubArgs,
						$oUser
					);
					if ($oUser instanceof \Aurora\Modules\Core\Classes\User)
					{
						$iUserId = $oUser->EntityId;
						$bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
						$oAccount = \Aurora\Modules\Mail\Module::Decorator()->CreateAccount(
							$iUserId,
							$sEmail,
							$sEmail,
							$sLogin,
							$sPassword,
							array('ServerId' => $oServer->EntityId)
						);
						\Aurora\System\Api::skipCheckUserRole($bPrevState);
						if ($oAccount)
						{
							$oAccount->UseToAuthorize = true;
							$oAccount->UseThreading = $oServer->EnableThreading;
							$bResult = $this->oApiAccountsManager->updateAccount($oAccount);
						}
						else
						{
							$bResult = false;
						}
					}
				}

				if ($bResult)
				{
					$mResult = array(
						'token' => 'auth',
						'sign-me' => $aArgs['SignMe'],
						'id' => $oAccount->IdUser,
						'account' => $oAccount->EntityId,
						'account_type' => $oAccount->getName()
					);
				}
			}
			catch (\Aurora\System\Exceptions\ApiException $oException)
			{
				throw $oException;
			}
			catch (\Exception $oException) {}
		}
		
		
	}
	/***** private functions *****/
}
