<?php
/**
 * Localized data
 *
 * @copyright Copyright (C) 2010-2024 Combodo SAS
 * @license    https://opensource.org/licenses/AGPL-3.0
 * 
 */
/**
 *
 */
Dict::Add('TR TR', 'Turkish', 'Türkçe', [
	'AuthentToken:CopyToken' => 'The credentials you have to provide are:<p>auth_token=<a>%1$s</a></p>Copy them now, you won\'t be able to get them later!~~',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Do you want to delete the token <a>%1$s</a>?~~',
	'AuthentToken:RebuildToken' => 'Rebuild token~~',
	'AuthentToken:RebuildToken+' => 'The authentification token will be recreated, BEWARE the previous one will be lost~~',
	'AuthentToken:Title:DeleteTokenConfirmation' => 'Confirmation~~',
	'Class:PersonalToken' => 'Personal Token~~',
	'Class:PersonalToken+' => 'Personal token for accessing '.ITOP_APPLICATION_SHORT.' webservices, import, export, rest and data synchro~~',
	'Class:PersonalToken/Attribute:application' => 'Application~~',
	'Class:PersonalToken/Attribute:application+' => 'Logical identifier to remember why you have created this token~~',
	'Class:PersonalToken/Attribute:auth_token' => 'Auth token~~',
	'Class:PersonalToken/Attribute:auth_token+' => 'Readable only at generation time~~',
	'Class:PersonalToken/Attribute:expiration_date' => 'Expiration date~~',
	'Class:PersonalToken/Attribute:expiration_date+' => '~~',
	'Class:PersonalToken/Attribute:last_use_date' => 'Last use date~~',
	'Class:PersonalToken/Attribute:last_use_date+' => 'Last time this token was used to connect~~',
	'Class:PersonalToken/Attribute:org_id' => 'Organization~~',
	'Class:PersonalToken/Attribute:org_id+' => 'Organization inherited from the associated user~~',
	'Class:PersonalToken/Attribute:scope' => 'Scope~~',
	'Class:PersonalToken/Attribute:scope+' => 'In which context(s), this token is allowed to be used~~',
	'Class:PersonalToken/Attribute:scope/Value:Export' => 'Export~~',
	'Class:PersonalToken/Attribute:scope/Value:Export+' => '/webservices/export-v2.php~~',
	'Class:PersonalToken/Attribute:scope/Value:Import' => 'Import~~',
	'Class:PersonalToken/Attribute:scope/Value:Import+' => '/webservices/import.php~~',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON~~',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON+' => '/webservices/rest.php~~',
	'Class:PersonalToken/Attribute:scope/Value:Synchro' => 'Synchro~~',
	'Class:PersonalToken/Attribute:scope/Value:Synchro+' => '/synchro/synchro_import.php and /synchro/synchro_exec.php~~',
	'Class:PersonalToken/Attribute:use_count' => 'Use count~~',
	'Class:PersonalToken/Attribute:use_count+' => 'Number of time this token was used to connect~~',
	'Class:PersonalToken/Attribute:user_id' => 'User~~',
	'Class:PersonalToken/Attribute:user_id+' => 'The user from which access rights will be inherited~~',
	'Class:User/Attribute:tokens_list' => 'Personal tokens~~',
	'Class:UserToken' => 'Application Token~~',
	'Class:UserToken+' => 'User for remote applications accessing '.ITOP_APPLICATION_SHORT.' webservices~~',
	'Class:UserToken/Attribute:auth_token' => 'Auth token~~',
	'Class:UserToken/Attribute:auth_token+' => 'Readable only at generation time~~',
	'Class:UserToken/Attribute:login' => 'Remote application~~',
	'Class:UserToken/Attribute:login+' => 'Remote application identification string~~',
	'Class:UserToken/Attribute:scope' => 'Scope~~',
	'Class:UserToken/Attribute:scope+' => 'In which context(s), this token is allowed to be used~~',
	'Class:UserToken/Attribute:scope/Value:Export' => 'Export~~',
	'Class:UserToken/Attribute:scope/Value:Export+' => '/webservices/export-v2.php~~',
	'Class:UserToken/Attribute:scope/Value:Import' => 'Import~~',
	'Class:UserToken/Attribute:scope/Value:Import+' => '/webservices/import.php~~',
	'Class:UserToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON~~',
	'Class:UserToken/Attribute:scope/Value:REST/JSON+' => '/webservices/rest.php~~',
	'Class:UserToken/Attribute:scope/Value:Synchro' => 'Synchro~~',
	'Class:UserToken/Attribute:scope/Value:Synchro+' => '/synchro/synchro_import.php and /synchro/synchro_exec.php~~',
	'Menu:SearchPersonalTokens' => 'Personal tokens~~',
	'Menu:SearchPersonalTokens+' => 'Personal tokens, usable on webservices import, export, rest and datasynchro~~',
	'MyAccount:SubTitle:contact' => 'My contact~~',
	'MyAccount:SubTitle:PersonalTokens' => 'My personal tokens~~',
	'MyAccount:SubTitle:user' => 'My user~~',
	'UI:Datatables:Column:RowActions:Description' => '~~',
	'UI:Datatables:Column:RowActions:Label' => '~~',
	'UI:Links:ActionRow:AddToken' => 'Add a new token~~',
	'UI:Links:ActionRow:DeleteToken' => 'Delete token~~',
	'UI:Links:ActionRow:Edit' => 'Edit~~',
	'UI:Links:ActionRow:EditToken' => 'Edit token~~',
	'UI:Links:ActionRow:SaveToken' => 'Save token~~',
	'UI:MyAccount' => 'My Account~~',
	'authent-token/Operation:MainPage/Title' => 'My Account~~',
]);
