<?php
/**
 * Localized data
 *
 * @copyright   Copyright (C) 2024 Combodo SAS
 */

Dict::Add('EN GB', 'British English', 'British English', array(
	'AuthentToken:CopyToken' => 'The credentials you have to provide are:<p>auth_token=<a>%1$s</a></p>Copy them now, you won\'t be able to get them later!',
	'AuthentToken:RebuildToken' => 'Rebuild token',
	'AuthentToken:RebuildToken+' => 'The authentication token will be recreated, BEWARE the previous one will be lost',
	'MyAccount:SubTitle:PersonalTokens' => 'My personal tokens',

	'UI:Datatables:Column:RowActions:Label' => '',
	'UI:Datatables:Column:RowActions:Description' => '',
	'UI:Links:ActionRow:DeleteToken' => 'Delete token',
	'UI:Links:ActionRow:AddToken' => 'Add a new token',
	'UI:Links:ActionRow:EditToken' => 'Edit token',
	'UI:Links:ActionRow:Edit' => 'Edit',
	'UI:Links:ActionRow:SaveToken' => 'Save token',

	'AuthentToken:Title:DeleteTokenConfirmation' => 'Confirmation',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Do you want to delete the token <a>%1$s</a>?',

	'Class:User/Attribute:tokens_list' => 'Personal tokens',
	'Menu:SearchPersonalTokens' => 'Personal tokens',
	'Menu:SearchPersonalTokens+' => 'Personal tokens, usable on web services import, export, rest and data synchronisation',

));


//
// Class: PersonalToken
//

Dict::Add('EN GB', 'British English', 'British English', array(
	'Class:PersonalToken' => 'Personal Token',
	'Class:PersonalToken+' => 'Personal token for accessing '.ITOP_APPLICATION_SHORT.' webservices, import, export, rest and data synchro',
	'Class:PersonalToken/Attribute:user_id' => 'User',
	'Class:PersonalToken/Attribute:user_id+' => 'The user from which access rights will be inherited',
	'Class:PersonalToken/Attribute:org_id' => 'Organisation',
	'Class:PersonalToken/Attribute:org_id+' => 'Organisation inherited from the associated user',
	'Class:PersonalToken/Attribute:auth_token' => 'Auth token',
	'Class:PersonalToken/Attribute:auth_token+' => 'Readable only at generation time',
	'Class:PersonalToken/Attribute:application' => 'Application',
	'Class:PersonalToken/Attribute:application+' => 'Logical identifier to remember why you have created this token',
	'Class:PersonalToken/Attribute:scope' => 'Scope',
	'Class:PersonalToken/Attribute:scope+' => 'In which context(s), this token is allowed to be used',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON+' => 'No translation needed.',
	'Class:PersonalToken/Attribute:scope/Value:Synchro' => 'Synchro',
	'Class:PersonalToken/Attribute:scope/Value:Synchro+' => '/ syncho / syncho_import.php and / syncho / syncho_exec.php',
	'Class:PersonalToken/Attribute:scope/Value:Import' => 'Import',
	'Class:PersonalToken/Attribute:scope/Value:Import+' => 'No translation needed.',
	'Class:PersonalToken/Attribute:scope/Value:Export' => 'Export',
	'Class:PersonalToken/Attribute:scope/Value:Export+' => 'No translation needed.',
	'Class:PersonalToken/Attribute:expiration_date' => 'Expiration date',
	'Class:PersonalToken/Attribute:expiration_date+' => '',
	'Class:PersonalToken/Attribute:use_count' => 'Use count',
	'Class:PersonalToken/Attribute:use_count+' => 'Number of times this token was used to connect',
	'Class:PersonalToken/Attribute:last_use_date' => 'Last use date',
	'Class:PersonalToken/Attribute:last_use_date+' => 'Last time this token was used to connect',
));

//
// Class: UserToken
//

Dict::Add('EN GB', 'British English', 'British English', array(
	'Class:UserToken' => 'Application Token',
    'Class:UserToken+' => 'User for remote applications accessing '.ITOP_APPLICATION_SHORT.' webservices',
	'Class:UserToken/Attribute:login' => 'Remote application',
	'Class:UserToken/Attribute:login+' => 'Remote application identification string',
	'Class:UserToken/Attribute:auth_token' => 'Auth token',
	'Class:UserToken/Attribute:auth_token+' => 'Readable only at generation time',
	'Class:UserToken/Attribute:scope' => 'Scope',
	'Class:UserToken/Attribute:scope+' => 'In which context(s), is this token allowed to be used',
	'Class:UserToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON',
	'Class:UserToken/Attribute:scope/Value:REST/JSON+' => 'No translation needed.',
	'Class:UserToken/Attribute:scope/Value:Synchro' => 'Synchro',
	'Class:UserToken/Attribute:scope/Value:Synchro+' => '/ syncho/synchro_import.php and /synchro/synchro_exec.php',
	'Class:UserToken/Attribute:scope/Value:Import' => 'Import',
	'Class:UserToken/Attribute:scope/Value:Import+' => '/webservices/import.php',
	'Class:UserToken/Attribute:scope/Value:Export' => 'Export',
	'Class:UserToken/Attribute:scope/Value:Export+' => '/webservices/export-v2.php',
));
