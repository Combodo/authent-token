<?php
/**
 * Localized data
 *
 * @copyright   Copyright (C) 2022 Combodo SARL
 */
Dict::Add('ES CR', 'Spanish', 'Español, Castellano', [
	'AuthentToken:CopyToken' => 'The credentials you have to provide are:<p>auth_token=<a>%1$s</a></p>Copy them now, you won\'t be able to get them later!~~',
	'AuthentToken:RebuildToken' => 'Rebuild token~~',
	'AuthentToken:RebuildToken+' => 'The authentification token will be recreated, BEWARE the previous one will be lost~~',
	'Class:UserToken' => 'Token based user~~',
	'Class:UserToken/Attribute:login' => 'Remote application~~',
	'Class:UserToken/Attribute:login+' => 'Remote application identification string~~',
	'UI:MyAccount' => 'My Account~~',
	'authent-token/Operation:MainPage/Title' => 'My Account~~',
	'MyAccount:SubTitle:user' => 'My user~~',
	'MyAccount:SubTitle:contact' => 'My contact~~',
	'MyAccount:SubTitle:personaltokens' => 'My personal tokens~~',
	'UI:Datatables:Column:RowActions:Label' => '~~',
	'UI:Datatables:Column:RowActions:Description' => '~~',
	'UI:Links:ActionRow:DeleteToken' => 'Delete token~~',
	'UI:Links:ActionRow:AddToken' => 'Add a new token~~',
	'UI:Links:ActionRow:EditToken' => 'Edit token~~',
	'UI:Links:ActionRow:Edit' => 'Edit~~',
	'UI:Links:ActionRow:SaveToken' => 'Save token~~',
	'AuthentToken:Title:DeleteTokenConfirmation' => 'Confirmation~~',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Do you want to delete the token <a>%1$s</a>?~~',
]);


//
// Class: PersonalToken
//

Dict::Add('ES CR', 'Spanish', 'Español, Castellano', array(
	'Class:PersonalToken' => 'PersonalToken~~',
	'Class:PersonalToken+' => '~~',
	'Class:PersonalToken/Attribute:user_id' => 'User id~~',
	'Class:PersonalToken/Attribute:user_id+' => '~~',
	'Class:PersonalToken/Attribute:auth_token' => 'Auth token~~',
	'Class:PersonalToken/Attribute:auth_token+' => '~~',
	'Class:PersonalToken/Attribute:application' => 'Application~~',
	'Class:PersonalToken/Attribute:application+' => '~~',
	'Class:PersonalToken/Attribute:scope' => 'Scope~~',
	'Class:PersonalToken/Attribute:scope+' => '~~',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON~~',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON+' => '~~',
	'Class:PersonalToken/Attribute:scope/Value:Synchro' => 'Synchro~~',
	'Class:PersonalToken/Attribute:scope/Value:Synchro+' => '~~',
	'Class:PersonalToken/Attribute:scope/Value:Import' => 'Import~~',
	'Class:PersonalToken/Attribute:scope/Value:Import+' => '~~',
	'Class:PersonalToken/Attribute:scope/Value:Export' => 'Export~~',
	'Class:PersonalToken/Attribute:scope/Value:Export+' => '~~',
	'Class:PersonalToken/Attribute:expiration_date' => 'Expiration date~~',
	'Class:PersonalToken/Attribute:expiration_date+' => '~~',
	'Class:PersonalToken/Attribute:use_count' => 'Use count~~',
	'Class:PersonalToken/Attribute:use_count+' => '~~',
	'Class:PersonalToken/Attribute:last_use_date' => 'Last use date~~',
	'Class:PersonalToken/Attribute:last_use_date+' => '~~',
));

//
// Class: UserToken
//

Dict::Add('ES CR', 'Spanish', 'Español, Castellano', array(
	'Class:UserToken/Attribute:auth_token' => 'Auth token~~',
	'Class:UserToken/Attribute:auth_token+' => '~~',
));
