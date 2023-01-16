<?php
/**
 * Localized data
 *
 * @copyright   Copyright (C) 2022 Combodo SARL
 */

Dict::Add('EN US', 'English', 'English', [
	'AuthentToken:CopyToken' => 'The credentials you have to provide are:<p>auth_token=%1$s</p>Copy them now, you won\'t be able to get them later!',
	'AuthentToken:RebuildToken' => 'Rebuild token',
	'AuthentToken:RebuildToken+' => 'The authentification token will be recreated, BEWARE the previous one will be lost',

	'Class:UserToken' => 'Token based user',
	'Class:UserToken/Attribute:login' => 'Remote application',
	'Class:UserToken/Attribute:login+' => 'Remote application identification string',

	'UI:MyAccount' => 'My Account',
	'authent-token/Operation:MainPage/Title' => 'My Account',
	'MyAccount:SubTitle:user' => 'My user',
	'MyAccount:SubTitle:contact' => 'My contact',
	'MyAccount:SubTitle:personaltokens' => 'My personal tokens',

	'UI:Datatables:Column:RowActions:Label' => '',
	'UI:Datatables:Column:RowActions:Description' => '',
	'UI:Links:ActionRow:DeleteToken' => 'Delete token',
	'UI:Links:ActionRow:AddToken' => 'Add a new token',
	'UI:Links:ActionRow:EditToken' => 'Edit token',

	'AuthentToken:DeleteTokenConfirmation' => 'Do you want to remove token (%1$s)?',
]);

