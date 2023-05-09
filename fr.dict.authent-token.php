<?php
/**
 * Localized data
 *
 * @copyright   Copyright (C) 2022 Combodo SARL
 */

Dict::Add('FR FR', 'French', 'Français', [
	'AuthentToken:CopyToken' => 'Les identifiants que vous aurez à fournir sont :<p>auth_token=<a>%1$s</a></p>Notez les maintenant, vous ne pourrez plus les afficher ensuite !',
	'AuthentToken:RebuildToken' => 'Regénérer le jeton',
	'AuthentToken:RebuildToken+' => 'Le jeton d\'authentification sera regénéré, ATTENTION le précédent sera perdu et ne pourra plus être utilisé',

	'Class:UserToken' => 'Utilisateur basé sur un jeton',
	'Class:UserToken/Attribute:login' => 'Application distante',
	'Class:UserToken/Attribute:login+' => 'Chaîne d\'identification de l\'application distante',

	'UI:MyAccount' => 'Mon compte',
	'authent-token/Operation:MainPage/Title' => 'Mon compte',
	'MyAccount:SubTitle:user' => 'Mon utilisateur',
	'MyAccount:SubTitle:contact' => 'Mon contact',
	'MyAccount:SubTitle:personaltokens' => 'Mes Tokens',

	'UI:Datatables:Column:RowActions:Label' => '',
	'UI:Datatables:Column:RowActions:Description' => '',
	'UI:Links:ActionRow:DeleteToken' => "Supprimer le token",
	'UI:Links:ActionRow:AddToken' => 'Ajouter un token',
	'UI:Links:ActionRow:EditToken' => "Modifier le token",
	'UI:Links:ActionRow:Edit' => 'Modifier',
	'UI:Links:ActionRow:SaveToken' => 'Sauver le token',

	'AuthentToken:Title:DeleteTokenConfirmation' => 'Confirmation',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Voulez-vous supprimer le token <a>%1$s</a>?',

]);

