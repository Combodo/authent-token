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


//
// Class: PersonalToken
//

Dict::Add('FR FR', 'French', 'Français', array(
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

Dict::Add('FR FR', 'French', 'Français', array(
	'Class:UserToken/Attribute:auth_token' => 'Auth token~~',
	'Class:UserToken/Attribute:auth_token+' => '~~',
));
