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
Dict::Add('FR FR', 'French', 'Français', [
	'AuthentToken:CopyToken' => 'Les identifiants que vous aurez à fournir sont :<p>auth_token=<a>%1$s</a></p>Notez les maintenant, vous ne pourrez plus les afficher ensuite !',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Voulez-vous supprimer le jeton <a>%1$s</a>?',
	'AuthentToken:RebuildToken' => 'Régénérer le jeton',
	'AuthentToken:RebuildToken+' => 'Le jeton d\'authentification sera régénéré, ATTENTION le précédent sera perdu et ne pourra plus être utilisé',
	'AuthentToken:Title:DeleteTokenConfirmation' => 'Confirmation',
	'Class:PersonalToken' => 'Jeton individuel de connexion',
	'Class:PersonalToken+' => 'Jeton permettant à une personne d\'accéder aux webservices, rest et synchro',
	'Class:PersonalToken/Attribute:application' => 'Application',
	'Class:PersonalToken/Attribute:application+' => 'Pour identifier ce jeton, indiquez l\'application pour laquelle il a été généré',
	'Class:PersonalToken/Attribute:auth_token' => 'Jeton d\'authentification',
	'Class:PersonalToken/Attribute:auth_token+' => 'Lisible uniquement à la génération',
	'Class:PersonalToken/Attribute:expiration_date' => 'Date d\'expiration',
	'Class:PersonalToken/Attribute:expiration_date+' => 'Ce jeton n\'est plus utilisable au délà de cette date',
	'Class:PersonalToken/Attribute:last_use_date' => 'Dernière utilisation',
	'Class:PersonalToken/Attribute:last_use_date+' => 'Dernière fois où ce jeton a été utilisé pour ce connecter',
	'Class:PersonalToken/Attribute:org_id' => 'Organisation',
	'Class:PersonalToken/Attribute:org_id+' => 'Organisation héritée de l\'utilisateur associé',
	'Class:PersonalToken/Attribute:scope' => 'Périmètre',
	'Class:PersonalToken/Attribute:scope+' => 'Les points d\'entrées autorisés à la connexion avec ce jeton',
	'Class:PersonalToken/Attribute:scope/Value:Export' => 'Export',
	'Class:PersonalToken/Attribute:scope/Value:Export+' => '/webservices/export-v2.php',
	'Class:PersonalToken/Attribute:scope/Value:Import' => 'Import',
	'Class:PersonalToken/Attribute:scope/Value:Import+' => '/webservices/import.php',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON+' => '/webservices/rest.php',
	'Class:PersonalToken/Attribute:scope/Value:Synchro' => 'Synchro',
	'Class:PersonalToken/Attribute:scope/Value:Synchro+' => '/synchro/synchro_import.php et /synchro/synchro_exec.php',
	'Class:PersonalToken/Attribute:use_count' => 'Compteur d\'accès',
	'Class:PersonalToken/Attribute:use_count+' => 'Nombre de fois où ce jeton a été utilisé pour ce connecter',
	'Class:PersonalToken/Attribute:user_id' => 'Utilisateur',
	'Class:PersonalToken/Attribute:user_id+' => 'Utilisateur dont les droits sont utilisés lors d\'une connexion avec ce jeton',
	'Class:User/Attribute:tokens_list' => 'Jetons de connexion',
	'Class:UserToken' => 'Utilisateur applicatif',
	'Class:UserToken+' => 'Utilisateur applicatif utilisant un jeton et limité aux webservices, rest et synchro',
	'Class:UserToken/Attribute:auth_token' => 'Jeton d\'authentification',
	'Class:UserToken/Attribute:auth_token+' => 'Lisible uniquement à la génération',
	'Class:UserToken/Attribute:login' => 'Application distante',
	'Class:UserToken/Attribute:login+' => 'Chaîne d\'identification de l\'application distante',
	'Class:UserToken/Attribute:scope' => 'Périmètre',
	'Class:UserToken/Attribute:scope+' => 'Les points d\'entrées autorisés à la connexion avec ce jeton',
	'Class:UserToken/Attribute:scope/Value:Export' => 'Export',
	'Class:UserToken/Attribute:scope/Value:Export+' => '/webservices/export-v2.php',
	'Class:UserToken/Attribute:scope/Value:Import' => 'Import',
	'Class:UserToken/Attribute:scope/Value:Import+' => '/webservices/import.php',
	'Class:UserToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON',
	'Class:UserToken/Attribute:scope/Value:REST/JSON+' => '/webservices/rest.php',
	'Class:UserToken/Attribute:scope/Value:Synchro' => 'Synchro',
	'Class:UserToken/Attribute:scope/Value:Synchro+' => '/synchro/synchro_import.php et /synchro/synchro_exec.php',
	'Menu:SearchPersonalTokens' => 'Jetons individuels de connexion',
	'Menu:SearchPersonalTokens+' => 'Jetons individuels de connexion permettant à une personne d\'accéder aux webservices, import, export, rest et synchro',
	'MyAccount:SubTitle:contact' => 'Mon contact',
	'MyAccount:SubTitle:PersonalTokens' => 'Mes jetons de connexion',
	'MyAccount:SubTitle:user' => 'Mon utilisateur',
	'UI:Datatables:Column:RowActions:Description' => '',
	'UI:Datatables:Column:RowActions:Label' => '',
	'UI:Links:ActionRow:AddToken' => 'Créer un jeton de connection',
	'UI:Links:ActionRow:DeleteToken' => 'Supprimer ce jeton',
	'UI:Links:ActionRow:Edit' => 'Modifier',
	'UI:Links:ActionRow:EditToken' => 'Modifier ce jeton',
	'UI:Links:ActionRow:SaveToken' => 'Sauver le jeton',
	'UI:MyAccount' => 'Mon compte',
	'authent-token/Operation:MainPage/Title' => 'Mon compte',
]);
