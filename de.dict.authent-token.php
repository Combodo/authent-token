<?php
/**
 * Localized data
 *
 * @copyright   Copyright (C) 2022 Combodo SARL
 */
Dict::Add('DE DE', 'German', 'Deutsch', [
	'AuthentToken:CopyToken' => 'Die Anmeldedaten (Token), die Sie angeben müssen, lauten: <p>auth_token=<a>%1$s</a></p>Bitte notieren Sie sie jetzt, Sie können sie später nicht mehr anzeigen!',
	'AuthentToken:RebuildToken' => 'Token neu erstellen',
	'AuthentToken:RebuildToken+' => 'Das Authentifizierungs-Token wird neu erstellt, VORSICHT, das vorherige Token geht verloren.',
	'Class:UserToken' => 'Token-basierter Nutzer',
	'Class:UserToken/Attribute:login' => 'Remote-Anwendung',
	'Class:UserToken/Attribute:login+' => 'Identifizierungs-String der Remote-Anwendung',
	'UI:MyAccount' => 'Mein Konto',
	'authent-token/Operation:MainPage/Title' => 'Mein Konto',
	'MyAccount:SubTitle:user' => 'Mein Benutzer',
	'MyAccount:SubTitle:contact' => 'Mein Kontakt',
	'MyAccount:SubTitle:personaltokens' => 'Meine persönlichen Token',
	'UI:Datatables:Column:RowActions:Label' => '',
	'UI:Datatables:Column:RowActions:Description' => '',
	'UI:Links:ActionRow:DeleteToken' => 'Token löschen',
	'UI:Links:ActionRow:AddToken' => 'Neuen Token hinzufügen',
	'UI:Links:ActionRow:EditToken' => 'Token bearbeiten',
	'UI:Links:ActionRow:Edit' => 'Bearbeiten',
	'UI:Links:ActionRow:SaveToken' => 'Token speichern',
	'AuthentToken:Title:DeleteTokenConfirmation' => 'Bestätigen',
	'AuthentToken:Message:DeleteTokenConfirmation' => 'Möchten Sie das Token <a>%1$s</a> löschen?',
]);


//
// Class: PersonalToken
//

Dict::Add('DE DE', 'German', 'Deutsch', array(
	'Class:PersonalToken' => 'Persönlicher Token',
	'Class:PersonalToken+' => '~~',
	'Class:PersonalToken/Attribute:user_id' => 'Benutzer',
	'Class:PersonalToken/Attribute:user_id+' => 'Zugeordneter Benutzer',
	'Class:PersonalToken/Attribute:auth_token' => 'Authentifizierungs-Token',
	'Class:PersonalToken/Attribute:auth_token+' => '~~',
	'Class:PersonalToken/Attribute:application' => 'Anwendung',
	'Class:PersonalToken/Attribute:application+' => '~~',
	'Class:PersonalToken/Attribute:scope' => 'Scope',
	'Class:PersonalToken/Attribute:scope+' => '~~',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON' => 'REST/JSON',
	'Class:PersonalToken/Attribute:scope/Value:REST/JSON+' => '',
	'Class:PersonalToken/Attribute:scope/Value:Synchro' => 'Synchro',
	'Class:PersonalToken/Attribute:scope/Value:Synchro+' => '',
	'Class:PersonalToken/Attribute:scope/Value:Import' => 'Import',
	'Class:PersonalToken/Attribute:scope/Value:Import+' => '',
	'Class:PersonalToken/Attribute:scope/Value:Export' => 'Export',
	'Class:PersonalToken/Attribute:scope/Value:Export+' => '',
	'Class:PersonalToken/Attribute:expiration_date' => 'Ablaufdatum',
	'Class:PersonalToken/Attribute:expiration_date+' => '',
	'Class:PersonalToken/Attribute:use_count' => 'Anmeldungen',
	'Class:PersonalToken/Attribute:use_count+' => 'Anzahl an Anmeldungen mit diesem Token',
	'Class:PersonalToken/Attribute:last_use_date' => 'Letzte Verwendung',
	'Class:PersonalToken/Attribute:last_use_date+' => '',
));

//
// Class: UserToken
//

Dict::Add('DE DE', 'German', 'Deutsch', array(
	'Class:UserToken/Attribute:auth_token' => 'Authentifizierungs-Token',
	'Class:UserToken/Attribute:auth_token+' => '~~',
));
