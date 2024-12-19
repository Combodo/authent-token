<?php
//
// iTop module definition file
//

SetupWebPage::AddModule(
	__FILE__, // Path to the current file, all other file names are relative to the directory containing this file
	'authent-token/2.2.1',
	[
		// Identification
		//
		'label' => 'User authentication by token',
		'category' => 'authentication',

		// Setup
		//
		'dependencies' => [
			'combodo-my-account/1.0.0',
            'itop-profiles-itil/3.2.0',
		],
		'mandatory' => false,
		'visible' => true,

		// Components
		//
		'datamodel' => [
			'vendor/autoload.php',
			'src/Model/PersonalTokenMenu.php',
			'src/Model/AbstractPersonalToken.php',
			'src/Hook/TokenLoginExtension.php',
			'src/Hook/LegacyTokenLoginExtension.php',
			'src/Model/AbstractApplicationToken.php',
			'model.authent-token.php', // Contains the PHP code generated by the "compilation" of datamodel.authent-token.xml
		],
		'webservice' => [

		],
		'data.struct' => [
			// add your 'structure' definition XML files here,
		],
		'data.sample' => [
			// add your sample data XML files here,
		],

		// Documentation
		//
		'doc.manual_setup' => '', // hyperlink to manual setup documentation, if any
		'doc.more_information' => '', // hyperlink to more information, if any

		// Default settings
		//
		'settings' => [
			// Module specific settings go here, if any
		],
	]
);
