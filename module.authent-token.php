<?php
//
// iTop module definition file
//

SetupWebPage::AddModule(
	__FILE__, // Path to the current file, all other file names are relative to the directory containing this file
	'authent-token/2.0.0',
	array(
		// Identification
		//
		'label' => 'User authentication by token',
		'category' => 'business',

		// Setup
		//
		'dependencies' => array(
			'itop-welcome-itil/2.7.0||itop-structure/3.0.0'
		),
		'mandatory' => true,
		'visible' => false,

		// Components
		//
		'datamodel' => array(
			'vendor/autoload.php',
			'legacy/Helper/Session.php',
			'src/Model/AbstractPersonalToken.php',
			'src/Hook/TokenLoginExtension.php',
			'src/Hook/LegacyTokenLoginExtension.php',
			'src/Model/AbstractApplicationToken.php',
			'src/Hook/MyAccountPopupMenuExtension.php',
			'model.authent-token.php', // Contains the PHP code generated by the "compilation" of datamodel.authent-token.xml
		),
		'webservice' => array(

		),
		'data.struct' => array(
			// add your 'structure' definition XML files here,
		),
		'data.sample' => array(
			// add your sample data XML files here,
		),

		// Documentation
		//
		'doc.manual_setup' => '', // hyperlink to manual setup documentation, if any
		'doc.more_information' => '', // hyperlink to more information, if any

		// Default settings
		//
		'settings' => array(
			// Module specific settings go here, if any
		),
	)
);
