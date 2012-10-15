<?php

return array(
	/**
	 * DB connection, leave null to use default
	 */
	'db_connection' => null,
	
	/**
	 * DB table name for the user table
	 */
	'table_name' => 'users',
	
	/**
	 * DB field name for the user table
	 */
	'field_id' => 'id',
	'field_username' => 'name',
	'field_login_id' => 'login_id',
	'field_password' => 'password',
	'field_last_login' => 'last_login',
	'field_login_hash' => 'login_hash',
	
	/**
	 * Choose which columns are selected,
	 *  must include: login_id, password, last_login, login_hash
	 */
	'table_columns' => array('*'),
	
	/**
	 * Salt for the login hash
	 */
	'login_hash_salt' => '',
);
