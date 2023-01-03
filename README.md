# Extension User authentication by token

 * in the configuration add 'rest-token' to _allowed_login_types_
 * connect using:
   * HTTP Header **Auth-Token**
   * query parameter **auth_token**

## Example


`curl --location -g --request POST 'https://localhost/itop/Develop/webservices/rest.php?version=1.3&XDEBUG_SESSION_START=PHPSTORM&json_data={
"operation": "core/get",
"class": "Person",
"key": "SELECT Person WHERE email LIKE '\''%.fr'\''",
"output_fields": "friendlyname, email"
}' \
--header 'Auth-Token: 1207cc8fd2ea4cecc16d43b723db2c0d49a1a76259a863150c5d93597048e621'`
