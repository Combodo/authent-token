# iTop module : User authentication by token

## About

This is one of the modules used in iTop packages (Community, Essential, Professional, SaaS) for [iTop](https://github.com/Combodo/iTop).

## Download

Available in iTop 3.1+, not available as a module in iTop Hub.

When downloading directly from GitHub (by cloning or downloading as zip) you will get potentially unstable code, and you will miss
additional modules.


## About Us

This iTop module development is sponsored, led and supported by [Combodo](https://www.combodo.com).

## Usage in a nutshell

 * Add `'rest-token'` to _allowed_login_types_ configuration parameter
 * Connect using either:
   * HTTP Header `Auth-Token`
   * query parameter `auth_token`

_Complete documentation [here](https://www.itophub.io/wiki/page?id=extensions:authent-token)_

### Example

`curl --location -g --request POST 'https://localhost/itop/Develop/webservices/rest.php?version=1.3&XDEBUG_SESSION_START=PHPSTORM&json_data={
"operation": "core/get",
"class": "Person",
"key": "SELECT Person WHERE email LIKE '\''%.fr'\''",
"output_fields": "friendlyname, email"
}' \
--header 'Auth-Token: 1234567890ABCDEF'`
