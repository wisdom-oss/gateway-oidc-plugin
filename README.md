<h1 align="center">Gateway OpenID Connect Plugin</h1>
<h3 align="center">gateway-oauth-plugin</h3>
<div align="center">
<p>
🧩 A plugin to extend the Kong API Gateway with an free OpenID Connect 
authentication plugin
</p>
<img alt="Version Badge" src="https://img.shields.io/luarocks/v/captainsuchard/wisdom-gateway-oidc-plugin?style=for-the-badge&label=Version">
<img alt="License Badge" src="https://img.shields.io/github/license/wisdom-oss/gateway-oidc-plugin?style=for-the-badge">
</div>

# About
The [WISdoM project](https://github.com/wisdom-oss) utilizes the Kong API 
Gateway to route requests to their services. To allow the authentication
of users accessing the gateway, usually a plugin directly from Kong Inc. would
be used. However, the plugin that would be used to authenticate users is only
available if a paid subscription is used for the Kong API Gateway. Furthermore,
it does not support all of the features, we need for this project.

## How to use it
The plugin is automatically installed to the API gateway, if the WISdoM project
is deployed to your host.

If you want to use the plugin outside of the WISdoM project you need to install
the plugin using `luarocks` and define it in the configuration of your Kong API
Gateway.

## What does it do?
The plugin takes a request and uses the plugins configuration to get the url
to the discovery endpoint of your OpenID Connect-compliant identity provider.
It then takes the url and requests the output of the discovery endpoint from
which the plugin then extracts the `userinfo` endpoint url.
If the endpoint url has been extracted, the plugin will then use the bearer
token from the incoming request and tries to get the users information.

The users information then is used, to get the username of the user sending the
request, as well the groups they are a member of. These values are then put
into the requests headers as `X-WISdoM-User` and `X-WISdoM-Groups` and the
request continues downstream.

If you want to change the header keys, you should fork this repository and
change them in accordance to the [MIT License](./LICENSE) this plugin is 
released under.