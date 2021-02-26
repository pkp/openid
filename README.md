# OJS Plugin for OpenID integration

![CI Test](https://github.com/leibniz-psychology/pkp-openid/workflows/CI%20Test/badge.svg?branch=master)

![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/leibniz-psychology/pkp-openid?include_prereleases&label=latest%20release)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/leibniz-psychology/pkp-openid)
![GitHub](https://img.shields.io/github/license/leibniz-psychology/pkp-openid)
[![OJS-Version](https://img.shields.io/badge/pkp--ojs-3.3-brightgreen)](https://github.com/pkp/ojs/tree/master)
![GitHub All Releases](https://img.shields.io/github/downloads/leibniz-psychology/pkp-openid/total)


<a href="http://translate.pkp.sfu.ca/engage/plugins/?utm_source=widget">
<img src="http://translate.pkp.sfu.ca/widgets/plugins/-/openid/287x66-black.png" alt="Übersetzungsstatus" />
</a>

## Description:
Currently, PKP's Open Journal System (OJS) does not offer the possibility of OpenID authentication using single sign-on providers. There are also no fully functional community plugins available, which solve this problem. Actually, there is an [OAuth plugin](https://github.com/ulsdevteam/pkp-oauth) that was created in the [Fredericton Sprint](https://pkp.sfu.ca/2016/11/14/fall-2016-sprint-report-oauth-integration/) in 2016, which was ultimately forked into the [ORCID plugin](https://github.com/pkp/orcidProfile). The OAuth plugin is used as basis for the development of this OpenID plugin, because fundamental functions for an authentication like receiving the authentication code and the JSON Web Token (JWT) were available. When the development of this plugin is completed, it will be made available to the PKP community via PKP's plugin gallery and maintained for future OJS versions.

## Features:
- Authentication via OpenID provider, i.e. the local OJS login is completely replaced. To keep the login secure, the JWT is validated via a public key before the user is logged in.
- Registration of new users via OpenID provider. User data (e-mail, given name, family name, OpenID identifier) is transferred from the Provider to OJS and used for registration.
- Merge existing user accounts: It is possible to connect existing OJS accounts to the OpenID account. This process must be done by the users themself to keep the administration effort as simple as possible. After the accounts are connected, local login is disabled for these accounts and the users have to authenticate via OpenID.
- Automatic generation of an OJS-API key to simplify the connection between OJS and third-party software. Currently, users have to generate this key manually, which is very cumbersome in case of developing an inhouse software infrastructure.
