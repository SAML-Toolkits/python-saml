# python-saml changelog

### 2.1.5 (Nov 3, 2015)
* [#86](https://github.com/onelogin/python-saml/pull/86) Make idp settings optional (Usefull when validating SP metadata)
* [#79](https://github.com/onelogin/python-saml/pull/79) Remove unnecesary dependence. M2crypto is not used.
* [#77](https://github.com/onelogin/python-saml/pull/77) Fix server_port can be None
* Fix bug on settings constructor related to sp_validation_only
* Make SPNameQualifier optional on the generateNameId method. Avoid the use of SPNameQualifier when generating the NameID on the LogoutRequest builder.
* Allows the RequestedAuthnContext Comparison attribute to be set via settings
* Be able to retrieve Session Timeout after processResponse
* Update documentation. Clarify the use of the certFingerprint

### 2.1.4 (Jul 17, 2015)
* Now the SP is able to select the algorithm to be used on signatures (DSA_SHA1, RSA_SHA1, RSA_SHA256, RSA_SHA384, RSA_SHA512).
* Support sign validation of different kinds of algorithm
* Add demo example of the Bottle framework.
* [#73](https://github.com/onelogin/python-saml/pull/73) Improve decrypt method
* Handle valid but uncommon dsig block with no URI in the reference
* Split the setting check methods. Now 1 method for IdP settings and other for SP settings
* Let the setting object to avoid the IdP setting check. required if we want to publish SP * SAML Metadata when the IdP data is still not provided.

### 2.1.3 (Jun 25, 2015)
* Do accesible the ID of the object Logout Request (id attribute)
* Add SAMLServiceProviderBackend reference to the README.md
* Solve HTTPs issue on demos
* Fix PHP-style array element in settings json
* Add fingerprint algorithm support. Previously the toolkit assumed SHA-1 algorithm
* Fix creation of metadata with no SLS, when using settings.get_sp_metadata()
* Allow configuration of metadata caching/expiry via settings
* Allow metadata signing with SP key specified as config value, not file
* Set NAMEID_UNSPECIFIED as default NameIDFormat to prevent conflicts
* Improve validUntil/cacheDuration metadata settings

### 2.1.2 (Feb 26, 2015)
* Fix wrong element order in generated metadata (SLS before NameID). metadata xsd updated
* Added SLO with nameID and SessionIndex in the demos
* Fix Exception message on Destination validation of the Logout_request

### 2.1.0 (Jan 14, 2015)
* Update the dm.xmlsec.binding library to 1.3.2 (Improved transform support, Workaround for buildout problem)
* Fix flask demo settings example.
* Add nameID & sessionIndex support on Logout Request
* Reject SAML Response if not signed and strict = false
* Add ForceAuh and IsPassive support on AuthN Request

### 2.0.2 (Dec 5, 2014)
* Adding AuthnContextClassRef support
* Process nested StatusCode
* Fix settings bug

### 2.0.1 (Nov 13, 2014)
* SSO and SLO (SP-Initiated and IdP-Initiated).
* Assertion and nameId encryption.
* Assertion signature.
* Message signature: AuthNRequest, LogoutRequest, LogoutResponses.
* Enable an Assertion Consumer Service endpoint.
* Enable a Single Logout Service endpoint.
* Publish the SP metadata (which can be signed).

### 1.1.0 (Sep 4, 2014)
* Security improved, added more checks at the SAMLResponse validation

### 1.0.0 (Jun 26, 2014)
* OneLogin's SAML Python Toolkit v1.0.0








