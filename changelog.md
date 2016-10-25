# python-saml changelog

### 2.2.0 (Oct 14, 2016)
* Several security improvements:
  * Conditions element required and unique.
  * AuthnStatement element required and unique.
  * SPNameQualifier must math the SP EntityID
  * Reject saml:Attribute element with same “Name” attribute
  * Reject empty nameID
  * Require Issuer element. (Must match IdP EntityID).
  * Destination value can't be blank (if present must match ACS URL).
  * Check that the EncryptedAssertion element only contains 1 Assertion element.
* Improve Signature validation process
* [#149](https://github.com/onelogin/python-saml/pull/149) Work-around for xmlsec.initialize
* [#151](https://github.com/onelogin/python-saml/pull/151) Fix flask demo error handling and improve documentation
* [#152](https://github.com/onelogin/python-saml/pull/152) Update LICENSE to include MIT rather than BSD license 
* [#155](https://github.com/onelogin/python-saml/pull/155) Fix typographical errors in docstring
* Fix RequestedAttribute Issue
* Fix __build_signature method. If relay_state is null not be part of the SignQuery
* [#164](https://github.com/onelogin/python-saml/pull/164) Add support for non-ascii fields in settings


### 2.1.9 (Jun 27, 2016)
* Change the decrypt assertion process.
* Add 2 extra validations to prevent Signature wrapping attacks.

### 2.1.8 (Jun 02, 2016)
* Fix Metadata XML (RequestedAttribute)
* Fix Windows specific Unix date formatting bug.
* Docs for OSx instlltion of libsecxml1
* Fix SHA384 Constant URI
* [#142](https://github.com/onelogin/python-saml/pull/142) Refactor of settings.py to make it a little more readable.
* Bugfix for ADFS lowercase signatures
* READMEs suggested wrong cert name

### 2.1.7 (May 14, 2016)
* [#117](https://github.com/onelogin/python-saml/pull/117) AttributeConsumingService support
* [#114](https://github.com/onelogin/python-saml/pull/114) Compare Assertion InResponseTo if not None
* Return empty list when there are no audience values
* Passing NameQualifier through to logout request
* Make deflate process when retrieving built SAML messages optional
* Add debug parameter to decrypt method
* Fix Idp Metadata parser
* Add documentation related to the new IdP metadata parser methods
* Extract the already encoded value directly from get_data
* [#133](https://github.com/onelogin/python-saml/pull/133) Fix typo and add extra assertions in util decrypt test
* Fix Signature with empty URI support
* Allow AuthnRequest with no NameIDPolicy
* Remove requirement of NameID on SAML responses

### 2.1.6 (Feb 15, 2016)
* Prevent signature wrapping attack!!
* [#111](https://github.com/onelogin/python-saml/pull/111) Add support for nested `NameID` children inside `AttributeValue`s
* ALOWED Misspell
* Improve how we obtain the settings path.
* Update docs adding reference to test depencence installation
* Fix Organization element on SP metadata.
* [#100](https://github.com/onelogin/python-saml/pull/100) Support Responses that don't have AttributeStatements.

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








