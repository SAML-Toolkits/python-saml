# python-saml changelog
### 2.13.0 (Oct 9, 2023)
- Improve get_metadata method from Parser, allowing to set timeouts and headers
- Fix expired payloads used on tests
- Updated content from docs folder
- Remove references of OneLogin as maintainer

### 2.12.0 (Dec 28, 2022)
- Remove version restriction on lxml dependency
- Update Demo Bottle
- Updated Travis file. Forced lxml to be installed using no-validate_binary

### 2.11.1 (Jan 28, 2022)
- lxml fixed to be lower than 4.7.1 since it seems to have issues validating the signature of encrypted elements  See https://github.com/onelogin/python3-saml/issues/292

### 2.11.0 (Jan 28, 2022)
- [#292](https://github.com/onelogin/python-saml/pull/292) Add rejectDeprecatedAlgorithm settings in order to be able reject messages signed with deprecated algorithms.
- Upgrade dm.xmlsec.binding to 2.1
- Set sha256 and rsa-sha256 as default algorithms
- Added warning about Open Redirect and Reply attacks

### 2.10.0 (Jul 23, 2021)
* Removed CC-BY-SA 3.0 non compliant implementation of dict_deep_merge
* Update expired dates from test responses
* Add warning about the use of OneLogin_Saml2_IdPMetadataParser class about SSRF attacks
* Migrate from Travis to Github Actions

### 2.9.0 (Jan 13, 2021)
* Destination URL Comparison is now case-insensitive for netloc
* Support single-label-domains as valid. New security parameter allowSingleLabelDomains
* Added get_idp_sso_url, get_idp_slo_url and get_idp_slo_response_url methods to the Settings class and use it in the toolkit
* [#267](https://github.com/onelogin/python-saml/issues/267) Custom lxml parser based on the one defined at xmldefused. Parser will ignore comments and processing instructions and by default have deactivated huge_tree, DTD and access to external documents
* Add get_friendlyname_attributes support
* Remove external lib method get_ext_lib_path. Add set_cert_path in order to allow set the cert path in a different folder than the toolkit
* Add python2 deprecation info
* [#269](https://github.com/onelogin/python-saml/issues/269) Add sha256 instead sha1 algorithm for sign/digest as recommended value on documentation and settings

### 2.8.0 (NOv 20, 2019)
* [#258](https://github.com/onelogin/python-saml/issues/258) Fix failOnAuthnContextMismatch feature
* [#250](https://github.com/onelogin/python-saml/issues/250) Allow any number of decimal places for seconds on SAML datetimes
* Update demo versions. Improve them and add Tornado demo.


### 2.7.0 (Sep 11, 2019)
* Set true as the default value for strict setting

### 2.6.0 (Jul 02, 2019)
* Adjusted acs endpoint to extract NameQualifier and SPNameQualifier from SAMLResponse. Adjusted single logout service to provide NameQualifier and SPNameQualifier to logout method. Add getNameIdNameQualifier to Auth and SamlResponse. Extend logout method from Auth and LogoutRequest constructor to support SPNameQualifier parameter. Align LogoutRequest constructor with SAML specs
* Added get_in_response_to method to Response and LogoutResponse classes
* Add get_last_authn_contexts method
* Fix bug on friendlyName/nameFormat parameters on RequestedAttribute elements. Wrong variable name caused FriendlyName to overwrite NameFormat
* Add support for Subjects on AuthNRequests by the new name_id_value_req parameeter.Fix testshib test. Improve README: Added inline markup to important references
* Update defusedxml
* Fix path in flask demo

### 2.5.0 (Jan 29, 2019)
* Security improvements. Use of tagid to prevent XPath injection. Disable DTD on fromstring defusedxml method
* [#239](https://github.com/onelogin/python-saml/issues/239) Check that the response has all of the AuthnContexts that we provided
* Fixed a ValidationError misspelling
* Don't require compression on LogoutResponse messages by relaxing the decode_base64_and_inflate method
* Add expected/received in WRONG_ISSUER error
* If debug enable, print reason for the SAMLResponse invalidation
* [#238](https://github.com/onelogin/python-saml/issues/238) Fix DSA constant
* Start using flake8 for code quality

### 2.4.2 (Sep 05, 2018)
* Update dm.xmlsec.binding dependency to 1.3.7
* Update pylint dependency to 1.9.1
* Update Django demo to use LTS version of Django

### 2.4.1 (Apr 25, 2018)
* Add ID to EntityDescriptor before sign it on add_sign method. Improve the way ds namespace is handled in add_sign method
* Update defusedxml, coveralls and coverage dependencies
* Update copyright and license reference

### 2.4.0 (Feb 27, 2018)
* Fix vulnerability [CVE-2017-11427](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11427). Process text of nodes properly, ignoring comments
* Improve how fingerprint is calcultated
* Fix issue with LogoutRequest rejected by ADFS due NameID with unspecified format instead no format attribute
* Be able to invalidate a SAMLResponse if it contains InResponseTo value but no RequestId parameter provided at the is_valid method. See rejectUnsolicitedResponsesWithInResponseTo security parameter (By default deactivated)
* Fix signature position in the SP metadata
* Redefine NSMAP constant

### 2.3.0 (Sep 15, 2017)
* [#205](https://github.com/onelogin/python-saml/pull/205) Improve decrypt method, Add an option to decrypt an element in place or copy it before decryption.
* [#204](https://github.com/onelogin/python-saml/pull/204) On a LogoutRequest if the NameIdFormat is entity, NameQualifier and SPNameQualifier will be ommited. If the NameIdFormat is not entity and a NameQualifier is provided, then the SPNameQualifier will be also added.
* Be able to get at the auth object the last processed ID (response/assertion) and the last generated ID.
* Reset errorReason attribute of the auth object before each Process method
* Fix issue on getting multiple certs when only sign or encryption certs
* Allow empty nameid if setting wantNameId is false. Only raise Exceptions when strict mode is enabled

### 2.2.3 (Jun 15, 2017)
* Replace some etree.tostring calls, that were introduced recfently,  by the sanitized call provided by defusedxml
* Update dm.xmlsec.binding requirement to 1.3.3 version

### 2.2.2 (May 18, 2017)
* Be able to relax SSL Certificate verification when retrieving idp metadata
* [#195](https://github.com/onelogin/python-saml/pull/195) Be able to register future SP x509cert on the settings and publish it on SP metadata
* [#195](https://github.com/onelogin/python-saml/pull/195) Be able to register more than 1 Identity Provider x509cert, linked with an specific use (signing or encryption
* [#195](https://github.com/onelogin/python-saml/pull/195) Allow metadata to be retrieved from source containing data of multiple entities
* [#195](https://github.com/onelogin/python-saml/pull/195) Adapt IdP XML metadata parser to take care of multiple IdP certtificates and be able to inject the data obtained on the settings.
* [#194](https://github.com/onelogin/python-saml/pull/194) Publish KeyDescriptor[use=encryption] only when required
* [#190](https://github.com/onelogin/python-saml/pull/190) Checking the status of response before assertion count
* Add Pyramid demo example
* Allows underscores in URL hosts
* NameID Format improvements
* [#184](https://github.com/onelogin/python-saml/pull/184) Be able to provide a NameIDFormat to LogoutRequest
* [#180](https://github.com/onelogin/python-saml/pull/180) Add DigestMethod support. (Add sign_algorithm and digest_algorithm parameters to sign_metadata and add_sign)
* Validate serial number as string to work around libxml2 limitation
* Make the Issuer on the Response Optional


### 2.2.1 (Jan 11, 2017)
* [#175](https://github.com/onelogin/python-saml/pull/175)  Optionally raise detailed exceptions vs. returning False.
Implement a more specific exception class for handling some validation errors. Improve/Fix tests
* [#171](https://github.com/onelogin/python-saml/pull/171) Add hooks to retrieve last-sent and last-received requests and responses
* Improved inResponse validation on Responses
* [#173](https://github.com/onelogin/python-saml/pull/173) Fix attributeConsumingService serviceName format in README


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
* SAML Python Toolkit v1.0.0
