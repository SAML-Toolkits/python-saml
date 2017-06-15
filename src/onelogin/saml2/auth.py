# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Auth class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Main class of OneLogin's Python Toolkit.

Initializes the SP SAML instance

"""

from base64 import b64encode
from urllib import quote_plus
from defusedxml.lxml import tostring

from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, xmlsec
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request


class OneLogin_Saml2_Auth(object):
    """

    This class implements the SP SAML instance.

    Defines the methods that you can invoke in your application in
    order to add SAML support (initiates SSO, initiates SLO, processes a
    SAML Response, a Logout Request or a Logout Response).
    """

    def __init__(self, request_data, old_settings=None, custom_base_path=None):
        """
        Initializes the SP SAML instance.

        :param request_data: Request Data
        :type request_data: dict

        :param settings: Optional. SAML Toolkit Settings
        :type settings: dict

        :param custom_base_path: Optional. Path where are stored the settings file and the cert folder
        :type custom_base_path: string
        """
        self.__request_data = request_data
        self.__settings = OneLogin_Saml2_Settings(old_settings, custom_base_path)
        self.__attributes = []
        self.__nameid = None
        self.__nameid_format = None
        self.__session_index = None
        self.__session_expiration = None
        self.__authenticated = False
        self.__errors = []
        self.__error_reason = None
        self.__last_request_id = None
        self.__last_request = None
        self.__last_response = None

    def get_settings(self):
        """
        Returns the settings info
        :return: Setting info
        :rtype: OneLogin_Saml2_Setting object
        """
        return self.__settings

    def set_strict(self, value):
        """
        Set the strict mode active/disable

        :param value:
        :type value: bool
        """
        assert isinstance(value, bool)
        self.__settings.set_strict(value)

    def process_response(self, request_id=None):
        """
        Process the SAML Response sent by the IdP.

        :param request_id: Is an optional argument. Is the ID of the AuthNRequest sent by this SP to the IdP.
        :type request_id: string

        :raises: OneLogin_Saml2_Error.SAML_RESPONSE_NOT_FOUND, when a POST with a SAMLResponse is not found
        """
        self.__errors = []

        if 'post_data' in self.__request_data and 'SAMLResponse' in self.__request_data['post_data']:
            # AuthnResponse -- HTTP_POST Binding
            response = OneLogin_Saml2_Response(self.__settings, self.__request_data['post_data']['SAMLResponse'])
            self.__last_response = response.get_xml_document()
            if response.is_valid(self.__request_data, request_id):
                self.__attributes = response.get_attributes()
                self.__nameid = response.get_nameid()
                self.__nameid_format = response.get_nameid_format()
                self.__session_index = response.get_session_index()
                self.__session_expiration = response.get_session_not_on_or_after()
                self.__authenticated = True

            else:
                self.__errors.append('invalid_response')
                self.__error_reason = response.get_error()

        else:
            self.__errors.append('invalid_binding')
            raise OneLogin_Saml2_Error(
                'SAML Response not found, Only supported HTTP_POST Binding',
                OneLogin_Saml2_Error.SAML_RESPONSE_NOT_FOUND
            )

    def process_slo(self, keep_local_session=False, request_id=None, delete_session_cb=None):
        """
        Process the SAML Logout Response / Logout Request sent by the IdP.

        :param keep_local_session: When false will destroy the local session, otherwise will destroy it
        :type keep_local_session: bool

        :param request_id: The ID of the LogoutRequest sent by this SP to the IdP
        :type request_id: string

        :returns: Redirection URL
        """
        self.__errors = []

        if 'get_data' in self.__request_data and 'SAMLResponse' in self.__request_data['get_data']:
            logout_response = OneLogin_Saml2_Logout_Response(self.__settings, self.__request_data['get_data']['SAMLResponse'])
            self.__last_response = logout_response.get_xml()
            if not logout_response.is_valid(self.__request_data, request_id):
                self.__errors.append('invalid_logout_response')
                self.__error_reason = logout_response.get_error()
            elif logout_response.get_status() != OneLogin_Saml2_Constants.STATUS_SUCCESS:
                self.__errors.append('logout_not_success')
            elif not keep_local_session:
                OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

        elif 'get_data' in self.__request_data and 'SAMLRequest' in self.__request_data['get_data']:
            logout_request = OneLogin_Saml2_Logout_Request(self.__settings, self.__request_data['get_data']['SAMLRequest'])
            self.__last_request = logout_request.get_xml()
            if not logout_request.is_valid(self.__request_data):
                self.__errors.append('invalid_logout_request')
                self.__error_reason = logout_request.get_error()
            else:
                if not keep_local_session:
                    OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

                in_response_to = logout_request.id
                response_builder = OneLogin_Saml2_Logout_Response(self.__settings)
                response_builder.build(in_response_to)
                self.__last_response = response_builder.get_xml()
                logout_response = response_builder.get_response()

                parameters = {'SAMLResponse': logout_response}
                if 'RelayState' in self.__request_data['get_data']:
                    parameters['RelayState'] = self.__request_data['get_data']['RelayState']
                # else:
                #    parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self.__request_data)

                security = self.__settings.get_security_data()
                if 'logoutResponseSigned' in security and security['logoutResponseSigned']:
                    parameters['SigAlg'] = security['signatureAlgorithm']
                    parameters['Signature'] = self.build_response_signature(logout_response, parameters.get('RelayState', None), security['signatureAlgorithm'])

                return self.redirect_to(self.get_slo_url(), parameters)
        else:
            self.__errors.append('invalid_binding')
            raise OneLogin_Saml2_Error(
                'SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding',
                OneLogin_Saml2_Error.SAML_LOGOUTMESSAGE_NOT_FOUND
            )

    def redirect_to(self, url=None, parameters={}):
        """
        Redirects the user to the URL passed by parameter or to the URL that we defined in our SSO Request.

        :param url: The target URL to redirect the user
        :type url: string
        :param parameters: Extra parameters to be passed as part of the URL
        :type parameters: dict

        :returns: Redirection URL
        """
        if url is None and 'RelayState' in self.__request_data['get_data']:
            url = self.__request_data['get_data']['RelayState']
        return OneLogin_Saml2_Utils.redirect(url, parameters, request_data=self.__request_data)

    def is_authenticated(self):
        """
        Checks if the user is authenticated or not.

        :returns: True if is authenticated, False if not
        :rtype: bool
        """
        return self.__authenticated

    def get_attributes(self):
        """
        Returns the set of SAML attributes.

        :returns: SAML attributes
        :rtype: dict
        """
        return self.__attributes

    def get_nameid(self):
        """
        Returns the nameID.

        :returns: NameID
        :rtype: string|None
        """
        return self.__nameid

    def get_nameid_format(self):
        """
        Returns the nameID Format.

        :returns: NameID Format
        :rtype: string|None
        """
        return self.__nameid_format

    def get_session_index(self):
        """
        Returns the SessionIndex from the AuthnStatement.
        :returns: The SessionIndex of the assertion
        :rtype: string
        """
        return self.__session_index

    def get_session_expiration(self):
        """
        Returns the SessionNotOnOrAfter from the AuthnStatement.
        :returns: The SessionNotOnOrAfter of the assertion
        :rtype: DateTime|None
        """
        return self.__session_expiration

    def get_errors(self):
        """
        Returns a list with code errors if something went wrong

        :returns: List of errors
        :rtype: list
        """
        return self.__errors

    def get_last_error_reason(self):
        """
        Returns the reason for the last error

        :returns: Reason of the last error
        :rtype: None | string
        """
        return self.__error_reason

    def get_attribute(self, name):
        """
        Returns the requested SAML attribute.

        :param name: Name of the attribute
        :type name: string

        :returns: Attribute value if exists or []
        :rtype: string
        """
        assert isinstance(name, basestring)
        value = None
        if self.__attributes and name in self.__attributes.keys():
            value = self.__attributes[name]
        return value

    def get_last_request_id(self):
        """
        :returns: The ID of the last Request SAML message generated.
        :rtype: string
        """
        return self.__last_request_id

    def login(self, return_to=None, force_authn=False, is_passive=False, set_nameid_policy=True):
        """
        Initiates the SSO process.

        :param return_to: Optional argument. The target URL the user should be redirected to after login.
        :type return_to: string

        :param force_authn: Optional argument. When true the AuthNRequest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNRequest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNRequest will set a nameIdPolicy element.
        :type set_nameid_policy: bool

        :returns: Redirection URL
        :rtype: string
        """
        authn_request = OneLogin_Saml2_Authn_Request(self.__settings, force_authn, is_passive, set_nameid_policy)
        self.__last_request = authn_request.get_xml()
        self.__last_request_id = authn_request.get_id()
        saml_request = authn_request.get_request()

        parameters = {'SAMLRequest': saml_request}
        if return_to is not None:
            parameters['RelayState'] = return_to
        else:
            parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self.__request_data)

        security = self.__settings.get_security_data()
        if security.get('authnRequestsSigned', False):
            parameters['SigAlg'] = security['signatureAlgorithm']
            parameters['Signature'] = self.build_request_signature(saml_request, parameters['RelayState'], security['signatureAlgorithm'])
        return self.redirect_to(self.get_sso_url(), parameters)

    def logout(self, return_to=None, name_id=None, session_index=None, nq=None, name_id_format=None):
        """
        Initiates the SLO process.

        :param return_to: Optional argument. The target URL the user should be redirected to after logout.
        :type return_to: string

        :param name_id: The NameID that will be set in the LogoutRequest.
        :type name_id: string

        :param session_index: SessionIndex that identifies the session of the user.
        :type session_index: string

        :param nq: IDP Name Qualifier
        :type: string

        :param name_id_format: The NameID Format that will be set in the LogoutRequest.
        :type: string

        :returns: Redirection url
        """
        slo_url = self.get_slo_url()
        if slo_url is None:
            raise OneLogin_Saml2_Error(
                'The IdP does not support Single Log Out',
                OneLogin_Saml2_Error.SAML_SINGLE_LOGOUT_NOT_SUPPORTED
            )

        if name_id is None and self.__nameid is not None:
            name_id = self.__nameid
        if name_id_format is None and self.__nameid_format is not None:
            name_id_format = self.__nameid_format

        logout_request = OneLogin_Saml2_Logout_Request(
            self.__settings,
            name_id=name_id,
            session_index=session_index,
            nq=nq,
            name_id_format=name_id_format
        )
        self.__last_request = logout_request.get_xml()
        self.__last_request_id = logout_request.id
        saml_request = logout_request.get_request()

        parameters = {'SAMLRequest': logout_request.get_request()}
        if return_to is not None:
            parameters['RelayState'] = return_to
        else:
            parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self.__request_data)

        security = self.__settings.get_security_data()
        if security.get('logoutRequestSigned', False):
            parameters['SigAlg'] = security['signatureAlgorithm']
            parameters['Signature'] = self.build_request_signature(saml_request, parameters['RelayState'], security['signatureAlgorithm'])
        return self.redirect_to(slo_url, parameters)

    def get_sso_url(self):
        """
        Gets the SSO URL.

        :returns: An URL, the SSO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.__settings.get_idp_data()
        return idp_data['singleSignOnService']['url']

    def get_slo_url(self):
        """
        Gets the SLO URL.

        :returns: An URL, the SLO endpoint of the IdP
        :rtype: string
        """
        url = None
        idp_data = self.__settings.get_idp_data()
        if 'singleLogoutService' in idp_data.keys() and 'url' in idp_data['singleLogoutService']:
            url = idp_data['singleLogoutService']['url']
        return url

    def build_request_signature(self, saml_request, relay_state, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature of the SAML Request.

        :param saml_request: The SAML Request
        :type saml_request: string

        :param relay_state: The target URL the user should be redirected to
        :type relay_state: string

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        return self.__build_signature(saml_request, relay_state, 'SAMLRequest', sign_algorithm)

    def build_response_signature(self, saml_response, relay_state, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature of the SAML Response.
        :param saml_request: The SAML Response
        :type saml_request: string

        :param relay_state: The target URL the user should be redirected to
        :type relay_state: string

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        return self.__build_signature(saml_response, relay_state, 'SAMLResponse', sign_algorithm)

    def __build_signature(self, saml_data, relay_state, saml_type, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature
        :param saml_data: The SAML Data
        :type saml_data: string

        :param relay_state: The target URL the user should be redirected to
        :type relay_state: string

        :param saml_type: The target URL the user should be redirected to
        :type saml_type: string  SAMLRequest | SAMLResponse

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        assert saml_type in ['SAMLRequest', 'SAMLResponse']

        # Load the key into the xmlsec context
        key = self.__settings.get_sp_key()

        if not key:
            raise OneLogin_Saml2_Error(
                "Trying to sign the %s but can't load the SP private key" % saml_type,
                OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
            )

        dsig_ctx = xmlsec.DSigCtx()
        dsig_ctx.signKey = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)

        msg = '%s=%s' % (saml_type, quote_plus(saml_data))
        if relay_state is not None:
            msg += '&RelayState=%s' % quote_plus(relay_state)
        msg += '&SigAlg=%s' % quote_plus(sign_algorithm)

        # Sign the metadata with our private key.
        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.TransformDsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.TransformRsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.TransformRsaSha256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.TransformRsaSha384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.TransformRsaSha512
        }
        sign_algorithm_transform = sign_algorithm_transform_map.get(sign_algorithm, xmlsec.TransformRsaSha1)

        signature = dsig_ctx.signBinary(str(msg), sign_algorithm_transform)
        return b64encode(signature)

    def get_last_response_xml(self, pretty_print_if_possible=False):
        """
        Retrieves the raw XML (decrypted) of the last SAML response,
        or the last Logout Response generated or processed

        :returns: SAML response XML
        :rtype: string|None
        """
        response = None
        if self.__last_response is not None:
            if isinstance(self.__last_response, basestring):
                response = self.__last_response
            else:
                response = tostring(self.__last_response, pretty_print=pretty_print_if_possible)
        return response

    def get_last_request_xml(self):
        """
        Retrieves the raw XML sent in the last SAML request

        :returns: SAML request XML
        :rtype: string|None
        """
        return self.__last_request or None
