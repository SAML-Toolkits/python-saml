# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Logout_Response class

Copyright (c) 2010-2018 OneLogin, Inc.
MIT License

Logout Response class of OneLogin's Python Toolkit.

"""
from __future__ import print_function

from base64 import b64encode, b64decode
from defusedxml.lxml import fromstring

from xml.dom.minidom import Document
from defusedxml.minidom import parseString

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError


class OneLogin_Saml2_Logout_Response(object):
    """

    This class  handles a Logout Response. It Builds or parses a Logout Response object
    and validates it.

    """

    def __init__(self, settings, response=None):
        """
        Constructs a Logout Response object (Initialize params from settings
        and if provided load the Logout Response.

        Arguments are:
            * (OneLogin_Saml2_Settings)   settings. Setting data
            * (string)                    response. An UUEncoded SAML Logout
                                                    response from the IdP.
        """
        self.__settings = settings
        self.__error = None
        self.id = None

        if response is not None:
            self.__logout_response = OneLogin_Saml2_Utils.decode_base64_and_inflate(response)
            self.document = parseString(self.__logout_response)
            self.id = self.document.documentElement.getAttribute('ID')

    def get_issuer(self):
        """
        Gets the Issuer of the Logout Response Message
        :return: The Issuer
        :rtype: string
        """
        issuer = None
        issuer_nodes = self.__query('/samlp:LogoutResponse/saml:Issuer')
        if len(issuer_nodes) == 1:
            issuer = OneLogin_Saml2_Utils.element_text(issuer_nodes[0])
        return issuer

    def get_status(self):
        """
        Gets the Status
        :return: The Status
        :rtype: string
        """
        entries = self.__query('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode')
        if len(entries) == 0:
            return None
        status = entries[0].attrib['Value']
        return status

    def is_valid(self, request_data, request_id=None, raise_exceptions=False):
        """
        Determines if the SAML LogoutResponse is valid
        :param request_id: The ID of the LogoutRequest sent by this SP to the IdP
        :type request_id: string
        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        :return: Returns if the SAML LogoutResponse is or not valid
        :rtype: boolean
        """
        self.__error = None
        lowercase_urlencoding = False
        try:
            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']
            get_data = request_data['get_data']

            if 'lowercase_urlencoding' in request_data.keys():
                lowercase_urlencoding = request_data['lowercase_urlencoding']

            if self.__settings.is_strict():
                res = OneLogin_Saml2_Utils.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if not isinstance(res, Document):
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd',
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                security = self.__settings.get_security_data()

                # Check if the InResponseTo of the Logout Response matches the ID of the Logout Request (requestId) if provided
                if request_id is not None and self.document.documentElement.hasAttribute('InResponseTo'):
                    in_response_to = self.document.documentElement.getAttribute('InResponseTo')
                    if request_id != in_response_to:
                        raise OneLogin_Saml2_ValidationError(
                            'The InResponseTo of the Logout Response: %s, does not match the ID of the Logout request sent by the SP: %s' % (in_response_to, request_id),
                            OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
                        )

                # Check issuer
                issuer = self.get_issuer()
                if issuer is not None and issuer != idp_entity_id:
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid issuer in the Logout Response (expected %(idpEntityId)s, got %(issuer)s)' %
                        {
                            'idpEntityId': idp_entity_id,
                            'issuer': issuer
                        },
                        OneLogin_Saml2_ValidationError.WRONG_ISSUER
                    )

                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check destination
                if self.document.documentElement.hasAttribute('Destination'):
                    destination = self.document.documentElement.getAttribute('Destination')
                    if destination != '':
                        if current_url not in destination:
                            raise OneLogin_Saml2_ValidationError(
                                'The LogoutResponse was received at %s instead of %s' % (current_url, destination),
                                OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                            )

                if security['wantMessagesSigned']:
                    if 'Signature' not in get_data:
                        raise OneLogin_Saml2_ValidationError(
                            'The Message of the Logout Response is not signed and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                        )

            if 'Signature' in get_data:
                if 'SigAlg' not in get_data:
                    sign_alg = OneLogin_Saml2_Constants.RSA_SHA1
                else:
                    sign_alg = get_data['SigAlg']

                signed_query = 'SAMLResponse=%s' % OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'SAMLResponse', lowercase_urlencoding=lowercase_urlencoding)
                if 'RelayState' in get_data:
                    signed_query = '%s&RelayState=%s' % (signed_query, OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'RelayState', lowercase_urlencoding=lowercase_urlencoding))
                signed_query = '%s&SigAlg=%s' % (signed_query, OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'SigAlg', OneLogin_Saml2_Constants.RSA_SHA1, lowercase_urlencoding=lowercase_urlencoding))

                exists_x509cert = 'x509cert' in idp_data and idp_data['x509cert']
                exists_multix509sign = 'x509certMulti' in idp_data and \
                    'signing' in idp_data['x509certMulti'] and \
                    idp_data['x509certMulti']['signing']

                if not (exists_x509cert or exists_multix509sign):
                    raise OneLogin_Saml2_Error(
                        'In order to validate the sign on the Logout Response, the x509cert of the IdP is required',
                        OneLogin_Saml2_Error.CERT_NOT_FOUND
                    )
                if exists_multix509sign:
                    for cert in idp_data['x509certMulti']['signing']:
                        if OneLogin_Saml2_Utils.validate_binary_sign(signed_query, b64decode(get_data['Signature']), cert, sign_alg):
                            return True
                    raise OneLogin_Saml2_ValidationError(
                        'Signature validation failed. Logout Response rejected',
                        OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                    )
                else:
                    cert = idp_data['x509cert']

                    if not OneLogin_Saml2_Utils.validate_binary_sign(signed_query, b64decode(get_data['Signature']), cert, sign_alg):
                        raise OneLogin_Saml2_ValidationError(
                            'Signature validation failed. Logout Response rejected',
                            OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                        )

            return True
        # pylint: disable=R0801
        except Exception as err:
            self.__error = err.__str__()
            debug = self.__settings.is_debug_active()
            if debug:
                print(err.__str__())
            if raise_exceptions:
                raise err
            return False

    def __query(self, query):
        """
        Extracts a node from the DOMDocument (Logout Response Menssage)
        :param query: Xpath Expresion
        :type query: string
        :return: The queried node
        :rtype: DOMNodeList
        """
        # Switch to lxml for querying
        xml = self.document.toxml()
        return OneLogin_Saml2_Utils.query(fromstring(xml), query)

    def build(self, in_response_to):
        """
        Creates a Logout Response object.
        :param in_response_to: InResponseTo value for the Logout Response.
        :type in_response_to: string
        """
        sp_data = self.__settings.get_sp_data()
        idp_data = self.__settings.get_idp_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        logout_response = """<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="%(id)s"
                      Version="2.0"
                      IssueInstant="%(issue_instant)s"
                      Destination="%(destination)s"
                      InResponseTo="%(in_response_to)s"
>
    <saml:Issuer>%(entity_id)s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
</samlp:LogoutResponse>""" % \
            {
                'id': uid,
                'issue_instant': issue_instant,
                'destination': idp_data['singleLogoutService']['url'],
                'in_response_to': in_response_to,
                'entity_id': sp_data['entityId'],
            }

        self.__logout_response = logout_response

    def get_response(self, deflate=True):
        """
        Returns the Logout Response defated, base64encoded
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: Logout Response maybe deflated and base64 encoded
        :rtype: string
        """
        if deflate:
            response = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__logout_response)
        else:
            response = b64encode(self.__logout_response)
        return response

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the response
        or that was received at the SP
        :return: XML response body
        :rtype: string
        """
        return self.__logout_response

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error
