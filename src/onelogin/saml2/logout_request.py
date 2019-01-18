# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Logout_Request class

Copyright (c) 2010-2018 OneLogin, Inc.
MIT License

Logout Request class of OneLogin's Python Toolkit.

"""
from __future__ import print_function

from zlib import decompress
from base64 import b64encode, b64decode
from lxml import etree
from defusedxml.lxml import fromstring
from xml.dom.minidom import Document

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError


class OneLogin_Saml2_Logout_Request(object):
    """

    This class handles a Logout Request.

    Builds a Logout Response object and validates it.

    """

    def __init__(self, settings, request=None, name_id=None, session_index=None, nq=None, name_id_format=None):
        """
        Constructs the Logout Request object.

        :param settings: Setting data
        :type request_data: OneLogin_Saml2_Settings

        :param request: Optional. A LogoutRequest to be loaded instead build one.
        :type request: string

        :param name_id: The NameID that will be set in the LogoutRequest.
        :type name_id: string

        :param session_index: SessionIndex that identifies the session of the user.
        :type session_index: string

        :param nq: IDP Name Qualifier
        :type: string

        :param name_id_format: The NameID Format that will be set in the LogoutRequest.
        :type: string
        """
        self.__settings = settings
        self.__error = None
        self.id = None

        if request is None:
            sp_data = self.__settings.get_sp_data()
            idp_data = self.__settings.get_idp_data()
            security = self.__settings.get_security_data()

            uid = OneLogin_Saml2_Utils.generate_unique_id()
            self.id = uid

            issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

            cert = None
            if 'nameIdEncrypted' in security and security['nameIdEncrypted']:
                exists_multix509enc = 'x509certMulti' in idp_data and \
                    'encryption' in idp_data['x509certMulti'] and \
                    idp_data['x509certMulti']['encryption']
                if exists_multix509enc:
                    cert = idp_data['x509certMulti']['encryption'][0]
                else:
                    cert = idp_data['x509cert']

            if name_id is not None:
                if not name_id_format and sp_data['NameIDFormat'] != OneLogin_Saml2_Constants.NAMEID_UNSPECIFIED:
                    name_id_format = sp_data['NameIDFormat']
            else:
                name_id_format = OneLogin_Saml2_Constants.NAMEID_ENTITY

            spNameQualifier = None
            if name_id_format == OneLogin_Saml2_Constants.NAMEID_ENTITY:
                name_id = idp_data['entityId']
                nq = None
            elif nq is not None:
                # We only gonna include SPNameQualifier if NameQualifier is provided
                spNameQualifier = sp_data['entityId']

            name_id_obj = OneLogin_Saml2_Utils.generate_name_id(
                name_id,
                spNameQualifier,
                name_id_format,
                cert,
                False,
                nq
            )

            if session_index:
                session_index_str = '<samlp:SessionIndex>%s</samlp:SessionIndex>' % session_index
            else:
                session_index_str = ''

            logout_request = """<samlp:LogoutRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="%(id)s"
        Version="2.0"
        IssueInstant="%(issue_instant)s"
        Destination="%(single_logout_url)s">
        <saml:Issuer>%(entity_id)s</saml:Issuer>
        %(name_id)s
        %(session_index)s
    </samlp:LogoutRequest>""" % \
                {
                    'id': uid,
                    'issue_instant': issue_instant,
                    'single_logout_url': idp_data['singleLogoutService']['url'],
                    'entity_id': sp_data['entityId'],
                    'name_id': name_id_obj,
                    'session_index': session_index_str,
                }
        else:
            decoded = b64decode(request)
            # We try to inflate
            try:
                inflated = decompress(decoded, -15)
                logout_request = inflated
            except Exception:
                logout_request = decoded
            self.id = self.get_id(logout_request)

        self.__logout_request = logout_request

    def get_request(self, deflate=True):
        """
        Returns the Logout Request deflated, base64encoded
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: Logout Request maybe deflated and base64 encoded
        :rtype: str object
        """
        if deflate:
            request = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__logout_request)
        else:
            request = b64encode(self.__logout_request)
        return request

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the request
        or that was received at the SP
        :return: XML request body
        :rtype: string
        """
        return self.__logout_request

    @staticmethod
    def get_id(request):
        """
        Returns the ID of the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: string ID
        :rtype: str object
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)
        return elem.get('ID', None)

    @staticmethod
    def get_nameid_data(request, key=None):
        """
        Gets the NameID Data of the the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
        :rtype: dict
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        name_id = None
        encrypted_entries = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:EncryptedID')

        if len(encrypted_entries) == 1:
            if key is None:
                raise OneLogin_Saml2_Error(
                    'Private Key is required in order to decrypt the NameID, check settings',
                    OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
                )

            encrypted_data_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:EncryptedID/xenc:EncryptedData')
            if len(encrypted_data_nodes) == 1:
                encrypted_data = encrypted_data_nodes[0]
                name_id = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        else:
            entries = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:NameID')
            if len(entries) == 1:
                name_id = entries[0]

        if name_id is None:
            raise OneLogin_Saml2_ValidationError(
                'NameID not found in the Logout Request',
                OneLogin_Saml2_ValidationError.NO_NAMEID
            )

        name_id_data = {
            'Value': OneLogin_Saml2_Utils.element_text(name_id)
        }
        for attr in ['Format', 'SPNameQualifier', 'NameQualifier']:
            if attr in name_id.attrib.keys():
                name_id_data[attr] = name_id.attrib[attr]

        return name_id_data

    @staticmethod
    def get_nameid(request, key=None):
        """
        Gets the NameID of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Value
        :rtype: string
        """
        name_id = OneLogin_Saml2_Logout_Request.get_nameid_data(request, key)
        return name_id['Value']

    @staticmethod
    def get_nameid_format(request, key=None):
        """
        Gets the NameID Format of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Value
        :rtype: string
        """
        name_id_format = None
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(request, key)
        if name_id_data and 'Format' in name_id_data.keys():
            name_id_format = name_id_data['Format']
        return name_id_format

    @staticmethod
    def get_issuer(request):
        """
        Gets the Issuer of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: The Issuer
        :rtype: string
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        issuer = None
        issuer_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:Issuer')
        if len(issuer_nodes) == 1:
            issuer = OneLogin_Saml2_Utils.element_text(issuer_nodes[0])
        return issuer

    @staticmethod
    def get_session_indexes(request):
        """
        Gets the SessionIndexes from the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: The SessionIndex value
        :rtype: list
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        session_indexes = []
        session_index_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/samlp:SessionIndex')
        for session_index_node in session_index_nodes:
            session_indexes.append(OneLogin_Saml2_Utils.element_text(session_index_node))
        return session_indexes

    def is_valid(self, request_data, raise_exceptions=False):
        """
        Checks if the Logout Request received is valid
        :param request_data: Request Data
        :type request_data: dict
        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        :return: If the Logout Request is or not valid
        :rtype: boolean
        """
        self.__error = None
        lowercase_urlencoding = False
        try:
            dom = fromstring(self.__logout_request)

            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']

            if 'get_data' in request_data.keys():
                get_data = request_data['get_data']
            else:
                get_data = {}

            if 'lowercase_urlencoding' in request_data.keys():
                lowercase_urlencoding = request_data['lowercase_urlencoding']

            if self.__settings.is_strict():
                res = OneLogin_Saml2_Utils.validate_xml(dom, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if not isinstance(res, Document):
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd',
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                security = self.__settings.get_security_data()

                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check NotOnOrAfter
                if dom.get('NotOnOrAfter', None):
                    na = OneLogin_Saml2_Utils.parse_SAML_to_time(dom.get('NotOnOrAfter'))
                    if na <= OneLogin_Saml2_Utils.now():
                        raise OneLogin_Saml2_ValidationError(
                            'Could not validate timestamp: expired. Check system clock.',
                            OneLogin_Saml2_ValidationError.RESPONSE_EXPIRED
                        )

                # Check destination
                if dom.get('Destination', None):
                    destination = dom.get('Destination')
                    if destination != '':
                        if current_url not in destination:
                            raise Exception(
                                'The LogoutRequest was received at '
                                '%(currentURL)s instead of %(destination)s' %
                                {
                                    'currentURL': current_url,
                                    'destination': destination,
                                },
                                OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                            )

                # Check issuer
                issuer = OneLogin_Saml2_Logout_Request.get_issuer(dom)
                if issuer is not None and issuer != idp_entity_id:
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid issuer in the Logout Request (expected %(idpEntityId)s, got %(issuer)s)' %
                        {
                            'idpEntityId': idp_entity_id,
                            'issuer': issuer
                        },
                        OneLogin_Saml2_ValidationError.WRONG_ISSUER
                    )

                if security['wantMessagesSigned']:
                    if 'Signature' not in get_data:
                        raise OneLogin_Saml2_ValidationError(
                            'The Message of the Logout Request is not signed and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                        )

            if 'Signature' in get_data:
                if 'SigAlg' not in get_data:
                    sign_alg = OneLogin_Saml2_Constants.RSA_SHA1
                else:
                    sign_alg = get_data['SigAlg']

                signed_query = 'SAMLRequest=%s' % OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'SAMLRequest', lowercase_urlencoding=lowercase_urlencoding)
                if 'RelayState' in get_data:
                    signed_query = '%s&RelayState=%s' % (signed_query, OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'RelayState', lowercase_urlencoding=lowercase_urlencoding))
                signed_query = '%s&SigAlg=%s' % (signed_query, OneLogin_Saml2_Utils.get_encoded_parameter(get_data, 'SigAlg', OneLogin_Saml2_Constants.RSA_SHA1, lowercase_urlencoding=lowercase_urlencoding))

                exists_x509cert = 'x509cert' in idp_data and idp_data['x509cert']
                exists_multix509sign = 'x509certMulti' in idp_data and \
                    'signing' in idp_data['x509certMulti'] and \
                    idp_data['x509certMulti']['signing']

                if not (exists_x509cert or exists_multix509sign):
                    raise OneLogin_Saml2_Error(
                        'In order to validate the sign on the Logout Request, the x509cert of the IdP is required',
                        OneLogin_Saml2_Error.CERT_NOT_FOUND
                    )
                if exists_multix509sign:
                    for cert in idp_data['x509certMulti']['signing']:
                        if OneLogin_Saml2_Utils.validate_binary_sign(signed_query, b64decode(get_data['Signature']), cert, sign_alg):
                            return True
                    raise OneLogin_Saml2_ValidationError(
                        'Signature validation failed. Logout Request rejected',
                        OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                    )
                else:
                    cert = idp_data['x509cert']

                    if not OneLogin_Saml2_Utils.validate_binary_sign(signed_query, b64decode(get_data['Signature']), cert, sign_alg):
                        raise OneLogin_Saml2_ValidationError(
                            'Signature validation failed. Logout Request rejected',
                            OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                        )
            return True
        except Exception as err:
            # pylint: disable=R0801sign_alg
            self.__error = err.__str__()
            debug = self.__settings.is_debug_active()
            if debug:
                print(err.__str__())
            if raise_exceptions:
                raise err
            return False

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error
