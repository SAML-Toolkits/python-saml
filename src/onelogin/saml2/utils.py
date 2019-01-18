# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Utils class

Copyright (c) 2010-2018 OneLogin, Inc.
MIT License

Auxiliary class of OneLogin's Python Toolkit.

"""
from __future__ import print_function

import base64
from copy import deepcopy
from datetime import datetime
import calendar
from hashlib import sha1, sha256, sha384, sha512
from isodate import parse_duration as duration_parser
from lxml import etree
from defusedxml.lxml import tostring, fromstring
from os.path import basename, dirname, join
import re
from sys import stderr
from tempfile import NamedTemporaryFile
from textwrap import wrap
from urllib import quote_plus
from uuid import uuid4
from xml.dom.minidom import Document, Element
from defusedxml.minidom import parseString
from functools import wraps

import zlib

import dm.xmlsec.binding as xmlsec
from dm.xmlsec.binding.tmpl import EncData, Signature

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError


if not globals().get('xmlsec_setup', False):
    xmlsec.initialize()
    globals()['xmlsec_setup'] = True


def return_false_on_exception(func):
    """
    Decorator. When applied to a function, it will, by default, suppress any exceptions
    raised by that function and return False. It may be overridden by passing a
    "raise_exceptions" keyword argument when calling the wrapped function.
    """
    @wraps(func)
    def exceptfalse(*args, **kwargs):
        if not kwargs.pop('raise_exceptions', False):
            try:
                return func(*args, **kwargs)
            except Exception:
                return False
        else:
            return func(*args, **kwargs)
    return exceptfalse


def print_xmlsec_errors(filename, line, func, error_object, error_subject, reason, msg):
    """
    Auxiliary method. It overrides the default xmlsec debug message.
    """

    info = []
    if error_object != "unknown":
        info.append("obj=" + error_object)
    if error_subject != "unknown":
        info.append("subject=" + error_subject)
    if msg.strip():
        info.append("msg=" + msg)
    if reason != 1:
        info.append("errno=%d" % reason)
    if info:
        print("%s:%d(%s)" % (filename, line, func), " ".join(info))


class OneLogin_Saml2_Utils(object):
    """

    Auxiliary class that contains several utility methods to parse time,
    urls, add sign, encrypt, decrypt, sign validation, handle xml ...

    """

    RESPONSE_SIGNATURE_XPATH = '/samlp:Response/ds:Signature'
    ASSERTION_SIGNATURE_XPATH = '/samlp:Response/saml:Assertion/ds:Signature'

    @staticmethod
    def decode_base64_and_inflate(value):
        """
        base64 decodes and then inflates according to RFC1951
        :param value: a deflated and encoded string
        :type value: string
        :returns: the string after decoding and inflating
        :rtype: string
        """
        decoded = base64.b64decode(value)
        # We try to inflate
        try:
            result = zlib.decompress(decoded, -15)
        except Exception:
            result = decoded

        return result.decode('utf-8')

    @staticmethod
    def deflate_and_base64_encode(value):
        """
        Deflates and then base64 encodes a string
        :param value: The string to deflate and encode
        :type value: string
        :returns: The deflated and encoded string
        :rtype: string
        """
        return base64.b64encode(zlib.compress(value.encode('utf-8'))[2:-4])

    @staticmethod
    def validate_xml(xml, schema, debug=False):
        """
        Validates a xml against a schema
        :param xml: The xml that will be validated
        :type: string|DomDocument
        :param schema: The schema
        :type: string
        :param debug: If debug is active, the parse-errors will be showed
        :type: bool
        :returns: Error code or the DomDocument of the xml
        :rtype: string
        """
        assert isinstance(xml, basestring) or isinstance(xml, Document) or isinstance(xml, etree._Element)
        assert isinstance(schema, basestring)

        if isinstance(xml, Document):
            xml = xml.toxml()
        elif isinstance(xml, etree._Element):
            xml = tostring(xml, encoding='unicode')

        # Switch to lxml for schema validation
        try:
            dom = fromstring(xml.encode('utf-8'))
        except Exception:
            return 'unloaded_xml'

        schema_file = join(dirname(__file__), 'schemas', schema)
        f_schema = open(schema_file, 'r')
        schema_doc = etree.parse(f_schema)
        f_schema.close()
        xmlschema = etree.XMLSchema(schema_doc)

        if not xmlschema.validate(dom):
            if debug:
                stderr.write('Errors validating the metadata')
                stderr.write(':\n\n')
                for error in xmlschema.error_log:
                    stderr.write('%s\n' % error.message)

            return 'invalid_xml'

        return parseString(tostring(dom, encoding='unicode').encode('utf-8'))

    @staticmethod
    def element_text(node):
        etree.strip_tags(node, etree.Comment)
        return node.text

    @staticmethod
    def format_cert(cert, heads=True):
        """
        Returns a x509 cert (adding header & footer if required).

        :param cert: A x509 unformatted cert
        :type: string

        :param heads: True if we want to include head and footer
        :type: boolean

        :returns: Formatted cert
        :rtype: string
        """
        x509_cert = cert.replace('\x0D', '')
        x509_cert = x509_cert.replace('\r', '')
        x509_cert = x509_cert.replace('\n', '')
        if len(x509_cert) > 0:
            x509_cert = x509_cert.replace('-----BEGIN CERTIFICATE-----', '')
            x509_cert = x509_cert.replace('-----END CERTIFICATE-----', '')
            x509_cert = x509_cert.replace(' ', '')

            if heads:
                x509_cert = "-----BEGIN CERTIFICATE-----\n" + "\n".join(wrap(x509_cert, 64)) + "\n-----END CERTIFICATE-----\n"

        return x509_cert

    @staticmethod
    def format_private_key(key, heads=True):
        """
        Returns a private key (adding header & footer if required).

        :param key A private key
        :type: string

        :param heads: True if we want to include head and footer
        :type: boolean

        :returns: Formatted private key
        :rtype: string
        """
        private_key = key.replace('\x0D', '')
        private_key = private_key.replace('\r', '')
        private_key = private_key.replace('\n', '')
        if len(private_key) > 0:
            if private_key.find('-----BEGIN PRIVATE KEY-----') != -1:
                private_key = private_key.replace('-----BEGIN PRIVATE KEY-----', '')
                private_key = private_key.replace('-----END PRIVATE KEY-----', '')
                private_key = private_key.replace(' ', '')
                if heads:
                    private_key = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(wrap(private_key, 64)) + "\n-----END PRIVATE KEY-----\n"
            else:
                private_key = private_key.replace('-----BEGIN RSA PRIVATE KEY-----', '')
                private_key = private_key.replace('-----END RSA PRIVATE KEY-----', '')
                private_key = private_key.replace(' ', '')
                if heads:
                    private_key = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(wrap(private_key, 64)) + "\n-----END RSA PRIVATE KEY-----\n"
        return private_key

    @staticmethod
    def redirect(url, parameters={}, request_data={}):
        """
        Executes a redirection to the provided url (or return the target url).

        :param url: The target url
        :type: string

        :param parameters: Extra parameters to be passed as part of the url
        :type: dict

        :param request_data: The request as a dict
        :type: dict

        :returns: Url
        :rtype: string
        """
        assert isinstance(url, basestring)
        assert isinstance(parameters, dict)

        if url.startswith('/'):
            url = '%s%s' % (OneLogin_Saml2_Utils.get_self_url_host(request_data), url)

        # Verify that the URL is to a http or https site.
        if re.search('^https?://', url) is None:
            raise OneLogin_Saml2_Error(
                'Redirect to invalid URL: ' + url,
                OneLogin_Saml2_Error.REDIRECT_INVALID_URL
            )

        # Add encoded parameters
        if url.find('?') < 0:
            param_prefix = '?'
        else:
            param_prefix = '&'

        for name, value in parameters.items():

            if value is None:
                param = quote_plus(name)
            elif isinstance(value, list):
                param = ''
                for val in value:
                    param += quote_plus(name) + '[]=' + quote_plus(val) + '&'
                if len(param) > 0:
                    param = param[0:-1]
            else:
                param = quote_plus(name) + '=' + quote_plus(value)

            if param:
                url += param_prefix + param
                param_prefix = '&'

        return url

    @staticmethod
    def get_self_url_host(request_data):
        """
        Returns the protocol + the current host + the port (if different than
        common ports).

        :param request_data: The request as a dict
        :type: dict

        :return: Url
        :rtype: string
        """
        current_host = OneLogin_Saml2_Utils.get_self_host(request_data)
        port = ''
        if OneLogin_Saml2_Utils.is_https(request_data):
            protocol = 'https'
        else:
            protocol = 'http'

        if 'server_port' in request_data and request_data['server_port'] is not None:
            port_number = str(request_data['server_port'])
            port = ':' + port_number

            if protocol == 'http' and port_number == '80':
                port = ''
            elif protocol == 'https' and port_number == '443':
                port = ''

        return '%s://%s%s' % (protocol, current_host, port)

    @staticmethod
    def get_self_host(request_data):
        """
        Returns the current host.

        :param request_data: The request as a dict
        :type: dict

        :return: The current host
        :rtype: string
        """
        if 'http_host' in request_data:
            current_host = request_data['http_host']
        elif 'server_name' in request_data:
            current_host = request_data['server_name']
        else:
            raise Exception('No hostname defined')

        if ':' in current_host:
            current_host_data = current_host.split(':')
            possible_port = current_host_data[-1]
            try:
                possible_port = float(possible_port)
                current_host = current_host_data[0]
            except ValueError:
                current_host = ':'.join(current_host_data)

        return current_host

    @staticmethod
    def is_https(request_data):
        """
        Checks if https or http.

        :param request_data: The request as a dict
        :type: dict

        :return: False if https is not active
        :rtype: boolean
        """
        is_https = 'https' in request_data and request_data['https'] != 'off'
        is_https = is_https or ('server_port' in request_data and str(request_data['server_port']) == '443')
        return is_https

    @staticmethod
    def get_self_url_no_query(request_data):
        """
        Returns the URL of the current host + current view.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)
        script_name = request_data['script_name']
        if script_name:
            if script_name[0] != '/':
                script_name = '/' + script_name
        else:
            script_name = ''
        self_url_no_query = self_url_host + script_name
        if 'path_info' in request_data:
            self_url_no_query += request_data['path_info']

        return self_url_no_query

    @staticmethod
    def get_self_routed_url_no_query(request_data):
        """
        Returns the routed URL of the current host + current view.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)
        route = ''
        if 'request_uri' in request_data.keys() and request_data['request_uri']:
            route = request_data['request_uri']
            if 'query_string' in request_data.keys() and request_data['query_string']:
                route = route.replace(request_data['query_string'], '')

        return self_url_host + route

    @staticmethod
    def get_self_url(request_data):
        """
        Returns the URL of the current host + current view + query.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view + query
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)

        request_uri = ''
        if 'request_uri' in request_data:
            request_uri = request_data['request_uri']
            if not request_uri.startswith('/'):
                match = re.search('^https?://[^/]*(/.*)', request_uri)
                if match is not None:
                    request_uri = match.groups()[0]

        return self_url_host + request_uri

    @staticmethod
    def generate_unique_id():
        """
        Generates an unique string (used for example as ID for assertions).

        :return: A unique string
        :rtype: string
        """
        return 'ONELOGIN_%s' % sha1(uuid4().hex).hexdigest()

    @staticmethod
    def parse_time_to_SAML(time):
        """
        Converts a UNIX timestamp to SAML2 timestamp on the form
        yyyy-mm-ddThh:mm:ss(\.s+)?Z.

        :param time: The time we should convert (DateTime).
        :type: string

        :return: SAML2 timestamp.
        :rtype: string
        """
        data = datetime.utcfromtimestamp(float(time))
        return data.strftime('%Y-%m-%dT%H:%M:%SZ')

    @staticmethod
    def parse_SAML_to_time(timestr):
        """
        Converts a SAML2 timestamp on the form yyyy-mm-ddThh:mm:ss(\.s+)?Z
        to a UNIX timestamp. The sub-second part is ignored.

        :param time: The time we should convert (SAML Timestamp).
        :type: string

        :return: Converted to a unix timestamp.
        :rtype: int
        """
        try:
            data = datetime.strptime(timestr, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            data = datetime.strptime(timestr, '%Y-%m-%dT%H:%M:%S.%fZ')
        return calendar.timegm(data.utctimetuple())

    @staticmethod
    def now():
        """
        :return: unix timestamp of actual time.
        :rtype: int
        """
        return calendar.timegm(datetime.utcnow().utctimetuple())

    @staticmethod
    def parse_duration(duration, timestamp=None):
        """
        Interprets a ISO8601 duration value relative to a given timestamp.

        :param duration: The duration, as a string.
        :type: string

        :param timestamp: The unix timestamp we should apply the duration to.
                          Optional, default to the current time.
        :type: string

        :return: The new timestamp, after the duration is applied.
        :rtype: int
        """
        assert isinstance(duration, basestring)
        assert timestamp is None or isinstance(timestamp, int)

        timedelta = duration_parser(duration)
        if timestamp is None:
            data = datetime.utcnow() + timedelta
        else:
            data = datetime.utcfromtimestamp(timestamp) + timedelta
        return calendar.timegm(data.utctimetuple())

    @staticmethod
    def get_expire_time(cache_duration=None, valid_until=None):
        """
        Compares 2 dates and returns the earliest.

        :param cache_duration: The duration, as a string.
        :type: string

        :param valid_until: The valid until date, as a string or as a timestamp
        :type: string

        :return: The expiration time.
        :rtype: int
        """
        expire_time = None

        if cache_duration is not None:
            expire_time = OneLogin_Saml2_Utils.parse_duration(cache_duration)

        if valid_until is not None:
            if isinstance(valid_until, int):
                valid_until_time = valid_until
            else:
                valid_until_time = OneLogin_Saml2_Utils.parse_SAML_to_time(valid_until)
            if expire_time is None or expire_time > valid_until_time:
                expire_time = valid_until_time

        if expire_time is not None:
            return '%d' % expire_time
        return None

    @staticmethod
    def query(dom, query, context=None):
        """
        Extracts nodes that match the query from the Element

        :param dom: The root of the lxml objet
        :type: Element

        :param query: Xpath Expresion
        :type: string

        :param context: Context Node
        :type: DOMElement

        :returns: The queried nodes
        :rtype: list
        """
        if context is None:
            return dom.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)
        else:
            return context.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)

    @staticmethod
    def delete_local_session(callback=None):
        """
        Deletes the local session.
        """

        if callback is not None:
            callback()

    @staticmethod
    def calculate_x509_fingerprint(x509_cert, alg='sha1'):
        """
        Calculates the fingerprint of a formatted x509cert.

        :param x509_cert: x509 cert formatted
        :type: string

        :param alg: The algorithm to build the fingerprint
        :type: string

        :returns: fingerprint
        :rtype: string
        """
        assert isinstance(x509_cert, basestring)

        lines = x509_cert.split('\n')
        data = ''
        inData = False

        for line in lines:
            # Remove '\r' from end of line if present.
            line = line.rstrip()
            if not inData:
                if line == '-----BEGIN CERTIFICATE-----':
                    inData = True
                elif line == '-----BEGIN PUBLIC KEY-----' or line == '-----BEGIN RSA PRIVATE KEY-----':
                    # This isn't an X509 certificate.
                    return None
            else:
                if line == '-----END CERTIFICATE-----':
                    break

                # Append the current line to the certificate data.
                data += line

        if not data:
            return None

        decoded_data = base64.b64decode(data)

        if alg == 'sha512':
            fingerprint = sha512(decoded_data)
        elif alg == 'sha384':
            fingerprint = sha384(decoded_data)
        elif alg == 'sha256':
            fingerprint = sha256(decoded_data)
        else:
            fingerprint = sha1(decoded_data)

        return fingerprint.hexdigest().lower()

    @staticmethod
    def format_finger_print(fingerprint):
        """
        Formats a fingerprint.

        :param fingerprint: fingerprint
        :type: string

        :returns: Formatted fingerprint
        :rtype: string
        """
        formated_fingerprint = fingerprint.replace(':', '')
        return formated_fingerprint.lower()

    @staticmethod
    def generate_name_id(value, sp_nq, sp_format=None, cert=None, debug=False, nq=None):
        """
        Generates a nameID.

        :param value: fingerprint
        :type: string

        :param sp_nq: SP Name Qualifier
        :type: string

        :param sp_format: SP Format
        :type: string

        :param cert: IdP Public Cert to encrypt the nameID
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param nq: IDP Name Qualifier
        :type: string

        :returns: DOMElement | XMLSec nameID
        :rtype: string
        """
        doc = Document()
        name_id_container = doc.createElementNS(OneLogin_Saml2_Constants.NS_SAML, 'container')
        name_id_container.setAttribute("xmlns:saml", OneLogin_Saml2_Constants.NS_SAML)

        name_id = doc.createElement('saml:NameID')
        if sp_nq is not None:
            name_id.setAttribute('SPNameQualifier', sp_nq)
        if nq is not None:
            name_id.setAttribute('NameQualifier', nq)
        if sp_format is not None:
            name_id.setAttribute('Format', sp_format)
        name_id.appendChild(doc.createTextNode(value))
        name_id_container.appendChild(name_id)

        if cert is not None:
            xml = name_id_container.toxml()
            elem = fromstring(xml)

            error_callback_method = None
            if debug:
                error_callback_method = print_xmlsec_errors
            xmlsec.set_error_callback(error_callback_method)

            # Load the public cert
            mngr = xmlsec.KeysMngr()
            file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
            key_data = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)
            key_data.name = basename(file_cert.name)
            mngr.addKey(key_data)
            file_cert.close()

            # Prepare for encryption
            enc_data = EncData(xmlsec.TransformAes128Cbc, type=xmlsec.TypeEncElement)
            enc_data.ensureCipherValue()
            key_info = enc_data.ensureKeyInfo()
            # enc_key = key_info.addEncryptedKey(xmlsec.TransformRsaPkcs1)
            enc_key = key_info.addEncryptedKey(xmlsec.TransformRsaOaep)
            enc_key.ensureCipherValue()

            # Encrypt!
            enc_ctx = xmlsec.EncCtx(mngr)
            enc_ctx.encKey = xmlsec.Key.generate(xmlsec.KeyDataAes, 128, xmlsec.KeyDataTypeSession)

            edata = enc_ctx.encryptXml(enc_data, elem[0])

            newdoc = parseString(tostring(edata, encoding='unicode').encode('utf-8'))

            if newdoc.hasChildNodes():
                child = newdoc.firstChild
                child.removeAttribute('xmlns')
                child.removeAttribute('xmlns:saml')
                child.setAttribute('xmlns:xenc', OneLogin_Saml2_Constants.NS_XENC)
                child.setAttribute('xmlns:dsig', OneLogin_Saml2_Constants.NS_DS)

            nodes = newdoc.getElementsByTagName("*")
            for node in nodes:
                if node.tagName == 'ns0:KeyInfo':
                    node.tagName = 'dsig:KeyInfo'
                    node.removeAttribute('xmlns:ns0')
                    node.setAttribute('xmlns:dsig', OneLogin_Saml2_Constants.NS_DS)
                else:
                    node.tagName = 'xenc:' + node.tagName

            encrypted_id = newdoc.createElement('saml:EncryptedID')
            encrypted_data = newdoc.replaceChild(encrypted_id, newdoc.firstChild)
            encrypted_id.appendChild(encrypted_data)
            return newdoc.saveXML(encrypted_id)
        else:
            return doc.saveXML(name_id)

    @staticmethod
    def get_status(dom):
        """
        Gets Status from a Response.

        :param dom: The Response as XML
        :type: Document

        :returns: The Status, an array with the code and a message.
        :rtype: dict
        """
        status = {}

        status_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status')
        if len(status_entry) != 1:
            raise OneLogin_Saml2_ValidationError(
                'Missing Status on response',
                OneLogin_Saml2_ValidationError.MISSING_STATUS
            )

        code_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode', status_entry[0])
        if len(code_entry) != 1:
            raise OneLogin_Saml2_ValidationError(
                'Missing Status Code on response',
                OneLogin_Saml2_ValidationError.MISSING_STATUS_CODE
            )
        code = code_entry[0].values()[0]
        status['code'] = code

        status['msg'] = ''
        message_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', status_entry[0])
        if len(message_entry) == 0:
            subcode_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', status_entry[0])
            if len(subcode_entry) == 1:
                status['msg'] = subcode_entry[0].values()[0]
        elif len(message_entry) == 1:
            status['msg'] = OneLogin_Saml2_Utils.element_text(message_entry[0])

        return status

    @staticmethod
    def decrypt_element(encrypted_data, key, debug=False, inplace=False):
        """
        Decrypts an encrypted element.

        :param encrypted_data: The encrypted data.
        :type: lxml.etree.Element | DOMElement | basestring

        :param key: The key.
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param inplace: update passed data with decrypted result
        :type: bool

        :returns: The decrypted element.
        :rtype: lxml.etree.Element
        """
        if isinstance(encrypted_data, Element):
            encrypted_data = fromstring(str(encrypted_data.toxml()))
        elif isinstance(encrypted_data, basestring):
            encrypted_data = fromstring(str(encrypted_data))
        elif not inplace and isinstance(encrypted_data, etree._Element):
            encrypted_data = deepcopy(encrypted_data)

        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        mngr = xmlsec.KeysMngr()

        key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)
        mngr.addKey(key)
        enc_ctx = xmlsec.EncCtx(mngr)

        return enc_ctx.decrypt(encrypted_data)

    @staticmethod
    def write_temp_file(content):
        """
        Writes some content into a temporary file and returns it.

        :param content: The file content
        :type: string

        :returns: The temporary file
        :rtype: file-like object
        """
        f_temp = NamedTemporaryFile(delete=True)
        f_temp.file.write(content)
        f_temp.file.flush()
        return f_temp

    @staticmethod
    def add_sign(xml, key, cert, debug=False, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1, digest_algorithm=OneLogin_Saml2_Constants.SHA1):
        """
        Adds signature key and senders certificate to an element (Message or
        Assertion).

        :param xml: The element we should sign
        :type: string | Document

        :param key: The private key
        :type: string

        :param cert: The public
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string

        :param digest_algorithm: Digest algorithm method
        :type digest_algorithm: string

        :returns: Signed XML
        :rtype: string
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')
        elif isinstance(xml, etree._Element):
            elem = xml
        elif isinstance(xml, Document):
            xml = xml.toxml()
            elem = fromstring(xml.encode('utf-8'))
        elif isinstance(xml, Element):
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAMLP),
                'xmlns:samlp',
                unicode(OneLogin_Saml2_Constants.NS_SAMLP)
            )
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAML),
                'xmlns:saml',
                unicode(OneLogin_Saml2_Constants.NS_SAML)
            )
            xml = xml.toxml()
            elem = fromstring(xml.encode('utf-8'))
        elif isinstance(xml, basestring):
            elem = fromstring(xml.encode('utf-8'))
        else:
            raise Exception('Error parsing xml string')

        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.TransformDsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.TransformRsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.TransformRsaSha256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.TransformRsaSha384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.TransformRsaSha512
        }
        sign_algorithm_transform = sign_algorithm_transform_map.get(sign_algorithm, xmlsec.TransformRsaSha1)

        signature = Signature(xmlsec.TransformExclC14N, sign_algorithm_transform, nsPrefix='ds')

        issuer = OneLogin_Saml2_Utils.query(elem, '//saml:Issuer')
        if len(issuer) > 0:
            issuer = issuer[0]
            issuer.addnext(signature)
            elem_to_sign = issuer.getparent()
        else:
            entity_descriptor = OneLogin_Saml2_Utils.query(elem, '//md:EntityDescriptor')
            if len(entity_descriptor) > 0:
                elem.insert(0, signature)
            else:
                elem[0].insert(0, signature)
            elem_to_sign = elem

        elem_id = elem_to_sign.get('ID', None)
        if elem_id is not None:
            if elem_id:
                elem_id = '#' + elem_id
        else:
            generated_id = generated_id = OneLogin_Saml2_Utils.generate_unique_id()
            elem_id = '#' + generated_id
            elem_to_sign.attrib['ID'] = generated_id

        xmlsec.addIDs(elem_to_sign, ["ID"])

        digest_algorithm_transform_map = {
            OneLogin_Saml2_Constants.SHA1: xmlsec.TransformSha1,
            OneLogin_Saml2_Constants.SHA256: xmlsec.TransformSha256,
            OneLogin_Saml2_Constants.SHA384: xmlsec.TransformSha384,
            OneLogin_Saml2_Constants.SHA512: xmlsec.TransformSha512
        }
        digest_algorithm_transform = digest_algorithm_transform_map.get(digest_algorithm, xmlsec.TransformSha1)

        ref = signature.addReference(digest_algorithm_transform)
        if elem_id:
            ref.attrib['URI'] = elem_id

        ref.addTransform(xmlsec.TransformEnveloped)
        ref.addTransform(xmlsec.TransformExclC14N)

        key_info = signature.ensureKeyInfo()
        key_info.addX509Data()

        dsig_ctx = xmlsec.DSigCtx()
        sign_key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)

        file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
        sign_key.loadCert(file_cert.name, xmlsec.KeyDataFormatCertPem)
        file_cert.close()

        dsig_ctx.signKey = sign_key
        dsig_ctx.sign(signature)

        return tostring(elem, encoding='unicode').encode('utf-8')
        newdoc = parseString(tostring(elem, encoding='unicode').encode('utf-8'))
        return newdoc.saveXML(newdoc.firstChild)

    @staticmethod
    @return_false_on_exception
    def validate_sign(xml, cert=None, fingerprint=None, fingerprintalg='sha1', validatecert=False, debug=False, xpath=None, multicerts=None):
        """
        Validates a signature (Message or Assertion).

        :param xml: The element we should validate
        :type: string | Document

        :param cert: The pubic cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool

        :param xpath: The xpath of the signed element
        :type: string

        :param multicerts: Multiple public certs
        :type: list

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')
        elif isinstance(xml, etree._Element):
            elem = xml
        elif isinstance(xml, Document):
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, Element):
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAMLP),
                'xmlns:samlp',
                unicode(OneLogin_Saml2_Constants.NS_SAMLP)
            )
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAML),
                'xmlns:saml',
                unicode(OneLogin_Saml2_Constants.NS_SAML)
            )
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, basestring):
            elem = fromstring(str(xml))
        else:
            raise Exception('Error parsing xml string')

        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        xmlsec.addIDs(elem, ["ID"])

        if xpath:
            signature_nodes = OneLogin_Saml2_Utils.query(elem, xpath)
        else:
            signature_nodes = OneLogin_Saml2_Utils.query(elem, OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH)

            if len(signature_nodes) == 0:
                signature_nodes = OneLogin_Saml2_Utils.query(elem, OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH)

        if len(signature_nodes) == 1:
            signature_node = signature_nodes[0]

            if not multicerts:
                return OneLogin_Saml2_Utils.validate_node_sign(signature_node, elem, cert, fingerprint, fingerprintalg, validatecert, debug, raise_exceptions=True)
            else:
                # If multiple certs are provided, I may ignore cert and
                # fingerprint provided by the method and just check the
                # certs multicerts
                fingerprint = fingerprintalg = None
                for cert in multicerts:
                    if OneLogin_Saml2_Utils.validate_node_sign(signature_node, elem, cert, fingerprint, fingerprintalg, validatecert, False, raise_exceptions=False):
                        return True
                raise OneLogin_Saml2_ValidationError('Signature validation failed. SAML Response rejected.')
        else:
            raise OneLogin_Saml2_ValidationError('Expected exactly one signature node; got {}.'.format(len(signature_nodes)), OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_SIGNATURES)

    @staticmethod
    @return_false_on_exception
    def validate_metadata_sign(xml, cert=None, fingerprint=None, fingerprintalg='sha1', validatecert=False, debug=False):
        """
        Validates a signature of a EntityDescriptor.

        :param xml: The element we should validate
        :type: string | Document

        :param cert: The pubic cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')
        elif isinstance(xml, etree._Element):
            elem = xml
        elif isinstance(xml, Document):
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, Element):
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_MD),
                'xmlns:md',
                unicode(OneLogin_Saml2_Constants.NS_MD)
            )
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, basestring):
            elem = fromstring(str(xml))
        else:
            raise Exception('Error parsing xml string')

        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        xmlsec.addIDs(elem, ["ID"])

        signature_nodes = OneLogin_Saml2_Utils.query(elem, '/md:EntitiesDescriptor/ds:Signature')

        if len(signature_nodes) == 0:
            signature_nodes += OneLogin_Saml2_Utils.query(elem, '/md:EntityDescriptor/ds:Signature')

            if len(signature_nodes) == 0:
                signature_nodes += OneLogin_Saml2_Utils.query(elem, '/md:EntityDescriptor/md:SPSSODescriptor/ds:Signature')
                signature_nodes += OneLogin_Saml2_Utils.query(elem, '/md:EntityDescriptor/md:IDPSSODescriptor/ds:Signature')

        if len(signature_nodes) > 0:
            for signature_node in signature_nodes:
                OneLogin_Saml2_Utils.validate_node_sign(signature_node, elem, cert, fingerprint, fingerprintalg, validatecert, debug, raise_exceptions=True)
            return True
        else:
            raise Exception('Could not validate metadata signature: No signature nodes found.')

    @staticmethod
    @return_false_on_exception
    def validate_node_sign(signature_node, elem, cert=None, fingerprint=None, fingerprintalg='sha1', validatecert=False, debug=False):
        """
        Validates a signature node.

        :param signature_node: The signature node
        :type: Node

        :param xml: The element we should validate
        :type: Document

        :param cert: The public cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        xmlsec.addIDs(elem, ["ID"])

        if (cert is None or cert == '') and fingerprint:
            x509_certificate_nodes = OneLogin_Saml2_Utils.query(signature_node, '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
            if len(x509_certificate_nodes) > 0:
                x509_certificate_node = x509_certificate_nodes[0]
                x509_cert_value = OneLogin_Saml2_Utils.element_text(x509_certificate_node)
                x509_cert_value_formatted = OneLogin_Saml2_Utils.format_cert(x509_cert_value)
                x509_fingerprint_value = OneLogin_Saml2_Utils.calculate_x509_fingerprint(x509_cert_value_formatted, fingerprintalg)

                if fingerprint == x509_fingerprint_value:
                    cert = x509_cert_value_formatted

        # Check if Reference URI is empty
        # reference_elem = OneLogin_Saml2_Utils.query(signature_node, '//ds:Reference')
        # if len(reference_elem) > 0:
        #    if reference_elem[0].get('URI') == '':
        #        reference_elem[0].set('URI', '#%s' % signature_node.getparent().get('ID'))

        if cert is None or cert == '':
            raise OneLogin_Saml2_Error(
                'Could not validate node signature: No certificate provided.',
                OneLogin_Saml2_Error.CERT_NOT_FOUND
            )

        file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)

        if validatecert:
            mngr = xmlsec.KeysMngr()
            mngr.loadCert(file_cert.name, xmlsec.KeyDataFormatCertPem, xmlsec.KeyDataTypeTrusted)
            dsig_ctx = xmlsec.DSigCtx(mngr)
        else:
            dsig_ctx = xmlsec.DSigCtx()
            dsig_ctx.signKey = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)

        file_cert.close()

        dsig_ctx.setEnabledKeyData([xmlsec.KeyDataX509])

        try:
            dsig_ctx.verify(signature_node)
        except Exception as err:
            raise OneLogin_Saml2_ValidationError(
                'Signature validation failed. SAML Response rejected. %s',
                OneLogin_Saml2_ValidationError.INVALID_SIGNATURE,
                err.__str__()
            )

        return True

    @staticmethod
    @return_false_on_exception
    def validate_binary_sign(signed_query, signature, cert=None, algorithm=OneLogin_Saml2_Constants.RSA_SHA1, debug=False):
        """
        Validates signed binary data (Used to validate GET Signature).

        :param signed_query: The element we should validate
        :type: string


        :param signature: The signature that will be validate
        :type: string

        :param cert: The public cert
        :type: string

        :param algorithm: Signature algorithm
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        error_callback_method = None
        if debug:
            error_callback_method = print_xmlsec_errors
        xmlsec.set_error_callback(error_callback_method)

        dsig_ctx = xmlsec.DSigCtx()

        file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
        dsig_ctx.signKey = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)
        file_cert.close()

        # Sign the metadata with our private key.
        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.TransformDsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.TransformRsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.TransformRsaSha256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.TransformRsaSha384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.TransformRsaSha512
        }
        sign_algorithm_transform = sign_algorithm_transform_map.get(algorithm, xmlsec.TransformRsaSha1)

        dsig_ctx.verifyBinary(signed_query, sign_algorithm_transform, signature)
        return True

    @staticmethod
    def get_encoded_parameter(get_data, name, default=None, lowercase_urlencoding=False):
        """Return a URL encoded get parameter value
        Prefer to extract the original encoded value directly from query_string since URL
        encoding is not canonical. The encoding used by ADFS 3.0 is not compatible with
        python's quote_plus (ADFS produces lower case hex numbers and quote_plus produces
        upper case hex numbers)
        """

        if name not in get_data:
            return OneLogin_Saml2_Utils.case_sensitive_urlencode(default, lowercase_urlencoding)
        if 'query_string' in get_data:
            return OneLogin_Saml2_Utils.extract_raw_query_parameter(get_data['query_string'], name)
        return OneLogin_Saml2_Utils.case_sensitive_urlencode(get_data[name], lowercase_urlencoding)

    @staticmethod
    def extract_raw_query_parameter(query_string, parameter, default=''):
        m = re.search('%s=([^&]+)' % parameter, query_string)
        if m:
            return m.group(1)
        else:
            return default

    @staticmethod
    def case_sensitive_urlencode(to_encode, lowercase=False):
        encoded = quote_plus(to_encode)
        return re.sub(r"%[A-F0-9]{2}", lambda m: m.group(0).lower(), encoded) if lowercase else encoded
