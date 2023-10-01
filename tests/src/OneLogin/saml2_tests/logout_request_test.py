# -*- coding: utf-8 -*-

# MIT License

from base64 import b64encode
import json
from os.path import dirname, join, exists
import unittest
from urlparse import urlparse, parse_qs
from xml.dom.minidom import parseString

from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError


class OneLogin_Saml2_Logout_Request_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    def loadSettingsJSON(self, name='settings1.json'):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, 'r')
            settings = json.load(stream)
            stream.close()
            return settings

    def file_contents(self, filename):
        f = open(filename, 'r')
        content = f.read()
        f.close()
        return content

    def testConstructor(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        """
        settings_info = self.loadSettingsJSON()
        settings_info['security']['nameIdEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegexpMatches(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = OneLogin_Saml2_Utils.decode_base64_and_inflate(payload)
        self.assertRegexpMatches(inflated, '^<samlp:LogoutRequest')

    def testCreateDeflatedSAMLLogoutRequestURLParameter(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        The creation of a deflated SAML Logout Request
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegexpMatches(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = OneLogin_Saml2_Utils.decode_base64_and_inflate(payload)
        self.assertRegexpMatches(inflated, '^<samlp:LogoutRequest')

    def testConstructorWithNameIdFormatOnSettings(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Defines NameIDFormat from settings
        """
        settings_info = self.loadSettingsJSON()
        name_id = 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c'
        name_id_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        settings_info['sp']['NameIDFormat'] = name_id_format
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, name_id=name_id)
        logout_request_xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(logout_request.get_request())
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request_xml)
        expected_name_id_data = {
            'Value': name_id,
            'Format': name_id_format
        }
        self.assertEqual(expected_name_id_data, name_id_data)

    def testConstructorWithoutNameIdFormat(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Checks that NameIDFormat is not added
        """
        settings_info = self.loadSettingsJSON()
        name_id = 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c'
        name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        settings_info['sp']['NameIDFormat'] = name_id_format
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, name_id=name_id)
        logout_request_xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(logout_request.get_request())
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request_xml)
        expected_name_id_data = {
            'Value': name_id
        }
        self.assertEqual(expected_name_id_data, name_id_data)

    def testConstructorEncryptIdUsingX509certMulti(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Able to generate encryptedID with MultiCert
        """
        settings_info = self.loadSettingsJSON('settings8.json')
        settings_info['security']['nameIdEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegexpMatches(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = OneLogin_Saml2_Utils.decode_base64_and_inflate(payload)
        self.assertRegexpMatches(inflated, '^<samlp:LogoutRequest')
        self.assertRegexpMatches(inflated, '<saml:EncryptedID>')

    def testGetIDFromSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        id = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id)

        dom = parseString(logout_request)
        id2 = OneLogin_Saml2_Logout_Request.get_id(dom)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id2)

    def testGetIDFromDeflatedSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        deflated_logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(deflated_logout_request)
        id = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id)

    def testGetNameIdData(self):
        """
        Tests the get_nameid_data method of the OneLogin_Saml2_LogoutRequest
        """
        expected_name_id_data = {
            'Value': 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'SPNameQualifier': 'http://idp.example.com/'
        }

        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(request)
        self.assertEqual(expected_name_id_data, name_id_data)

        dom = parseString(request)
        name_id_data_2 = OneLogin_Saml2_Logout_Request.get_nameid_data(dom)
        self.assertEqual(expected_name_id_data, name_id_data_2)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        with self.assertRaisesRegexp(OneLogin_Saml2_Error, 'Key is required in order to decrypt the NameID'):
            OneLogin_Saml2_Logout_Request.get_nameid_data(request_2)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_data_4 = OneLogin_Saml2_Logout_Request.get_nameid_data(request_2, key)
        expected_name_id_data = {
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69',
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'SPNameQualifier': 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php'
        }
        self.assertEqual(expected_name_id_data, name_id_data_4)

        dom_2 = parseString(request_2)
        encrypted_id_nodes = dom_2.getElementsByTagName('saml:EncryptedID')
        encrypted_data = encrypted_id_nodes[0].firstChild.nextSibling
        encrypted_id_nodes[0].removeChild(encrypted_data)
        with self.assertRaisesRegexp(OneLogin_Saml2_ValidationError, 'NameID not found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid_data(dom_2.toxml(), key)

        idp_data = settings.get_idp_data()
        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'NameQualifier': idp_data['entityId'],
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69'
        }

        inv_request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'no_nameId.xml'))
        with self.assertRaisesRegexp(OneLogin_Saml2_ValidationError, 'NameID not found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid_data(inv_request)

        logout_request = OneLogin_Saml2_Logout_Request(settings, None, expected_name_id_data['Value'], None, idp_data['entityId'], expected_name_id_data['Format'])
        dom = parseString(logout_request.get_xml())
        name_id_data_3 = OneLogin_Saml2_Logout_Request.get_nameid_data(dom)
        self.assertEqual(expected_name_id_data, name_id_data_3)

        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69'
        }
        logout_request = OneLogin_Saml2_Logout_Request(settings, None, expected_name_id_data['Value'], None, None, expected_name_id_data['Format'])
        dom = parseString(logout_request.get_xml())
        name_id_data_4 = OneLogin_Saml2_Logout_Request.get_nameid_data(dom)
        self.assertEqual(expected_name_id_data, name_id_data_4)

        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
            'Value': 'http://idp.example.com/'
        }
        logout_request = OneLogin_Saml2_Logout_Request(settings)
        dom = parseString(logout_request.get_xml())
        name_id_data_5 = OneLogin_Saml2_Logout_Request.get_nameid_data(dom)
        self.assertEqual(expected_name_id_data, name_id_data_5)

    def testGetNameId(self):
        """
        Tests the get_nameid of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id = OneLogin_Saml2_Logout_Request.get_nameid(request)
        self.assertEqual(name_id, 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c')

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        with self.assertRaisesRegexp(OneLogin_Saml2_Error, 'Key is required in order to decrypt the NameID'):
            OneLogin_Saml2_Logout_Request.get_nameid(request_2)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_3 = OneLogin_Saml2_Logout_Request.get_nameid(request_2, key)
        self.assertEqual('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', name_id_3)

    def testGetIssuer(self):
        """
        Tests the get_issuer of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        issuer = OneLogin_Saml2_Logout_Request.get_issuer(request)
        self.assertEqual('http://idp.example.com/', issuer)

        dom = parseString(request)
        issuer_2 = OneLogin_Saml2_Logout_Request.get_issuer(dom)
        self.assertEqual('http://idp.example.com/', issuer_2)

        issuer_node = dom.getElementsByTagName('saml:Issuer')[0]
        issuer_node.parentNode.removeChild(issuer_node)
        issuer_3 = OneLogin_Saml2_Logout_Request.get_issuer(dom)
        self.assertIsNone(issuer_3)

    def testGetSessionIndexes(self):
        """
        Tests the get_session_indexes of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        session_indexes = OneLogin_Saml2_Logout_Request.get_session_indexes(request)
        self.assertEqual(len(session_indexes), 0)

        dom = parseString(request)
        session_indexes_2 = OneLogin_Saml2_Logout_Request.get_session_indexes(dom)
        self.assertEqual(len(session_indexes_2), 0)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_with_sessionindex.xml'))
        session_indexes_3 = OneLogin_Saml2_Logout_Request.get_session_indexes(request_2)
        self.assertEqual(['_ac72a76526cb6ca19f8438e73879a0e6c8ae5131'], session_indexes_3)

    def testIsInvalidXML(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid XML
        """
        request = b64encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, request)

        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, request)
        self.assertFalse(logout_request2.is_valid(request_data))

    def testIsInvalidIssuer(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid Issuer
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'invalid_issuer.xml'))
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))
        self.assertIn('Invalid issuer in the Logout Request', logout_request2.get_error())

    def testIsInvalidDestination(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid Destination
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))
        self.assertIn('The LogoutRequest was received at', logout_request2.get_error())

        dom = parseString(request)
        dom.documentElement.setAttribute('Destination', None)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        dom.documentElement.removeAttribute('Destination')
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertTrue(logout_request4.is_valid(request_data))

    def testIsValidWithCapitalization(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'exaMPLe.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))

        settings.set_strict(False)
        dom = parseString(request)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        settings.set_strict(True)
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertFalse(logout_request4.is_valid(request_data))

        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url.lower())
        logout_request5 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request5.is_valid(request_data))

    def testIsInValidWithCapitalization(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'INdex.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))

        settings.set_strict(False)
        dom = parseString(request)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        settings.set_strict(True)
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertFalse(logout_request4.is_valid(request_data))

        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url.lower())
        logout_request5 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request5.is_valid(request_data))

    def testIsInvalidNotOnOrAfter(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid NotOnOrAfter
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'not_after_failed.xml'))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))
        self.assertIn('Could not validate timestamp: expired. Check system clock.', logout_request2.get_error())

    def testIsValid(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))

        settings.set_strict(False)
        dom = parseString(request)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        settings.set_strict(True)
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, b64encode(dom.toxml()))
        self.assertFalse(logout_request4.is_valid(request_data))

        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        logout_request5 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request5.is_valid(request_data))

    def testIsValidRaisesExceptionWhenRaisesArgumentIsTrue(self):
        request = OneLogin_Saml2_Utils.deflate_and_base64_encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        settings.set_strict(True)

        logout_request = OneLogin_Saml2_Logout_Request(settings, request)

        self.assertFalse(logout_request.is_valid(request_data))

        with self.assertRaisesRegexp(OneLogin_Saml2_ValidationError, "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd"):
            logout_request.is_valid(request_data, raise_exceptions=True)

    def testIsValidSign(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {
                'SAMLRequest': 'lVLBitswEP0Vo7tjWbJkSyReFkIhsN1tm6WHvQTZHmdFbUmVZLqfXzlpIS10oZdhGM17b96MtkHNk5MP9myX+AW+LxBi9jZPJsjLyw4t3kirgg7SqBmCjL083n98kGSDpfM22t5O6AbyPkKFAD5qa1B22O/QSWA+EFWPjCtaM6gBugrXHCo6Ut6UgvTV2DSkBoKyr+BDQu5QIkrwEBY4mBCViamEyyrHNCf4ueSScMnIC8r2yY02Kl5QrzG6IIvC6dgt07eNsbl2G+vPhYEf1sBkz9oUA8y2LLQZ4G3jXt1dmALKHm18Mk/+fozgk5YQNMciJ+UzKWV11Wq3q3l5mcq3/9YKenYTrL3FGkihB1fMENWgoloVt8Ut0ZX1Me3xsM+On9bk86ImPep1kv+xdKuBsg/Wzyq+f6u1ood8vLTK6JUJGkxE7WnsSDcQRirOKMc97TtWCgqU1ZyJBvM+RZbSrv/l5mrg6sbJI4T1kId1ye0JhoaQgYg+XT1dnilMSZO4uko1jPSYVF0luqQjrmR/4X8X//jC7U8=',
                'RelayState': '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
                'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                'Signature': 'j/qDRTzgQw3cMDkkSkBOShqxi3t9qJxYnrADqwAECnJ3Y+iYgT33C0l/Vy3+ooQkFRyObYJqg9o7iIcMdgV6CXxpa6itVIUAI2VJewsMjzvJ4OdpePeSx7+/umVPKCfMvffsELlqo/UgxsyRZh8NMLej0ojCB7bUfIMKsiU7e0c='
            }
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

        request = OneLogin_Saml2_Utils.decode_base64_and_inflate(request_data['get_data']['SAMLRequest'])

        settings.set_strict(False)
        logout_request = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        relayState = request_data['get_data']['RelayState']
        del request_data['get_data']['RelayState']
        self.assertFalse(logout_request.is_valid(request_data))
        request_data['get_data']['RelayState'] = relayState

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))
        self.assertIn('The LogoutRequest was received at', logout_request2.get_error())

        settings.set_strict(False)
        old_signature = request_data['get_data']['Signature']
        request_data['get_data']['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333='
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertFalse(logout_request3.is_valid(request_data))
        self.assertIn('Signature validation failed. Logout Request rejected', logout_request3.get_error())

        request_data['get_data']['Signature'] = old_signature
        old_signature_algorithm = request_data['get_data']['SigAlg']
        del request_data['get_data']['SigAlg']
        self.assertTrue(logout_request3.is_valid(request_data))

        request_data['get_data']['RelayState'] = 'http://example.com/relaystate'
        self.assertFalse(logout_request3.is_valid(request_data))
        self.assertIn('Signature validation failed. Logout Request rejected', logout_request3.get_error())

        settings.set_strict(True)
        request_2 = request.replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', current_url)
        request_2 = request_2.replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/')
        request_data['get_data']['SAMLRequest'] = OneLogin_Saml2_Utils.deflate_and_base64_encode(request_2)
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, b64encode(request_2))
        self.assertFalse(logout_request4.is_valid(request_data))
        self.assertIn('Signature validation failed. Logout Request rejected', logout_request4.get_error())

        settings.set_strict(False)
        logout_request5 = OneLogin_Saml2_Logout_Request(settings, b64encode(request_2))
        self.assertFalse(logout_request5.is_valid(request_data))
        self.assertIn('Signature validation failed. Logout Request rejected', logout_request5.get_error())

        request_data['get_data']['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        self.assertFalse(logout_request5.is_valid(request_data))
        self.assertIn('Signature validation failed. Logout Request rejected', logout_request5.get_error())

        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        request_data['get_data']['SigAlg'] = old_signature_algorithm
        old_signature = request_data['get_data']['Signature']
        del request_data['get_data']['Signature']
        logout_request6 = OneLogin_Saml2_Logout_Request(settings, b64encode(request_2))
        self.assertFalse(logout_request6.is_valid(request_data))
        self.assertIn('The Message of the Logout Request is not signed and the SP require it', logout_request6.get_error())

        request_data['get_data']['Signature'] = old_signature
        settings_info['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        del settings_info['idp']['x509cert']
        settings_2 = OneLogin_Saml2_Settings(settings_info)
        logout_request7 = OneLogin_Saml2_Logout_Request(settings_2, b64encode(request_2))
        self.assertFalse(logout_request7.is_valid(request_data))
        self.assertEqual('In order to validate the sign on the Logout Request, the x509cert of the IdP is required', logout_request7.get_error())

    def testIsValidSignUsingX509certMulti(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {
                'SAMLRequest': 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
                'RelayState': '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
                'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                'Signature': 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
            }
        }
        settings_info = self.loadSettingsJSON('settings8.json')
        settings_info['strict'] = False
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, request_data['get_data']['SAMLRequest'])
        self.assertTrue(logout_request.is_valid(request_data))

    def testIsInValidRejectingDeprecatedSignatureAlgorithm(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {
                'SAMLRequest': 'fZJNa+MwEIb/itHdiTz6sC0SQyEsBPoB27KHXoIsj7cGW3IlGfLzV7G7kN1DL2KYmeedmRcdgp7GWT26326JP/FzwRCz6zTaoNbKkSzeKqfDEJTVEwYVjXp9eHpUsKNq9i4640Zyh3xP6BDQx8FZkp1PR3KpqexAl72QmpUCS8SW01IiZz2TVVGD4X1VQYlAsl/oQyKPJAklPIQFzzZEbWNK0YLnlOVA3wqpQCoB7yQ7pWsGq+NKfcQ4q/0+xKXvd8ZNe7Td7AYbw10UxrCbP2aSPbv4Yl/8Qx/R3+SB5bTOoXiDQvFNvjnc7lXrIr75kh+6eYdXPc0jrkMO+/umjXhOtpxP2Q/nJx2/9+uWGbq8X1tV9NqGAW0kzaVvoe1AAJeCSWqYaUVRM2SilKKuqDTpFSlszdcK29RthVm9YriZebYdXpsLdhVAB7VJzif3haYMqqTVcl0JMBR4y+s2zak3sf/4v8l/vlHzBw==',
                'RelayState': '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
                'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                'Signature': 'Ouxo9BV6zmq4yrgamT9EbSKy/UmvSxGS8z26lIMgKOEP4LFR/N23RftdANmo4HafrzSfA0YTXwhKDqbOByS0j+Ql8OdQOes7vGioSjo5qq/Bi+5i6jXwQfphnfcHAQiJL4gYVIifkhhHRWpvYeiysF1Y9J02me0izwazFmoRXr4='
            }
        }
        settings_info = self.loadSettingsJSON('settings8.json')
        settings_info['security']['rejectDeprecatedAlgorithm'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, request_data['get_data']['SAMLRequest'])
        self.assertFalse(logout_request.is_valid(request_data))
        self.assertEqual('Deprecated signature algorithm found: http://www.w3.org/2000/09/xmldsig#rsa-sha1', logout_request.get_error())

    def testGetXML(self):
        """
        Tests that we can get the logout request XML directly without
        going through intermediate steps
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request_generated = OneLogin_Saml2_Logout_Request(settings)

        expectedFragment = (
            'Destination="http://idp.example.com/SingleLogoutService.php">\n'
            '        <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '        <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://idp.example.com/</saml:NameID>\n'
            '        \n    </samlp:LogoutRequest>'
        )
        self.assertIn(expectedFragment, logout_request_generated.get_xml())

        logout_request_processed = OneLogin_Saml2_Logout_Request(settings, b64encode(request))
        self.assertEqual(request, logout_request_processed.get_xml())


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    unittest.main(testRunner=runner)
