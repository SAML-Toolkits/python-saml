# -*- coding: utf-8 -*-

# MIT License

from base64 import b64encode
import json
from os.path import dirname, join, exists
import unittest

from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings


class OneLogin_Saml2_SignedResponse_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    def loadSettingsJSON(self):
        filename = join(self.settings_path, 'settings1.json')
        if exists(filename):
            stream = open(filename, 'r')
            settings = json.load(stream)
            stream.close()
            return settings
        else:
            raise Exception('Settings json file does not exist')

    def file_contents(self, filename):
        f = open(filename, 'r')
        content = f.read()
        f.close()
        return content

    def testResponseSignedAssertionNot(self):
        """
        Tests the getNameId method of the OneLogin_Saml2_Response
        Case valid signed response, unsigned assertion
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'responses', 'open_saml_response.xml'))
        response = OneLogin_Saml2_Response(settings, b64encode(message))

        self.assertEquals('someone@example.org', response.get_nameid())

    def testResponseAndAssertionSigned(self):
        """
        Tests the getNameId method of the OneLogin_Saml2_Response
        Case valid signed response, signed assertion
        """
        settings_info = self.loadSettingsJSON()
        settings_info['idp']['entityId'] = "https://federate.example.net/saml/saml2/idp/metadata.php"
        settings_info['sp']['entityId'] = "hello.com"

        settings = OneLogin_Saml2_Settings(settings_info)
        message = self.file_contents(join(self.data_path, 'responses', 'simple_saml_php.xml'))
        response = OneLogin_Saml2_Response(settings, b64encode(message))

        self.assertEquals('someone@example.com', response.get_nameid())


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    unittest.main(testRunner=runner)
