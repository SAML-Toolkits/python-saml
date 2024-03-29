# -*- coding: utf-8 -*-

# MIT License

import unittest
from onelogin.saml2.errors import OneLogin_Saml2_Error


class OneLogin_Saml2_Error_Test(unittest.TestCase):
    """
    Tests the OneLogin_Saml2_Error Constructor.
    """
    def runTest(self):
        exception = OneLogin_Saml2_Error('test')
        self.assertEqual(exception.message, 'test')


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    unittest.main(testRunner=runner)
