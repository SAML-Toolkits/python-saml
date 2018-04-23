# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

import unittest
from teamcity import is_running_under_teamcity
from teamcity.unittestpy import TeamcityTestRunner
from onelogin.saml2.errors import OneLogin_Saml2_Error


class OneLogin_Saml2_Error_Test(unittest.TestCase):
    """
    Tests the OneLogin_Saml2_Error Constructor.
    """
    def runTest(self):
        exception = OneLogin_Saml2_Error('test')
        self.assertEqual(exception.message, 'test')


if __name__ == '__main__':
    if is_running_under_teamcity():
        runner = TeamcityTestRunner()
    else:
        runner = unittest.TextTestRunner()
    unittest.main(testRunner=runner)
