# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Authn_Request class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

AuthNRequest class of OneLogin's Python Toolkit.

"""
import logging

from base64 import b64encode
from zlib import compress

from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.constants import OneLogin_Saml2_Constants

import dm.xmlsec.binding as xmlsec
from dm.xmlsec.binding.tmpl import Signature

log = logging.getLogger(__name__)

class OneLogin_Saml2_Authn_Request(object):
    """

    This class handles an AuthNRequest. It builds an
    AuthNRequest object.

    """

    def __init__(self, settings, force_authn=False, is_passive=False):
        """
        Constructs the AuthnRequest object.

        :param settings: OSetting data
        :type return_to: OneLogin_Saml2_Settings

        :param force_authn: Optional argument. When true the AuthNReuqest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNReuqest will set the Ispassive='true'.
        :type is_passive: bool
        """
        self.__settings = settings

        sp_data = self.__settings.get_sp_data()
        idp_data = self.__settings.get_idp_data()
        security = self.__settings.get_security_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        self.__id = uid
        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        destination = idp_data['singleSignOnService']['url']

        name_id_policy_format = sp_data['NameIDFormat']
        if 'wantNameIdEncrypted' in security and security['wantNameIdEncrypted']:
            name_id_policy_format = OneLogin_Saml2_Constants.NAMEID_ENCRYPTED

        provider_name_str = ''
        organization_data = settings.get_organization()
        if isinstance(organization_data, dict) and organization_data:
            langs = organization_data.keys()
            if 'en-US' in langs:
                lang = 'en-US'
            else:
                lang = langs[0]
            if 'displayname' in organization_data[lang] and organization_data[lang]['displayname'] is not None:
                provider_name_str = 'ProviderName="%s"' % organization_data[lang]['displayname']

        force_authn_str = ''
        if force_authn is True:
            force_authn_str = 'ForceAuthn="true"'

        is_passive_str = ''
        if is_passive is True:
            is_passive_str = 'IsPassive="true"'

        requested_authn_context_str = ''
        if 'requestedAuthnContext' in security.keys() and security['requestedAuthnContext'] is not False:
            if security['requestedAuthnContext'] is True:
                requested_authn_context_str = """    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>"""
            else:
                requested_authn_context_str = '     <samlp:RequestedAuthnContext Comparison="exact">'
                for authn_context in security['requestedAuthnContext']:
                    requested_authn_context_str += '<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>' % authn_context
                requested_authn_context_str += '    </samlp:RequestedAuthnContext>'

        request = """<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%(id)s"
    Version="2.0"
    %(provider_name)s
    %(force_authn_str)s
    %(is_passive_str)s
    IssueInstant="%(issue_instant)s"
    Destination="%(destination)s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="%(assertion_url)s">
    <saml:Issuer>%(entity_id)s</saml:Issuer>


    <samlp:NameIDPolicy
        Format="%(name_id_policy)s"
        AllowCreate="true" />
%(requested_authn_context_str)s
</samlp:AuthnRequest>""" % \
            {
                'id': uid,
                'provider_name': provider_name_str,
                'force_authn_str': force_authn_str,
                'is_passive_str': is_passive_str,
                'issue_instant': issue_instant,
                'destination': destination,
                'assertion_url': sp_data['assertionConsumerService']['url'],
                'entity_id': sp_data['entityId'],
                'name_id_policy': name_id_policy_format,
                'requested_authn_context_str': requested_authn_context_str,
            }


        # Only the urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST binding gets the enveloped signature
        if settings.get_idp_data()['singleSignOnService'].get('binding', None) == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' and security['authnRequestsSigned'] == True:

            log.debug("Generating AuthnRequest using urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST binding")

            xmlsec.initialize()
            xmlsec.set_error_callback(self.print_xmlsec_errors)

            signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)

            from lxml.etree import parse, tostring, fromstring
            doc = fromstring(request)

            # ID attributes different from xml:id must be made known by the application through a call
            # to the addIds(node, ids) function defined by xmlsec.
            xmlsec.addIDs(doc, ['ID'])

            doc.insert(0, signature)

            ref = signature.addReference(xmlsec.TransformSha1,uri="#%s" % uid)
            ref.addTransform(xmlsec.TransformEnveloped)
            ref.addTransform(xmlsec.TransformExclC14N)

            key_info = signature.ensureKeyInfo()
            key_info.addKeyName()
            key_info.addX509Data()


            # Load the key into the xmlsec context
            key = settings.get_sp_key()
            if not key:
                raise OneLogin_Saml2_Error("Attempt to sign the AuthnRequest but unable to load the SP private key")

            dsig_ctx = xmlsec.DSigCtx()

            sign_key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)

            from tempfile import NamedTemporaryFile
            cert_file = NamedTemporaryFile(delete=True)
            cert_file.write(settings.get_sp_cert())
            cert_file.seek(0)

            sign_key.loadCert(cert_file.name, xmlsec.KeyDataFormatPem)

            dsig_ctx.signKey = sign_key

            # Note: the assignment below effectively copies the key
            dsig_ctx.sign(signature)

            self.__authn_request = tostring(doc)
            log.debug("Generated AuthnRequest: {}".format(self.__authn_request))

        else:
            self.__authn_request = request

    def print_xmlsec_errors(self, filename, line, func, errorObject, errorSubject, reason, msg):
        # this would give complete but often not very usefull) information
        print "%(filename)s:%(line)d(%(func)s) error %(reason)d obj=%(errorObject)s subject=%(errorSubject)s: %(msg)s" % locals()
        # the following prints if we get something with relation to the application

        info = []
        if errorObject != "unknown": info.append("obj=" + errorObject)
        if errorSubject != "unknown": info.append("subject=" + errorSubject)
        if msg.strip(): info.append("msg=" + msg)
        if info:
            print "%s:%d(%s)" % (filename, line, func), " ".join(info)

    def get_request(self):
        """
        Returns unsigned AuthnRequest.
        :return: Unsigned AuthnRequest
        :rtype: str object
        """
        deflated_request = compress(self.__authn_request)[2:-4]
        return b64encode(deflated_request)

    def get_id(self):
        """
        Returns the AuthNRequest ID.
        :return: AuthNRequest ID
        :rtype: string
        """
        return self.__id
