# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Metadata class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Metadata class of OneLogin's Python Toolkit.

"""

from time import gmtime, strftime, time
from datetime import datetime
from defusedxml.minidom import parseString

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Metadata(object):
    """

    A class that contains methods related to the metadata of the SP

    """

    TIME_VALID = 172800   # 2 days
    TIME_CACHED = 604800  # 1 week

    @staticmethod
    def builder(sp, authnsign=False, wsign=False, valid_until=None, cache_duration=None, contacts=None, organization=None):
        """
        Builds the metadata of the SP

        :param sp: The SP data
        :type sp: string

        :param authnsign: authnRequestsSigned attribute
        :type authnsign: string

        :param wsign: wantAssertionsSigned attribute
        :type wsign: string

        :param valid_until: Metadata's expiry date
        :type valid_until: string|DateTime|Timestamp

        :param cache_duration: Duration of the cache in seconds
        :type cache_duration: int|string

        :param contacts: Contacts info
        :type contacts: dict

        :param organization: Organization info
        :type organization: dict
        """
        if valid_until is None:
            valid_until = int(time()) + OneLogin_Saml2_Metadata.TIME_VALID
        if not isinstance(valid_until, basestring):
            if isinstance(valid_until, datetime):
                valid_until_time = valid_until.timetuple()
            else:
                valid_until_time = gmtime(valid_until)
            valid_until_str = strftime(r'%Y-%m-%dT%H:%M:%SZ', valid_until_time)
        else:
            valid_until_str = valid_until

        if cache_duration is None:
            cache_duration = OneLogin_Saml2_Metadata.TIME_CACHED
        if not isinstance(cache_duration, basestring):
            cache_duration_str = 'PT%sS' % cache_duration  # 'P'eriod of 'T'ime x 'S'econds
        else:
            cache_duration_str = cache_duration

        if contacts is None:
            contacts = {}
        if organization is None:
            organization = {}

        str_attribute_consuming_service = ''
        if 'attributeConsumingService' in sp and len(sp['attributeConsumingService']):
            attr_cs_desc_str = ''
            if "serviceDescription" in sp['attributeConsumingService']:
                attr_cs_desc_str = """            <md:ServiceDescription xml:lang="en">%s</md:ServiceDescription>
""" % sp['attributeConsumingService']['serviceDescription']

            requested_attribute_data = []
            for req_attribs in sp['attributeConsumingService']['requestedAttributes']:
                req_attr_nameformat_str = req_attr_friendlyname_str = req_attr_isrequired_str = ''
                req_attr_aux_str = ' />'

                if 'nameFormat' in req_attribs.keys() and req_attribs['nameFormat']:
                    req_attr_nameformat_str = " NameFormat=\"%s\"" % req_attribs['nameFormat']
                if 'friendlyName' in req_attribs.keys() and req_attribs['friendlyName']:
                    req_attr_nameformat_str = " FriendlyName=\"%s\"" % req_attribs['friendlyName']
                if 'isRequired' in req_attribs.keys() and req_attribs['isRequired']:
                    req_attr_isrequired_str = " isRequired=\"%s\"" % req_attribs['isRequired']

                if 'attributeValue' in req_attribs.keys() and req_attribs['attributeValue']:
                    if isinstance(req_attribs['attributeValue'], basestring):
                        req_attribs['attributeValue'] = [req_attribs['attributeValue']]

                    req_attr_aux_str = ">"
                    for attrValue in req_attribs['attributeValue']:
                        req_attr_aux_str += """
                <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(attributeValue)s</saml:AttributeValue>""" % \
                            {
                                'attributeValue': attrValue
                            }
                    req_attr_aux_str += """
            </md:RequestedAttribute>"""

                requested_attribute = """            <md:RequestedAttribute Name="%(req_attr_name)s"%(req_attr_nameformat_str)s%(req_attr_friendlyname_str)s%(req_attr_isrequired_str)s%(req_attr_aux_str)s""" % \
                    {
                        'req_attr_name': req_attribs['name'],
                        'req_attr_nameformat_str': req_attr_nameformat_str,
                        'req_attr_friendlyname_str': req_attr_friendlyname_str,
                        'req_attr_isrequired_str': req_attr_isrequired_str,
                        'req_attr_aux_str': req_attr_aux_str
                    }

                requested_attribute_data.append(requested_attribute)

            str_attribute_consuming_service = """        <md:AttributeConsumingService index="1">
            <md:ServiceName xml:lang="en">%(service_name)s</md:ServiceName>
%(attr_cs_desc)s%(requested_attribute_str)s
        </md:AttributeConsumingService>
""" % \
                {
                    'service_name': sp['attributeConsumingService']['serviceName'],
                    'attr_cs_desc': attr_cs_desc_str,
                    'requested_attribute_str': '\n'.join(requested_attribute_data)
                }

        sls = ''
        if 'singleLogoutService' in sp and 'url' in sp['singleLogoutService']:
            sls = """        <md:SingleLogoutService Binding="%(binding)s"
                                Location="%(location)s" />\n""" % \
                {
                    'binding': sp['singleLogoutService']['binding'],
                    'location': sp['singleLogoutService']['url'],
                }

        str_authnsign = 'true' if authnsign else 'false'
        str_wsign = 'true' if wsign else 'false'

        str_organization = ''
        if len(organization) > 0:
            organization_names = []
            organization_displaynames = []
            organization_urls = []
            for (lang, info) in organization.items():
                organization_names.append("""        <md:OrganizationName xml:lang="%s">%s</md:OrganizationName>""" % (lang, info['name']))
                organization_displaynames.append("""        <md:OrganizationDisplayName xml:lang="%s">%s</md:OrganizationDisplayName>""" % (lang, info['displayname']))
                organization_urls.append("""        <md:OrganizationURL xml:lang="%s">%s</md:OrganizationURL>""" % (lang, info['url']))
            org_data = '\n'.join(organization_names) + '\n' + '\n'.join(organization_displaynames) + '\n' + '\n'.join(organization_urls)
            str_organization = """    <md:Organization>
%(org)s
    </md:Organization>\n""" % {'org': org_data}

        str_contacts = ''
        if len(contacts) > 0:
            contacts_info = []
            for (ctype, info) in contacts.items():
                contact = """    <md:ContactPerson contactType="%(type)s">
        <md:GivenName>%(name)s</md:GivenName>
        <md:EmailAddress>%(email)s</md:EmailAddress>
    </md:ContactPerson>""" % \
                    {
                        'type': ctype,
                        'name': info['givenName'],
                        'email': info['emailAddress'],
                    }
                contacts_info.append(contact)
            str_contacts = '\n'.join(contacts_info) + '\n'

        metadata = u"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     %(valid)s
                     %(cache)s
                     entityID="%(entity_id)s">
    <md:SPSSODescriptor AuthnRequestsSigned="%(authnsign)s" WantAssertionsSigned="%(wsign)s" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(sls)s        <md:NameIDFormat>%(name_id_format)s</md:NameIDFormat>
        <md:AssertionConsumerService Binding="%(binding)s"
                                     Location="%(location)s"
                                     index="1" />
%(attribute_consuming_service)s    </md:SPSSODescriptor>
%(organization)s%(contacts)s</md:EntityDescriptor>""" % \
            {
                'valid': ('validUntil="%s"' % valid_until_str) if valid_until_str else '',
                'cache': ('cacheDuration="%s"' % cache_duration_str) if cache_duration_str else '',
                'entity_id': sp['entityId'],
                'authnsign': str_authnsign,
                'wsign': str_wsign,
                'name_id_format': sp['NameIDFormat'],
                'binding': sp['assertionConsumerService']['binding'],
                'location': sp['assertionConsumerService']['url'],
                'sls': sls,
                'organization': str_organization,
                'contacts': str_contacts,
                'attribute_consuming_service': str_attribute_consuming_service
            }
        return metadata

    @staticmethod
    def sign_metadata(metadata, key, cert, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Signs the metadata with the key/cert provided

        :param metadata: SAML Metadata XML
        :type metadata: string

        :param key: x509 key
        :type key: string

        :param cert: x509 cert
        :type cert: string

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string

        :returns: Signed Metadata
        :rtype: string
        """
        return OneLogin_Saml2_Utils.add_sign(metadata, key, cert, False, sign_algorithm)

    @staticmethod
    def add_x509_key_descriptors(metadata, cert=None):
        """
        Adds the x509 descriptors (sign/encryption) to the metadata
        The same cert will be used for sign/encrypt

        :param metadata: SAML Metadata XML
        :type metadata: string

        :param cert: x509 cert
        :type cert: string

        :returns: Metadata with KeyDescriptors
        :rtype: string
        """
        if cert is None or cert == '':
            return metadata
        try:
            xml = parseString(metadata.encode('utf-8'))
        except Exception as e:
            raise Exception('Error parsing metadata. ' + e.message)

        formated_cert = OneLogin_Saml2_Utils.format_cert(cert, False)
        x509_certificate = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:X509Certificate')
        content = xml.createTextNode(formated_cert)
        x509_certificate.appendChild(content)

        key_data = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:X509Data')
        key_data.appendChild(x509_certificate)

        key_info = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:KeyInfo')
        key_info.appendChild(key_data)

        key_descriptor = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'md:KeyDescriptor')

        entity_descriptor = xml.getElementsByTagName('md:EntityDescriptor')[0]

        sp_sso_descriptor = entity_descriptor.getElementsByTagName('md:SPSSODescriptor')[0]
        sp_sso_descriptor.insertBefore(key_descriptor.cloneNode(True), sp_sso_descriptor.firstChild)
        sp_sso_descriptor.insertBefore(key_descriptor.cloneNode(True), sp_sso_descriptor.firstChild)

        signing = xml.getElementsByTagName('md:KeyDescriptor')[0]
        signing.setAttribute('use', 'signing')

        encryption = xml.getElementsByTagName('md:KeyDescriptor')[1]
        encryption.setAttribute('use', 'encryption')

        signing.appendChild(key_info)
        encryption.appendChild(key_info.cloneNode(True))

        signing.setAttribute('xmlns:ds', OneLogin_Saml2_Constants.NS_DS)
        encryption.setAttribute('xmlns:ds', OneLogin_Saml2_Constants.NS_DS)

        return xml.toxml()
