# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

# Run with Python 3.7 or later.
"""File in the certauth module."""
#
# Uses the following recent Python features.
# -   Python 3.7 subprocess text output and capture_output.
#
# Standard library imports, in alphabetic order.
#
# Email address parser, only used to identify email addresses.
# https://docs.python.org/3/library/email.headerregistry.html#email.headerregistry.Address
from email.headerregistry import Address
from email.errors import InvalidHeaderDefect
#
# Internet Protocol (IP) address parser. Only used to identify IP addresses.
# https://docs.python.org/3/library/ipaddress.html#ipaddress.ip_interface
from ipaddress import ip_interface
#
# Module for OO path handling.
# https://docs.python.org/3/library/pathlib.html
from pathlib import Path
#
# Local imports.
#
from certauth.certificate_purpose import CertificatePurpose

class CertificateConfiguration:

    # Properties for cartauth CLI.
    @property
    def countryCode(self):
        return self._countryCode
    @countryCode.setter
    def countryCode(self, countryCode):
        self._countryCode = countryCode

    @property
    def stateName(self):
        return self._stateName
    @stateName.setter
    def stateName(self, stateName):
        self._stateName = stateName

    @property
    def localityName(self):
        return self._localityName
    @localityName.setter
    def localityName(self, localityName):
        self._localityName = localityName

    @property
    def organisationName(self):
        return self._organisationName
    @organisationName.setter
    def organisationName(self, organisationName):
        self._organisationName = organisationName

    @property
    def organisationalUnitName(self):
        return self._organisationalUnitName
    @organisationalUnitName.setter
    def organisationalUnitName(self, organisationalUnitName):
        self._organisationalUnitName = organisationalUnitName

    @property
    def purposesSpecifier(self):
        return self._purposesSpecifier
    @purposesSpecifier.setter
    def purposesSpecifier(self, purposesSpecifier):
        self._purposesSpecifier = purposesSpecifier

    # End of CLI properties.

    # Computed property.
    @property
    def certificatesPurposes(self):
        return self._certificatesPurposes

    # End of computer property.

    def _write_one_CNF(self, cnfPath, address, purposes):
        # TOTH
        #
        # CNF file:
        # https://www.golinuxcloud.com/openssl-generate-csr-create-san-certificate/
        # https://www.golinuxcloud.com/openssl-create-client-server-certificate/
        #
        # How to put UPN into a certificate:
        # https://mchesnavsky.tech/generate-ssl-certificate-with-user-principal-name-openssl/
        #
        # Long identifiers for fields in the distinguished name:  
        # https://www.openssl.org/docs/man3.0/man1/openssl-req.html  
        # Look for stateOrProvinceName.
        #
        # Subject Alternate Name in a CNF file for a CSR.
        # https://www.ibm.com/support/pages/how-create-csr-multiple-subject-alternative-name-san-entries-pase-openssl-3rd-party-or-internet-ca
        #
        # Some other useful looking pages:
        # https://sockettools.com/kb/creating-certificate-using-openssl/
        # https://www.openssl.org/docs/manmaster/man5/x509v3_config.html

        addressCNF = address.replace('#', '\#')

        keyUsages = []
        extendedKeyUsages = []
        for purpose in purposes:
            for usage in purpose.keyUsages:
                if usage not in keyUsages:
                    keyUsages.append(usage)
            for usage in purpose.extendedKeyUsages:
                if usage not in extendedKeyUsages:
                    extendedKeyUsages.append(usage)
        
        keyUsagesCNF = (
            "" if len(keyUsages) == 0 else
            ''.join(( 'keyUsage = ', (", ".join(keyUsages)), "\n" ))
        )
        extendedKeyUsagesCNF = (
            "" if len(extendedKeyUsages) == 0 else
            ''.join((
                'extendedKeyUsage = ', (", ".join(extendedKeyUsages)), "\n"
            ))
        )
        alternativeNames = "\n".join(
            name
            for name in self._subject_alternative_names(address, addressCNF)
        )

        if address != addressCNF: print(f'CNF address "{addressCNF}"')
        cnfPath.write_text(f'''# Written by certauth module.
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names
{keyUsagesCNF}{extendedKeyUsagesCNF}
[alt_names]
{alternativeNames}

[req]
prompt = no
distinguished_name = distinguished_names
req_extensions = req_extensions

[req_extensions]
subjectAltName = @alt_names
{keyUsagesCNF}{extendedKeyUsagesCNF}
[distinguished_names]
commonName = {addressCNF}
countryName = {self.countryCode}
stateOrProvinceName = {self.stateName}
localityName = {self.localityName}
emailAddress = {addressCNF}
organizationName = {self.organisationName}
organizationalUnitName = {self.organisationalUnitName}
'''
# deprecated.
# nsCertType = client, email
# nsComment = "OpenSSL Generated Client Certificate"

        )

        return cnfPath
    
    def _subject_alternative_names(self, address, addressCNF):
        isEmail = True
        try:
            _ = Address(addr_spec=address)
        except InvalidHeaderDefect:
            isEmail = False

        if isEmail:
            yield f'otherName = 1.3.6.1.4.1.311.20.2.3;UTF8:{addressCNF}'
            yield f'email = {addressCNF}'
            return
        
        nameType = "IP"
        try:
            _ = ip_interface(address)
        except ValueError:
            nameType = "DNS"

        yield f'{nameType} = {addressCNF}'

    def write_client_CNFs(self, depotPath, clientName, address):
        # On the next line
        #
        # -   humanSuffixes() is the default of all purposes.
        # -   [1] gets the certificate long forms.
        # -   [0] gets the first long form and there will be only one
        #     certificate.
        defaultSuffix = CertificatePurpose.suffix(
            CertificatePurpose.parsePurposesSpecifier(
                CertificatePurpose.humanSuffixes())[1][0])

        for purposes in self.certificatesPurposes:
            suffix = CertificatePurpose.suffix(purposes)
            if suffix == defaultSuffix:
                suffix = ""
            # Add a dummy suffix in case the client name includes a dot. The
            # with_suffix() method replaces everything after the last dot in the
            # stem.
            cnfPath = Path(
                depotPath, "".join((clientName, suffix, ".dummySuffix"))
            ).resolve().with_suffix(".cnf")
            yield self._write_one_CNF(cnfPath, address, purposes)

    def parsePurposesSpecifier(self):
        shortForm, certificates, ok, reports = (
            CertificatePurpose.parsePurposesSpecifier(self.purposesSpecifier))
        if not(
            ok and self.purposesSpecifier == CertificatePurpose.humanSuffixes()
        ):
            print(f'Purposes "{self.purposesSpecifier}".')
            if shortForm != self.purposesSpecifier:
                print(f'Parsed short form "{shortForm}".')
            print(f"Certificates {len(certificates)}:")
            for index, report in enumerate(reports):
                print(index + 1, report)

        self._certificatesPurposes = certificates[:]

        return ok

