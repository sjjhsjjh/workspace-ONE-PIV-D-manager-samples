# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

# Run with Python 3.7 or later.
"""File in the certauth module."""
#
# Standard library imports, in alphabetic order.
#
# Module for enum classes.
# https://docs.python.org/3/library/enum.html
from enum  import auto, Enum


class KeyUsage(Enum):
    critical = auto()
    dataEncipherment = auto()
    keyEncipherment = auto()
    keyAgreement = auto()
    clientAuth = auto()
    nonRepudiation = auto()
    digitalSignature = auto()
    emailProtection = auto()
    serverAuth = auto()

# Some handy pages for key usage values.
#
# https://security.stackexchange.com/questions/33824/ssl-cert-types-and-key-usage
#
# https://gsallewell.github.io/piv-guides/details/

class CertificatePurpose(Enum):

    def __init__(
        self, keyUsages, extendedKeyUsages, humanSuffix=None, default=True
    ):
        self.keyUsages = tuple(
            keyUsage.name for keyUsage in keyUsages)
        self.extendedKeyUsages = tuple(
            extendedKeyUsage.name for extendedKeyUsage in extendedKeyUsages)
        self.humanSuffix = self.name[:4] if humanSuffix is None else humanSuffix
        self.default = default

    Authentication = ((
        # KeyUsage.critical, 
        KeyUsage.keyEncipherment, KeyUsage.keyAgreement
    ), (
        # KeyUsage.critical,
        KeyUsage.clientAuth,
    ))

    Encryption = ((
        # KeyUsage.critical,
        KeyUsage.dataEncipherment,
    ), (
        KeyUsage.emailProtection,
    ), "Encrypt")

    Signature = ((
        # KeyUsage.critical,
        KeyUsage.nonRepudiation, KeyUsage.digitalSignature
    ), (
        KeyUsage.emailProtection,
    ))

    # TOTH configuration for server certificates.
    # https://www.golinuxcloud.com/openssl-create-client-server-certificate/
    Server = ((
        KeyUsage.digitalSignature, KeyUsage.keyEncipherment
    ), (
        KeyUsage.serverAuth,
    ), None, False)

    @classmethod
    def defaults(cls):
        return tuple(purpose for purpose in cls if purpose.default)

    @classmethod
    def humanSuffixes(cls):
        return "".join(purpose.humanSuffix for purpose in cls.defaults())

    @staticmethod
    def suffix(purposes):
        return "".join(( "_" + purpose.name[:4] for purpose in purposes ))

    @classmethod
    def short_form(cls, specifier):
        allLower = specifier.islower()
        specifierParse = []
        startGroup = True
        for index, chr in enumerate(specifier):
            if startGroup:
                if chr.islower() or chr.isupper():
                    specifierParse += chr.lower()
                    startGroup = False
                continue
            
            if chr.isupper():
                specifierParse += chr.lower()
                continue
            
            if (allLower and chr.islower()):
                specifierParse += chr.lower()
                continue

            if not chr.islower():
                specifierParse += ','
                startGroup = True

        return ''.join(specifierParse)

    @classmethod
    def parsePurposesSpecifier(cls, specifier):
        shortForm = cls.short_form(specifier)
        if specifier == cls.Server.name:
            return specifier, [[cls.Server,],], True, ["Server special case."]
        certificates = []
        reports = []
        ok = None
        for specifiers in shortForm.split(','):
            purposes = []
            repeatedPurpose = False
            for specifier in specifiers:
                for purpose in CertificatePurpose:
                    if purpose.name.lower().startswith(specifier):
                        if purpose in purposes:
                            repeatedPurpose = True
                        purposes.append(purpose)
                        break
            duplicate = False
            for certificate in certificates:
                if len(certificate) != len(purposes):
                    continue
                match = True
                for otherPurpose in certificate:
                    if purpose != otherPurpose:
                        match = False
                        break
                if match:
                    duplicate = True
                    break
            certificates.append(purposes)
            error = (
                "Repeated purpose" if repeatedPurpose
                else "Duplicate" if duplicate
                else "No purposes" if len(purposes) == 0
                else None if len(specifiers) == len(purposes)
                else "Mismatch"
            )
            reports.append(" ".join((
                "OK" if error is None else error,
                f'"{specifiers}"',
                f'{",".join(tuple(purpose.name for purpose in purposes))}'
            )))
            if ok is None:
                ok = (error is None)
            else:
                ok = ok and (error is None)

        if ok is None:
            ok = False
        
        return shortForm, certificates, ok, reports

# Encryption only.
# keyUsage = keyEncipherment
# No EKU.

# Signature only.
# keyUsage = nonRepiation, digitalSignature
# No EKU.

# No purposes
# keyUsage = critical, digitalSignature
# extendedKeyUsage = critical, clientAuth

# Signature and Encryption cert, no auth:
# keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
# extendedKeyUsage = emailProtection

# Authentication and Encryption cert, no signing:
# keyUsage = critical, keyEncipherment, keyAgreement
# extendedKeyUsage = critical, clientAuth

# extendedKeyUsage = clientAuth, emailProtection
