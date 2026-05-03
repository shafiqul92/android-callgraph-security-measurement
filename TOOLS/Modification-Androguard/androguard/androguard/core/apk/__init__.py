# Allows type hinting of types not-yet-declared
# in Python >= 3.7
# see https://peps.python.org/pep-0563/
from __future__ import annotations

# Python core
import binascii
import hashlib
import io
import os
import re
from struct import unpack
from typing import Iterator, Union
import zipfile
from zlib import crc32

# Androguard
from androguard.core import androconf
from androguard.util import get_certificate_name_string
from apkInspector.headers import ZipEntry

from androguard.core.axml import (ARSCParser,
    AXMLPrinter,
    ARSCResTableConfig,
    AXMLParser,
    format_value,
    START_TAG,
    END_TAG,
    TEXT,
    END_DOCUMENT)

# External dependencies
from lxml.etree import Element
import lxml.sax
from xml.dom.pulldom import SAX2DOM
# Used for reading Certificates
from asn1crypto import cms, x509, keys

from loguru import logger

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree

# Dictionary of the different protection levels mapped to their corresponding attribute names as described in
# https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/content/pm/PermissionInfo.java
protection_flags_to_attributes = {
    "0x00000000": "normal",
    "0x00000001": "dangerous",
    "0x00000002": "signature",
    "0x00000003": "signature or system",
    "0x00000004": "internal",
    "0x00000010": "privileged",
    "0x00000020": "development",
    "0x00000040": "appop",
    "0x00000080": "pre23",
    "0x00000100": "installer",
    "0x00000200": "verifier",
    "0x00000400": "preinstalled",
    "0x00000800": "setup",
    "0x00001000": "instant",
    "0x00002000": "runtime only",
    "0x00004000": "oem",
    "0x00008000": "vendor privileged",
    "0x00010000": "system text classifier",
    "0x00020000": "wellbeing",
    "0x00040000": "documenter",
    "0x00080000": "configurator",
    "0x00100000": "incident report approver",
    "0x00200000": "app predictor",
    "0x00400000": "module",
    "0x00800000": "companion",
    "0x01000000": "retail demo",
    "0x02000000": "recents",
    "0x04000000": "role",
    "0x08000000": "known signer"
}

def parse_lxml_dom(tree):
    handler = SAX2DOM()
    lxml.sax.saxify(tree, handler)
    return handler.document


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class FileNotPresent(Error):
    pass


class BrokenAPKError(Error):
    pass


class APK:
    # Constants in ZipFile
    _PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
    _PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

    # Constants in the APK Signature Block
    _APK_SIG_MAGIC = b"APK Sig Block 42"
    _APK_SIG_KEY_V2_SIGNATURE = 0x7109871a
    _APK_SIG_KEY_V3_SIGNATURE = 0xf05368c0
    _APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xbeeff00d

    _APK_SIG_ALGO_IDS = {
        0x0101 : "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102 : "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        0x0103 : "RSASSA-PKCS1-v1_5 with SHA2-256 digest.", # This is for build systems which require deterministic signatures.
        0x0104 : "RSASSA-PKCS1-v1_5 with SHA2-512 digest.", # This is for build systems which require deterministic signatures.
        0x0201 : "ECDSA with SHA2-256 digest",
        0x0202 : "ECDSA with SHA2-512 digest",
        0x0301 : "DSA with SHA2-256 digest",
    }

    __no_magic = False

    def __init__(self, filename:str, raw:bool=False, magic_file:Union[str,None]=None, skip_analysis:bool=False, testzip:bool=False) -> None:
        """
        This class can access to all elements in an APK file

        example::

            APK("myfile.apk")
            APK(read("myfile.apk"), raw=True)

        :param filename: specify the path of the file, or raw data
        :param raw: specify if the filename is a path or raw data (optional)
        :param magic_file: specify the magic file (not used anymore - legacy only)
        :param skip_analysis: Skip the analysis, e.g. no manifest files are read. (default: False)
        :param testzip: Test the APK for integrity, e.g. if the ZIP file is broken. Throw an exception on failure (default False)

        :type filename: string
        :type raw: boolean
        :type magic_file: string
        :type skip_analysis: boolean
        :type testzip: boolean

        """
        if magic_file:
            logger.warning("You set magic_file but this parameter is actually unused. You should remove it.")

        self.filename = filename

        self.xml = {}
        self.axml = {}
        self.arsc = {}

        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.uses_permissions = []
        self.declared_permissions = {}
        self.valid_apk = False

        self._is_signed_v2 = None
        self._is_signed_v3 = None
        self._v2_blocks = {}
        self._v2_signing_data = None
        self._v3_signing_data = None

        self._files = {}
        self.files_crc32 = {}

        if raw is True:
            self.__raw = filename
            self._sha256 = hashlib.sha256(self.__raw).hexdigest()
            # Set the filename to something sane
            self.filename = "raw_apk_sha256:{}".format(self._sha256)
            self.zip = ZipEntry.parse(io.BytesIO(self.__raw), True)
        else:
            self.zip = ZipEntry.parse(filename, False)
            self.__raw = self.zip.zip.getvalue()

        if testzip:
            logger.info("Testing zip file integrity, this might take a while...")
            # Test the zipfile for integrity before continuing.
            # This process might be slow, as the whole file is read.
            # Therefore it is possible to enable it as a separate feature.
            #
            # A short benchmark showed, that testing the zip takes about 10 times longer!
            # e.g. normal zip loading (skip_analysis=True) takes about 0.01s, where
            # testzip takes 0.1s!
            test_zip = zipfile.ZipFile(io.BytesIO(self.__raw), mode="r")
            ret = test_zip.testzip()
            if ret is not None:
                # we could print the filename here, but there are zip which are so broken
                # That the filename is either very very long or does not make any sense.
                # Thus we do not do it, the user might find out by using other tools.
                raise BrokenAPKError("The APK is probably broken: testzip returned an error.")

        if not skip_analysis:
            self._apk_analysis()

    @staticmethod
    def _ns(name):
        """
        return the name including the Android namespace URI
        """
        return NS_ANDROID + name

    def _apk_analysis(self):
        """
        Run analysis on the APK file.

        This method is usually called by __init__ except if skip_analysis is False.
        It will then parse the AndroidManifest.xml and set all fields in the APK class which can be
        extracted from the Manifest.
        """
        i = "AndroidManifest.xml"
        logger.info("Starting analysis on {}".format(i))
        try:
            manifest_data = self.zip.read(i)
        except KeyError:
            logger.warning("Missing AndroidManifest.xml. Is this an APK file?")
        else:
            ap = AXMLPrinter(manifest_data)

            if not ap.is_valid():
                logger.error("Error while parsing AndroidManifest.xml - is the file valid?")
                return

            self.axml[i] = ap
            self.xml[i] = self.axml[i].get_xml_obj()

            if self.axml[i].is_packed():
                logger.warning("XML Seems to be packed, operations on the AndroidManifest.xml might fail.")

            if self.xml[i] is not None:
                if self.xml[i].tag != "manifest":
                    logger.error("AndroidManifest.xml does not start with a <manifest> tag! Is this a valid APK?")
                    return

                self.package = self.get_attribute_value("manifest", "package")
                self.androidversion["Code"] = self.get_attribute_value("manifest", "versionCode")
                self.androidversion["Name"] = self.get_attribute_value("manifest", "versionName")
                permission = list(self.get_all_attribute_value("uses-permission", "name"))
                self.permissions = list(set(self.permissions + permission))

                for uses_permission in self.find_tags("uses-permission"):
                    self.uses_permissions.append([
                        self.get_value_from_tag(uses_permission, "name"),
                        self._get_permission_maxsdk(uses_permission)
                    ])

                # getting details of the declared permissions
                for d_perm_item in self.find_tags('permission'):
                    d_perm_name = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "name")))
                    d_perm_label = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "label")))
                    d_perm_description = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "description")))
                    d_perm_permissionGroup = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "permissionGroup")))
                    d_perm_protectionLevel = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "protectionLevel")))

                    d_perm_details = {
                        "label": d_perm_label,
                        "description": d_perm_description,
                        "permissionGroup": d_perm_permissionGroup,
                        "protectionLevel": d_perm_protectionLevel,
                    }
                    self.declared_permissions[d_perm_name] = d_perm_details

                self.valid_apk = True
                logger.info("APK file was successfully validated!")
                print("Hello, world!")

        self.permission_module = androconf.load_api_specific_resource_module(
            "aosp_permissions", self.get_target_sdk_version())
        self.permission_module_min_sdk = androconf.load_api_specific_resource_module(
            "aosp_permissions", self.get_min_sdk_version())
        print("Hello, world!")
    
    def __getstate__(self):
        """
        Function for pickling APK Objects.

        We remove the zip from the Object, as it is not pickable
        And it does not make any sense to pickle it anyways.

        :returns: the picklable APK Object without zip.
        """
        # Upon pickling, we need to remove the ZipFile
        x = self.__dict__
        x['axml'] = str(x['axml'])
        x['xml'] = str(x['xml'])
        del x['zip']

        return x

    def __setstate__(self, state):
        """
        Load a pickled APK Object and restore the state

        We load the zip file back by reading __raw from the Object.

        :param state: pickled state
        """
        self.__dict__ = state

        self.zip = zipfile.ZipFile(io.BytesIO(self.get_raw()), mode="r")

    def _get_res_string_value(self, string):
        if not string.startswith('@string/'):
            return string
        string_key = string[9:]

        res_parser = self.get_android_resources()
        if not res_parser:
            return ''
        string_value = ''
        for package_name in res_parser.get_packages_names():
            extracted_values = res_parser.get_string(package_name, string_key)
            if extracted_values:
                string_value = extracted_values[1]
                break
        return string_value

    def _get_permission_maxsdk(self, item):
        maxSdkVersion = None
        try:
            maxSdkVersion = int(self.get_value_from_tag(item, "maxSdkVersion"))
        except ValueError:
            logger.warning(str(maxSdkVersion) + ' is not a valid value for <uses-permission> maxSdkVersion')
        except TypeError:
            pass
        return maxSdkVersion

    def is_valid_APK(self) -> bool:
        """
        Return true if the APK is valid, false otherwise.
        An APK is seen as valid, if the AndroidManifest.xml could be successful parsed.
        This does not mean that the APK has a valid signature nor that the APK
        can be installed on an Android system.

        :rtype: boolean
        """
        return self.valid_apk

    def get_filename(self) -> str:
        """
        Return the filename of the APK

        :rtype: :class:`str`
        """
        return self.filename

    def get_app_name(self, locale=None) -> str:
        """
        Return the appname of the APK

        This name is read from the AndroidManifest.xml
        using the application android:label.
        If no label exists, the android:label of the main activity is used.

        If there is also no main activity label, an empty string is returned.

        :rtype: :class:`str`
        """

        app_name = self.get_attribute_value('application', 'label')
        if app_name is None:
            activities = self.get_main_activities()
            main_activity_name = None
            if len(activities) > 0:
                main_activity_name = activities.pop()

            # FIXME: would need to use _format_value inside get_attribute_value for each returned name!
            # For example, as the activity name might be foobar.foo.bar but inside the activity it is only .bar
            app_name = self.get_attribute_value('activity', 'label', name=main_activity_name)

        if app_name is None:
            # No App name set
            # TODO return packagename instead?
            logger.warning("It looks like that no app name is set for the main activity!")
            return ""

        if app_name.startswith("@"):
            res_parser = self.get_android_resources()
            if not res_parser:
                # TODO: What should be the correct return value here?
                return app_name

            res_id, package = res_parser.parse_id(app_name)

            # If the package name is the same as the APK package,
            # we should be able to resolve the ID.
            if package and package != self.get_package():
                if package == 'android':
                    # TODO: we can not resolve this, as we lack framework-res.apk
                    # one exception would be when parsing framework-res.apk directly.
                    logger.warning("Resource ID with android package name encountered! "
                                "Will not resolve, framework-res.apk would be required.")
                    return app_name
                else:
                    # TODO should look this up, might be in the resources
                    logger.warning("Resource ID with Package name '{}' encountered! Will not resolve".format(package))
                    return app_name

            try:
                config = ARSCResTableConfig(None, locale=locale) if locale else ARSCResTableConfig.default_config()
                app_name = res_parser.get_resolved_res_configs(
                    res_id,
                    config)[0][1]
            except Exception as e:
                logger.warning("Exception selecting app name: %s" % e)
        return app_name

    
    def get_package(self) -> str:
        """
        Return the name of the package

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.package

    def get_androidversion_code(self) -> str:
        """
        Return the android version code

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self) -> str:
        """
        Return the android version name

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Name"]

    def get_files(self) -> list[str]:
        """
        Return the file names inside the APK.

        :rtype: a list of :class:`str`
        """
        return self.zip.namelist()

    
    def get_files_types(self) -> dict[str,str]:
        """
        Return the files inside the APK with their associated types (by using python-magic)

        At the same time, the CRC32 are calculated for the files.

        :rtype: a dictionary
        """
        if self._files == {}:
            # Generate File Types / CRC List
            for i in self.get_files():
                buffer = self._get_crc32(i)
                self._files[i] = self._get_file_magic_name(buffer)

        return self._files

    def _patch_magic(self, buffer, orig):
        """
        Overwrite some probably wrong detections by mime libraries

        :param buffer: bytes of the file to detect
        :param orig: guess by mime libary
        :returns: corrected guess
        """
        if ("Zip" in orig) or ('(JAR)' in orig) and androconf.is_android_raw(buffer) == 'APK':
            return "Android application package file"

        return orig

    def _get_crc32(self, filename):
        """
        Calculates and compares the CRC32 and returns the raw buffer.

        The CRC32 is added to `files_crc32` dictionary, if not present.

        :param filename: filename inside the zipfile
        :rtype: bytes
        """
        buffer = self.zip.read(filename)
        if filename not in self.files_crc32:
            self.files_crc32[filename] = crc32(buffer)
            if self.files_crc32[filename] != self.zip.infolist()[filename].crc32_of_uncompressed_data:
                logger.error("File '{}' has different CRC32 after unpacking! "
                          "Declared: {:08x}, Calculated: {:08x}".format(filename,
                                                                        self.zip.infolist()[filename].crc32_of_uncompressed_data,
                                                                        self.files_crc32[filename]))
        return buffer

    def get_files_crc32(self) -> dict[str, int]:
        """
        Calculates and returns a dictionary of filenames and CRC32

        :returns: dict of filename: CRC32
        """
        if self.files_crc32 == {}:
            for i in self.get_files():
                self._get_crc32(i)

        return self.files_crc32

    def get_files_information(self) -> Iterator[tuple[str, str, int]]:
        """
        Return the files inside the APK with their associated types and crc32

        :rtype: str, str, int
        """
        for k in self.get_files():
            yield k, self.get_files_types()[k], self.get_files_crc32()[k]

    def get_raw(self) -> bytes:
        """
        Return raw bytes of the APK

        :rtype: bytes
        """

        if self.__raw:
            return self.__raw
        else:
            with open(self.filename, 'rb') as f:
                self.__raw = bytearray(f.read())
            return self.__raw

    def get_file(self, filename:str) -> bytes:
        """
        Return the raw data of the specified filename
        inside the APK

        :rtype: bytes
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self) -> bytes:
        """
        Return the raw data of the classes dex file

        This will give you the data of the file called `classes.dex`
        inside the APK. If the APK has multiple DEX files, you need to use :func:`~APK.get_all_dex`.

        :rtype: bytes
        """
        try:
            return self.get_file("classes.dex")
        except FileNotPresent:
            # TODO is this a good idea to return an empty string?
            return b""

    def get_dex_names(self) -> list[str]:
        """
        Return the names of all DEX files found in the APK.
        This method only accounts for "offical" dex files, i.e. all files
        in the root directory of the APK named classes.dex or classes[0-9]+.dex

        :rtype: a list of str
        """
        dexre = re.compile(r"^classes(\d*).dex$")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self) -> Iterator[bytes]:
        """
        Return the raw data of all classes dex files

        :rtype: a generator of bytes
        """
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def is_multidex(self) -> bool:
        """
        Test if the APK has multiple DEX files

        :returns: True if multiple dex found, otherwise False
        """
        dexre = re.compile(r"^classes(\d+)?.dex$")
        return len([instance for instance in self.get_files() if dexre.search(instance)]) > 1

    def _format_value(self, value):
        """
        Format a value with packagename, if not already set.
        For example, the name :code:`'.foobar'` will be transformed into :code:`'package.name.foobar'`.

        Names which do not contain any dots are assumed to be packagename-less as well:
        :code:`foobar` will also transform into :code:`package.name.foobar`.

        :param value:
        :returns:
        """
        if value and self.package:
            v_dot = value.find(".")
            if v_dot == 0:
                # Dot at the start
                value = self.package + value
            elif v_dot == -1:
                # Not a single dot
                value = self.package + "." + value
        return value

    def get_all_attribute_value(
        self, tag_name: str, attribute: str, format_value:bool=True, **attribute_filter
    ) -> Iterator[str]:
        """
        Yields all the attribute values in xml files which match with the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """
        tags = self.find_tags(tag_name, **attribute_filter)
        for tag in tags:
            value = tag.get(self._ns(attribute)) or tag.get(attribute)
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value

    def get_attribute_value(
        self, tag_name:str, attribute:str, format_value:bool=False, **attribute_filter
    ) -> str:
        """
        Return the attribute value in xml files which matches the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """

        for value in self.get_all_attribute_value(
                tag_name, attribute, format_value, **attribute_filter):
            if value is not None:
                return value

    def get_value_from_tag(self, tag: Element, attribute: str) -> Union[str,None]:
        """
        Return the value of the android prefixed attribute in a specific tag.

        This function will always try to get the attribute with a android: prefix first,
        and will try to return the attribute without the prefix, if the attribute could not be found.
        This is useful for some broken AndroidManifest.xml, where no android namespace is set,
        but could also indicate malicious activity (i.e. wrongly repackaged files).
        A warning is printed if the attribute is found without a namespace prefix.

        If you require to get the exact result you need to query the tag directly:

        example::
            >>> from lxml.etree import Element
            >>> tag = Element('bar', nsmap={'android': 'http://schemas.android.com/apk/res/android'})
            >>> tag.set('{http://schemas.android.com/apk/res/android}foobar', 'barfoo')
            >>> tag.set('name', 'baz')
            # Assume that `a` is some APK object
            >>> a.get_value_from_tag(tag, 'name')
            'baz'
            >>> tag.get('name')
            'baz'
            >>> tag.get('foobar')
            None
            >>> a.get_value_from_tag(tag, 'foobar')
            'barfoo'

        :param lxml.etree.Element tag: specify the tag element
        :param str attribute: specify the attribute name
        :returns: the attribute's value, or None if the attribute is not present
        """

        # TODO: figure out if both android:name and name tag exist which one to give preference:
        # currently we give preference for the namespace one and fallback to the un-namespaced
        value = tag.get(self._ns(attribute))
        if value is None:
            value = tag.get(attribute)

            if value:
                # If value is still None, the attribute could not be found, thus is not present
                logger.warning("Failed to get the attribute '{}' on tag '{}' with namespace. "
                            "But found the same attribute without namespace!".format(attribute, tag.tag))
        return value

    def find_tags(self, tag_name: str, **attribute_filter) -> list[str]:
        """
        Return a list of all the matched tags in all available xml

        :param str tag: specify the tag name
        """
        all_tags = [
            self.find_tags_from_xml(
                i, tag_name, **attribute_filter
            )
            for i in self.xml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tags_from_xml(
        self, xml_name: str, tag_name: str, **attribute_filter
    ) -> list[str]:
        """
        Return a list of all the matched tags in a specific xml
        w
        :param str xml_name: specify from which xml to pick the tag from
        :param str tag_name: specify the tag name
        """
        xml = self.xml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(
                xml.tag, **attribute_filter
            ):
                return [xml]
            return []
        tags = set()
        tags.update(xml.findall(".//" + tag_name))

        # https://github.com/androguard/androguard/pull/1053
        # permission declared using tag <android:uses-permission...
        tags.update(xml.findall(".//" + NS_ANDROID + tag_name))
        return [
            tag for tag in tags if self.is_tag_matched(
                tag, **attribute_filter
            )
        ]

    def is_tag_matched(self, tag: str, **attribute_filter) -> bool:
        r"""
        Return true if the attributes matches in attribute filter.

        An attribute filter is a dictionary containing: {attribute_name: value}.
        This function will return True if and only if all attributes have the same value.
        This function allows to set the dictionary via kwargs, thus you can filter like this:

        example::
            a.is_tag_matched(tag, name="foobar", other="barfoo")

        This function uses a fallback for attribute searching. It will by default use
        the namespace variant but fall back to the non-namespace variant.
        Thus specifiying :code:`{"name": "foobar"}` will match on :code:`<bla name="foobar" \>`
        as well as on :code:`<bla android:name="foobar" \>`.

        :param lxml.etree.Element tag: specify the tag element
        :param attribute_filter: specify the attribute filter as dictionary
        """
        if len(attribute_filter) <= 0:
            return True
        for attr, value in attribute_filter.items():
            _value = self.get_value_from_tag(tag, attr)
            if _value != value:
                return False
        return True

    def get_main_activities(self) -> set[str]:
        """
        Return names of the main activities

        These values are read from the AndroidManifest.xml

        :rtype: a set of str
        """
        x = set()
        y = set()

        for i in self.xml:
            if self.xml[i] is None:
                continue
            activities_and_aliases = self.xml[i].findall(".//activity") + \
                                     self.xml[i].findall(".//activity-alias")

            for item in activities_and_aliases:
                # Some applications have more than one MAIN activity.
                # For example: paid and free content
                activityEnabled = item.get(self._ns("enabled"))
                if activityEnabled == "false":
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.action.MAIN":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            x.add(item.get(self._ns("name")))
                        else:
                            logger.warning('Main activity without name')

                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            y.add(item.get(self._ns("name")))
                        else:
                            logger.warning('Launcher activity without name')

        return x.intersection(y)

    def get_main_activity(self) -> Union[str,None]:
        """
        Return the name of the main activity

        This value is read from the AndroidManifest.xml

        :rtype: str
        """
        activities = self.get_main_activities()
        if len(activities) == 1:
            return self._format_value(activities.pop())
        elif len(activities) > 1:
            main_activities = {self._format_value(ma) for ma in activities}
            # sorted is necessary
            # 9fc7d3e8225f6b377f9181a92c551814317b77e1aa0df4c6d508d24b18f0f633
            good_main_activities = sorted(
                main_activities.intersection(self.get_activities()))
            if good_main_activities:
                return good_main_activities[0]
            return sorted(main_activities)[0]
        return None

    def get_activities(self) -> list[str]:
        """
        Return the android:name attribute of all activities

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("activity", "name"))

    def get_activity_aliases(self) -> list[dict[str,str]]:
        """
        Return the android:name and android:targetActivity attribute of all activity aliases.

        :rtype: a list of dict
        """
        ali = []
        for alias in self.find_tags('activity-alias'):
            activity_alias = {}
            for attribute in ['name', 'targetActivity']:
                value = (alias.get(attribute) or
                         alias.get(self._ns(attribute)))
                if not value:
                    continue
                activity_alias[attribute] = self._format_value(value)
            if activity_alias:
                ali.append(activity_alias)
        return ali

    def get_services(self) -> list[str]:
        """
        Return the android:name attribute of all services

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("service", "name"))

    def get_receivers(self) -> list[str]:
        """
        Return the android:name attribute of all receivers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("receiver", "name"))

    def get_providers(self) -> list[str]:
        """
        Return the android:name attribute of all providers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("provider", "name"))

    def get_res_value(self, name:str) -> str:
        """
        Return the literal value with a resource id
        :rtype: str
        """

        res_parser = self.get_android_resources()
        if not res_parser:
            return name

        res_id = res_parser.parse_id(name)[0]
        try:
            value = res_parser.get_resolved_res_configs(
                res_id,
                ARSCResTableConfig.default_config())[0][1]
        except Exception as e:
            logger.warning("Exception get resolved resource id: %s" % e)
            return name

        return value

    def get_intent_filters(self, itemtype:str, name:str) -> dict[str,list[str]]:
        """
        Find intent filters for a given item and name.

        Intent filter are attached to activities, services or receivers.
        You can search for the intent filters of such items and get a dictionary of all
        attached actions and intent categories.

        :param itemtype: the type of parent item to look for, e.g. `activity`,  `service` or `receiver`
        :param name: the `android:name` of the parent item, e.g. activity name
        :returns: a dictionary with the keys `action` and `category` containing the `android:name` of those items
        """
        attributes = {"action": ["name"], "category": ["name"], "data": ['scheme', 'host', 'port', 'path', 'pathPattern', 'pathPrefix', 'mimeType']}

        
    def get_permissions(self) -> list[str]:
        """
        Return permissions names declared in the AndroidManifest.xml.

        It is possible that permissions are returned multiple times,
        as this function does not filter the permissions, i.e. it shows you
        exactly what was defined in the AndroidManifest.xml.

        Implied permissions, which are granted automatically, are not returned
        here. Use :meth:`get_uses_implied_permission_list` if you need a list
        of implied permissions.

        :returns: A list of permissions
        :rtype: list
        """
        return self.permissions

    def get_uses_implied_permission_list(self) -> list[str]:
        """
            Return all permissions implied by the target SDK or other permissions.

            :rtype: list of string
        """
        target_sdk_version = self.get_effective_target_sdk_version()

        READ_CALL_LOG = 'android.permission.READ_CALL_LOG'
        READ_CONTACTS = 'android.permission.READ_CONTACTS'
        READ_EXTERNAL_STORAGE = 'android.permission.READ_EXTERNAL_STORAGE'
        READ_PHONE_STATE = 'android.permission.READ_PHONE_STATE'
        WRITE_CALL_LOG = 'android.permission.WRITE_CALL_LOG'
        WRITE_CONTACTS = 'android.permission.WRITE_CONTACTS'
        WRITE_EXTERNAL_STORAGE = 'android.permission.WRITE_EXTERNAL_STORAGE'

        implied = []

        implied_WRITE_EXTERNAL_STORAGE = False
        if target_sdk_version < 4:
            if WRITE_EXTERNAL_STORAGE not in self.permissions:
                implied.append([WRITE_EXTERNAL_STORAGE, None])
                implied_WRITE_EXTERNAL_STORAGE = True
            if READ_PHONE_STATE not in self.permissions:
                implied.append([READ_PHONE_STATE, None])

        if (WRITE_EXTERNAL_STORAGE in self.permissions or implied_WRITE_EXTERNAL_STORAGE) \
            and READ_EXTERNAL_STORAGE not in self.permissions:
            maxSdkVersion = None
            for name, version in self.uses_permissions:
                if name == WRITE_EXTERNAL_STORAGE:
                    maxSdkVersion = version
                    break
            implied.append([READ_EXTERNAL_STORAGE, maxSdkVersion])

        if target_sdk_version < 16:
            if READ_CONTACTS in self.permissions \
                and READ_CALL_LOG not in self.permissions:
                implied.append([READ_CALL_LOG, None])
            if WRITE_CONTACTS in self.permissions \
                and WRITE_CALL_LOG not in self.permissions:
                implied.append([WRITE_CALL_LOG, None])

        return implied

    def _update_permission_protection_level(self, protection_level, sdk_version):
        if not sdk_version or int(sdk_version) <= 15:
            return protection_level.replace('Or', '|').lower()
        return protection_level

    def _fill_deprecated_permissions(self, permissions):
        min_sdk = self.get_min_sdk_version()
        target_sdk = self.get_target_sdk_version()
        filled_permissions = permissions.copy()
        for permission in filled_permissions:
            protection_level, label, description = filled_permissions[permission]
            if ((not label or not description)
                and permission in self.permission_module_min_sdk):
                x = self.permission_module_min_sdk[permission]
                protection_level = self._update_permission_protection_level(
                    x['protectionLevel'], min_sdk)
                filled_permissions[permission] = [
                    protection_level, x['label'], x['description']]
            else:
                filled_permissions[permission] = [
                    self._update_permission_protection_level(
                            protection_level, target_sdk),
                    label, description]
        return filled_permissions

    def get_details_permissions(self) -> dict[str, list[str]]:
        """
        Return permissions with details.

        THis can only return details about the permission, if the permission is
        defined in the AOSP.

        :rtype: dict of {permission: [protectionLevel, label, description]}
        """
        l = {}

        for i in self.permissions:
            if i in self.permission_module:
                x = self.permission_module[i]
                l[i] = [x["protectionLevel"], x["label"], x["description"]]
            elif i in self.declared_permissions:
                protectionLevel_hex = self.declared_permissions[i]["protectionLevel"]
                protectionLevel = protection_flags_to_attributes[protectionLevel_hex]
                l[i] = [protectionLevel, "Unknown permission from android reference",
                        "Unknown permission from android reference"]
            else:
                # Is there a valid case not belonging to the above two?
                logger.info(f"Unknown permission {i}")
        return self._fill_deprecated_permissions(l)

    def get_requested_aosp_permissions(self) -> list[str]:
        """
        Returns requested permissions declared within AOSP project.

        This includes several other permissions as well, which are in the platform apps.

        :rtype: list of str
        """
        aosp_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm in list(self.permission_module.keys()):
                aosp_permissions.append(perm)
        return aosp_permissions

    def get_requested_aosp_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns requested aosp permissions with details.

        :rtype: dictionary
        """
        l = {}
        for i in self.permissions:
            try:
                l[i] = self.permission_module[i]
            except KeyError:
                # if we have not found permission do nothing
                continue
        return l

    def get_requested_third_party_permissions(self) -> list[str]:
        """
        Returns list of requested permissions not declared within AOSP project.

        :rtype: list of strings
        """
        third_party_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm not in list(self.permission_module.keys()):
                third_party_permissions.append(perm)
        return third_party_permissions

    def get_declared_permissions(self) -> list[str]:
        """
        Returns list of the declared permissions.

        :rtype: list of strings
        """
        return list(self.declared_permissions.keys())

    def get_declared_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns declared permissions with the details.

        :rtype: dict
        """
        return self.declared_permissions

    def get_max_sdk_version(self) -> str:
        """
            Return the android:maxSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "maxSdkVersion")

    def get_min_sdk_version(self) -> str:
        """
            Return the android:minSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "minSdkVersion")

    def get_target_sdk_version(self) -> str:
        """
            Return the android:targetSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "targetSdkVersion")

    def get_effective_target_sdk_version(self) -> int:
        """
            Return the effective targetSdkVersion, always returns int > 0.

            If the targetSdkVersion is not set, it defaults to 1.  This is
            set based on defaults as defined in:
            https://developer.android.com/guide/topics/manifest/uses-sdk-element.html

            :rtype: int
        """
        target_sdk_version = self.get_target_sdk_version()
        if not target_sdk_version:
            target_sdk_version = self.get_min_sdk_version()
        try:
            return int(target_sdk_version)
        except (ValueError, TypeError):
            return 1





    

    
