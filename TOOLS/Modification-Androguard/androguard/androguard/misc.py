# Allows type hinting of types not-yet-declared
# in Python >= 3.7
# see https://peps.python.org/pep-0563/
from __future__ import annotations
import hashlib
import os
import re
from typing import Union

from loguru import logger

from androguard.session import Session
from androguard.decompiler import decompiler
from androguard.core import androconf
from androguard.core import apk, dex
from androguard.core.analysis.analysis import Analysis


def AnalyzeAPK(_file: Union[str,bytes], session:Union[Session,None]=None, raw:bool=False) -> tuple[apk.APK, list[dex.DEX], Analysis]:
    """
    Analyze an android application and setup all stuff for a more quickly
    analysis!
    If session is None, no session is used at all. This is the default
    behaviour.
    If you like to continue your work later, it might be a good idea to use a
    session.
    A default session can be created by using :meth:`~get_default_session`.

    :param _file: the filename of the android application or a buffer which represents the application
    :type _file: string (for filename) or bytes (for raw)
    :param session: A session (default: None)
    :param raw: boolean if raw bytes are supplied instead of a filename
    :rtype: return the :class:`~androguard.core.apk.APK`, list of :class:`~androguard.core.dex.DEX`, and :class:`~androguard.core.analysis.analysis.Analysis` objects
    """
    logger.debug("AnalyzeAPK")

    if session:
        logger.debug("Using existing session {}".format(session))
        if raw:
            data = _file
            filename = hashlib.md5(_file).hexdigest()
        else:
            with open(_file, "rb") as fd:
                data = fd.read()
                filename = _file

        digest = session.add(filename, data)
        return session.get_objects_apk(filename, digest)
    else:
        logger.debug("Analysing without session")
        a = apk.APK(_file, raw=raw)
        # FIXME: probably it is not necessary to keep all DEXs, as
        # they are already part of Analysis. But when using sessions, it works
        # this way...
        d = []
        dx = Analysis()
        for dex_bytes in a.get_all_dex():
            df = dex.DEX(dex_bytes, using_api=a.get_target_sdk_version())
            dx.add(df)
            d.append(df)
            df.set_decompiler(decompiler.DecompilerDAD(df, dx))

        dx.create_xref()

        return a, d, dx






