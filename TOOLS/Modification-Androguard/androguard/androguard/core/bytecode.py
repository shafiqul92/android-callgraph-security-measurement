# Allows type hinting of types not-yet-declared
# in Python >= 3.7
# see https://peps.python.org/pep-0563/
from __future__ import annotations

import hashlib
import json
from struct import pack
import textwrap
from typing import TYPE_CHECKING, Union


from androguard.core.androconf import CONF, color_range
from androguard.core.dex.dex_types import Kind, Operand
if TYPE_CHECKING:
    from androguard.core.analysis import DEXBasicBlock, MethodAnalysis
    from androguard.core.dex import DEX

from loguru import logger
from xml.sax.saxutils import escape





def vm2json(vm:DEX) -> str:
    """
    Get a JSON representation of a DEX file

    :param vm: :class:`~androguard.core.dex.DEX`
    :return: str
    """
    d = {"name": "root", "children": []}

    for _class in vm.get_classes():
        c_class = {"name": _class.get_name(), "children": []}

        for method in _class.get_methods():
            c_method = {"name": method.get_name(), "children": []}

            c_class["children"].append(c_method)

        d["children"].append(c_class)

    return json.dumps(d)


class TmpBlock:
    def __init__(self, name:str) -> None:
        self.name = name

    def get_name(self) -> str:
        return self.name


def method2json(mx: MethodAnalysis, directed_graph:bool=False) -> str:
    """
    Create directed or undirected graph in the json format.

    :param mx: :class:`~androguard.core.analysis.analysis.MethodAnalysis`
    :param directed_graph: True if a directed graph should be created (default: False)
    :return: str
    """
    if directed_graph:
        return method2json_direct(mx)
    return method2json_undirect(mx)


def method2json_undirect(mx: MethodAnalysis) -> str:
    """

    :param mx: :class:`~androguard.core.analysis.analysis.MethodAnalysis`
    :return: str
    """
    d = {}
    reports = []
    d["reports"] = reports

    for DVMBasicMethodBlock in mx.basic_blocks.gets():
        cblock = {"BasicBlockId": DVMBasicMethodBlock.get_name(),
                  "registers": mx.get_method().get_code().get_registers_size(), "instructions": []}

        ins_idx = DVMBasicMethodBlock.start
        for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():
            c_ins = {"idx": ins_idx, "name": DVMBasicMethodBlockInstruction.get_name(),
                     "operands": DVMBasicMethodBlockInstruction.get_operands(
                         ins_idx)}

            cblock["instructions"].append(c_ins)
            ins_idx += DVMBasicMethodBlockInstruction.get_length()

        cblock["Edge"] = []
        for DVMBasicMethodBlockChild in DVMBasicMethodBlock.childs:
            cblock["Edge"].append(DVMBasicMethodBlockChild[-1].get_name())

        reports.append(cblock)

    return json.dumps(d)


def method2json_direct(mx: MethodAnalysis) -> str:
    """

    :param mx: :class:`~androguard.core.analysis.analysis.MethodAnalysis`
    :return:
    """
    d = {}
    reports = []
    d["reports"] = reports

    hooks = {}

    l = []
    for DVMBasicMethodBlock in mx.basic_blocks.gets():
        for index, DVMBasicMethodBlockChild in enumerate(DVMBasicMethodBlock.childs):
            if DVMBasicMethodBlock.get_name() == DVMBasicMethodBlockChild[-1].get_name():

                preblock = TmpBlock(DVMBasicMethodBlock.get_name() + "-pre")

                cnblock = {"BasicBlockId": DVMBasicMethodBlock.get_name() + "-pre",
                           "start": DVMBasicMethodBlock.start,
                           "notes": [],
                           "Edge": [DVMBasicMethodBlock.get_name()],
                           "registers": 0,
                           "instructions": [],
                           "info_bb": 0}

                l.append(cnblock)

                for parent in DVMBasicMethodBlock.fathers:
                    hooks[parent[-1].get_name()] = []
                    hooks[parent[-1].get_name()].append(preblock)

                    for idx, child in enumerate(parent[-1].childs):
                        if child[-1].get_name() == DVMBasicMethodBlock.get_name(
                        ):
                            hooks[parent[-1].get_name()].append(child[-1])

    for DVMBasicMethodBlock in mx.basic_blocks.gets():
        cblock = {"BasicBlockId": DVMBasicMethodBlock.get_name(),
                  "start": DVMBasicMethodBlock.start,
                  "notes": DVMBasicMethodBlock.get_notes(),
                  "registers": mx.get_method().get_code().get_registers_size(),
                  "instructions": []}

        ins_idx = DVMBasicMethodBlock.start
        last_instru = None
        for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():
            c_ins = {"idx": ins_idx,
                     "name": DVMBasicMethodBlockInstruction.get_name(),
                     "operands": DVMBasicMethodBlockInstruction.get_operands(ins_idx),
                     }

            cblock["instructions"].append(c_ins)

            if (DVMBasicMethodBlockInstruction.get_op_value() == 0x2b or
                    DVMBasicMethodBlockInstruction.get_op_value() == 0x2c):
                values = DVMBasicMethodBlock.get_special_ins(ins_idx)
                cblock["info_next"] = values.get_values()

            ins_idx += DVMBasicMethodBlockInstruction.get_length()
            last_instru = DVMBasicMethodBlockInstruction

        cblock["info_bb"] = 0
        if DVMBasicMethodBlock.childs:
            if len(DVMBasicMethodBlock.childs) > 1:
                cblock["info_bb"] = 1

            if (last_instru.get_op_value() == 0x2b or
                    last_instru.get_op_value() == 0x2c):
                cblock["info_bb"] = 2

        cblock["Edge"] = []
        for DVMBasicMethodBlockChild in DVMBasicMethodBlock.childs:
            ok = False
            if DVMBasicMethodBlock.get_name() in hooks:
                if DVMBasicMethodBlockChild[-1] in hooks[DVMBasicMethodBlock.get_name()]:
                    ok = True
                    cblock["Edge"].append(hooks[DVMBasicMethodBlock.get_name()][0].get_name())

            if not ok:
                cblock["Edge"].append(DVMBasicMethodBlockChild[-1].get_name())

        exception_analysis = DVMBasicMethodBlock.get_exception_analysis()
        if exception_analysis:
            cblock["Exceptions"] = exception_analysis.get()

        reports.append(cblock)

    reports.extend(l)

    return json.dumps(d)


def object_to_bytes(obj:Union[str,bool,int,bytearray]) -> bytearray:
    """
    Convert a object to a bytearray or call get_raw() of the object
    if no useful type was found.
    """
    if isinstance(obj, str):
        return bytearray(obj, "UTF-8")
    if isinstance(obj, bool):
        return bytearray()
    if isinstance(obj, int):
        return pack("<L", obj)
    if obj is None:
        return bytearray()
    if isinstance(obj, bytearray):
        return obj

    return obj.get_raw()


def FormatClassToJava(i:str) -> str:
    """
    Transform a java class name into the typed variant found in DEX files.

    example::

        >>> FormatClassToJava('java.lang.Object')
        'Ljava/lang/Object;'

    :param i: the input class name
    :rtype: str
    """
    return "L" + i.replace(".", "/") + ";"


def FormatClassToPython(i:str) -> str:
    """
    Transform a typed class name into a form which can be used as a python
    attribute

    example::

        >>> FormatClassToPython('Lfoo/bar/foo/Barfoo$InnerClass;')
        'Lfoo_bar_foo_Barfoo_InnerClass'

    :param i: classname to transform
    :rtype: str
    """
    i = i[:-1]
    i = i.replace("/", "_")
    i = i.replace("$", "_")

    return i


def get_package_class_name(name:str)->tuple[str, str]:
    """
    Return package and class name in a java variant from a typed variant name.

    If no package could be found, the package is an empty string.

    If the name is an array type, the array is discarded.

    example::

        >>> get_package_class_name('Ljava/lang/Object;')
        ('java.lang', 'Object')
        >>> get_package_class_name('[[Ljava/lang/Object;')
        ('java.lang', 'Object')
        >>> get_package_class_name('LSomeClass;')
        ('', 'SomeClass')

    :param name: the name
    :rtype: tuple
    :return:
    """
    # name is MUTF8, so make sure we get the string variant
    name = str(name)
    if name[-1] != ';':
        raise ValueError("The name '{}' does not look like a typed name!".format(name))

    # discard array types, there might be many...
    name = name.lstrip('[')

    if name[0] != 'L':
        raise ValueError("The name '{}' does not look like a typed name!".format(name))

    name = name[1:-1]
    if '/' not in name:
        return '', name

    package, clsname = name.rsplit('/', 1)
    package = package.replace('/', '.')

    return package, clsname


def FormatNameToPython(i:str) -> str:
    """
    Transform a (method) name into a form which can be used as a python
    attribute

    example::

        >>> FormatNameToPython('<clinit>')
        'clinit'

    :param i: name to transform
    :rtype: str
    """

    i = i.replace("<", "")
    i = i.replace(">", "")
    i = i.replace("$", "_")

    return i


def FormatDescriptorToPython(i:str) -> str:
    """
    Format a descriptor into a form which can be used as a python attribute

    example::

        >>> FormatDescriptorToPython('(Ljava/lang/Long; Ljava/lang/Long; Z Z)V')
        'Ljava_lang_LongLjava_lang_LongZZV

    :param i: name to transform
    :rtype: str
    """

    i = i.replace("/", "_")
    i = i.replace(";", "")
    i = i.replace("[", "")
    i = i.replace("(", "")
    i = i.replace(")", "")
    i = i.replace(" ", "")
    i = i.replace("$", "")

    return i


class Node:
    def __init__(self, n, s):
        self.id = n
        self.title = s
        self.children = []
