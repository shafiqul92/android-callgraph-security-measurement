#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Androguard is a full Python tool to reverse Android Applications."""
import sys

import click
from loguru import logger

import androguard
from androguard import util
import networkx as nx

@click.group(help=__doc__)
@click.version_option(version=androguard.__version__)
@click.option("--verbose", "--debug", 'verbosity', flag_value='verbose', help="Print more")
def entry_point(verbosity):
    if verbosity is None:
        util.set_log("ERROR")
    else:
        util.set_log("INFO")
    logger.add("androguard.log", retention="10 days")


# callgraph exporting utility functions
def _write_gml(G, path):
    """Wrapper around nx.write_gml"""
    return nx.write_gml(G, path, stringizer=str)

def _write_gpickle(G, path):
    """Wrapper around pickle dump"""
    import pickle
    with open(path, 'wb') as f:
        pickle.dump(G, f, pickle.HIGHEST_PROTOCOL)

def _write_yaml(G, path):
    """Wrapper around yaml dump"""
    import yaml
    with open(path, 'w') as f:
        yaml.dump(G, f)

_PRIMITIVE_TYPES = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
}

def _decode_type(descriptor: str) -> str:
    # Remove spaces that Androguard sometimes adds
    descriptor = descriptor.replace(' ', '').strip()
    
    array_dim = 0
    i = 0
    while i < len(descriptor) and descriptor[i] == '[':
        array_dim += 1
        i += 1

    base_desc = descriptor[i:]
    if not base_desc:
        type_name = 'void'
    elif base_desc in _PRIMITIVE_TYPES:
        type_name = _PRIMITIVE_TYPES[base_desc]
    elif base_desc.startswith('L') and base_desc.endswith(';'):
        type_name = base_desc[1:-1].replace('/', '.')
    else:
        type_name = base_desc

    if array_dim:
        type_name += '[]' * array_dim

    return type_name

def _decode_parameters(parameters: str) -> list[str]:
    # Remove all spaces from descriptor (Androguard sometimes adds spaces)
    parameters = parameters.replace(' ', '')
    
    params = []
    i = 0
    while i < len(parameters):
        array_dim = 0
        while i < len(parameters) and parameters[i] == '[':
            array_dim += 1
            i += 1

        if i >= len(parameters):
            break

        if parameters[i] in _PRIMITIVE_TYPES:
            type_name = _PRIMITIVE_TYPES[parameters[i]]
            i += 1
        elif parameters[i] == 'L':
            end = parameters.index(';', i)
            type_name = parameters[i + 1:end].replace('/', '.')
            i = end + 1
        else:
            raise ValueError(f"Unknown descriptor sequence: {parameters[i:]}")

        if array_dim:
            type_name += '[]' * array_dim

        params.append(type_name)

    return params

def _descriptor_to_signature(descriptor: str) -> tuple[list[str], str]:
    if not descriptor or descriptor[0] != '(':
        raise ValueError(f"Invalid method descriptor: {descriptor}")

    params_desc, return_desc = descriptor[1:].split(')', 1)
    params = _decode_parameters(params_desc)
    return_type = _decode_type(return_desc)
    return params, return_type

def _method_sort_key(method) -> tuple[str, str, str]:
    return (
        method.get_class_name(),
        method.get_name(),
        method.get_descriptor(),
    )

def _format_method_signature(method) -> str:
    class_name = method.get_class_name().lstrip('L').rstrip(';').replace('/', '.')
    method_name = method.get_name()
    params, return_type = _descriptor_to_signature(method.get_descriptor())
    joined_params = ', '.join(params)
    return f"<{class_name}: {return_type} {method_name}({joined_params})>"

def _write_plaintext(G, path):
    with open(path, 'w', encoding='utf-8') as f:
        for source, target in sorted(G.edges(), key=lambda edge: (
            _method_sort_key(edge[0]),
            _method_sort_key(edge[1])
        )):
            f.write(f"{_format_method_signature(source)} ==> {_format_method_signature(target)}\n")

# mapping of types to their respective exporting functions
write_methods = dict(
    gml=_write_gml,
    gexf=nx.write_gexf,
    # gpickle=_write_gpickle,   # Pickling can't be done due to BufferedReader attributes (e.g. EncodedMethod.buff) not being serializable
    graphml=nx.write_graphml,
    # yaml=_write_yaml,         # Same limitation as gpickle
    net=nx.write_pajek,
    txt=_write_plaintext)

@entry_point.command()
@click.argument(
    'file_',
    type=click.Path(exists=True, dir_okay=False, file_okay=True),
    required=True,
)
@click.option(
    '--output', '-o',
    default='callgraph.gml',
    help='Filename of the output graph file',
)
@click.option(
    '--output-type',
    type=click.Choice(
        list(write_methods.keys()),
        case_sensitive=False),
    default='gml',
    help='Type of the graph to output '
)
@click.option(
    '--show', '-s',
    default=False,
    is_flag=True,
    help='instead of saving the graph file, render it with matplotlib',
)
@click.option(
    '--classname',
    default='.*',
    help='Regex to filter by classname',
)
@click.option(
    '--methodname',
    default='.*',
    help='Regex to filter by methodname',
)
@click.option(
    '--descriptor',
    default='.*',
    help='Regex to filter by descriptor',
)
@click.option(
    '--accessflag',
    default='.*',
    help='Regex to filter by accessflag',
)
@click.option(
    '--no-isolated',
    default=False,
    is_flag=True,
    help='Do not store methods which has no xrefs',
)
def cg(
    file_,
    output,
    output_type,
    show,
    classname,
    methodname,
    descriptor,
    accessflag,
    no_isolated):
    """
    Create a call graph based on the data of Analysis and export it into a graph format.
    """
    from androguard.core.bytecode import FormatClassToJava
    from androguard.misc import AnalyzeAPK
    from androguard.core.analysis.analysis import ExternalMethod

    import matplotlib.pyplot as plt

    a, d, dx = AnalyzeAPK(file_)

    entry_points = map(FormatClassToJava,
                       a.get_activities() + a.get_providers() +
                       a.get_services() + a.get_receivers())
    entry_points = list(entry_points)

    callgraph = dx.get_call_graph(
        classname,
        methodname,
        descriptor,
        accessflag,
        no_isolated,
        entry_points
    )

    if show:
        try:
            import PyQt5
        except ImportError:
            print("PyQt5 is not installed. In most OS you can install it by running 'pip install PyQt5'.\n")
            exit()
        pos = nx.spring_layout(callgraph)
        internal = []
        external = []

        for n in callgraph:
            if isinstance(n, ExternalMethod):
                external.append(n)
            else:
                internal.append(n)

        nx.draw_networkx_nodes(
            callgraph,
            pos=pos, node_color='r',
            nodelist=internal)

        nx.draw_networkx_nodes(
            callgraph,
            pos=pos,
            node_color='b',
            nodelist=external)

        nx.draw_networkx_edges(
            callgraph,
            pos,
            width=0.5,
            arrows=True)

        nx.draw_networkx_labels(callgraph,
                                pos=pos,
                                font_size=6,
                                labels={n: f"{n.get_class_name()} {n.name} {n.descriptor}"
                                        for n in callgraph.nodes})

        plt.draw()
        plt.show()

    else:
        output_type_lower = output_type.lower()
        if output_type_lower not in write_methods:
            print(f"Could not find a method to export files to {output_type_lower}!")
            sys.exit(1)

        write_methods[output_type_lower](callgraph, output)


if __name__ == '__main__':
    entry_point()
