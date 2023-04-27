#!/usr/bin/env python

import argparse
import os
import webbrowser
from distutils.spawn import find_executable
from os.path import dirname
from threading import Timer

from flask import Flask

from puncover_riscv import renderers
from puncover_riscv.builders import ElfBuilder
from puncover_riscv.collector import Collector
from puncover_riscv.gcc_tools import GCCTools
from puncover_riscv.middleware import BuilderMiddleware
from puncover_riscv.version import __version__


def is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


def create_builder(gcc_base_filename, elf_file=None, map_file=None, su_dir=None, src_root=None):
    c = Collector(GCCTools(gcc_base_filename))
    if elf_file:
        return ElfBuilder(c, src_root, elf_file, map_file, su_dir)
    else:
        raise Exception("Unable to configure builder for collector")


app = Flask(__name__)


def find_riscv_tools_location():
    obj_dump = find_executable("riscv64-unknown-elf-objdump")
    return dirname(dirname(obj_dump)) if obj_dump else None


def open_browser(host, port):
    webbrowser.open_new("http://{}:{}/".format(host, port))


def main():
    gcc_tools_base = os.path.join(
        find_riscv_tools_location(), 'bin/riscv64-unknown-elf-')

    parser = argparse.ArgumentParser(
        description="Analyses RISCV C/C++ build output for code size, static variables, and stack usage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--gcc-tools-base', '--gcc_tools_base', default=gcc_tools_base,
                        help='filename prefix for your gcc tools, e.g. /usr/bin/toolchain_gcc_t-head_linux/bin/riscv64-unknown-elf-')
    parser.add_argument('--elf_file', '--elf-file', required=True,
                        help='location of an ELF file')
    parser.add_argument('--map_file', '--map_file', required=True,
                        help='location of an MAP file')
    parser.add_argument('--src_root', '--src-root',
                        help='location of your sources')
    parser.add_argument('--build_dir', '--build-dir',
                        help='location of your build output')
    parser.add_argument('--debug', action='store_true',
                        help='enable Flask debugger')
    parser.add_argument('--port', dest='port', default=5000, type=int,
                        help='port the HTTP server runs on')
    parser.add_argument('--host', default='127.0.0.1',
                        help='host IP the HTTP server runs on')
    parser.add_argument('--no-open-browser', action='store_true',
                        help="don't automatically open a browser window")
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + __version__)
    args = parser.parse_args()

    # if is_port_in_use(args.port):
    #     print("Port {} is already in use, please choose a different port.".format(args.port))
    #     exit(1)

    builder = create_builder(args.gcc_tools_base, elf_file=args.elf_file, map_file=args.map_file,
                             src_root=args.src_root, su_dir=args.build_dir)
    builder.build_if_needed()
    renderers.register_jinja_filters(app.jinja_env)
    renderers.register_urls(app, builder.collector)
    app.wsgi_app = BuilderMiddleware(app.wsgi_app, builder)

    if args.debug:
        app.debug = True

    # Open a browser window, only if this is the first instance of the server
    # from https://stackoverflow.com/a/63216793
    if not args.no_open_browser and not os.environ.get("WERKZEUG_RUN_MAIN"):
        # wait one second before starting, so the flask server is ready and we
        # don't see a 404 for a moment first
        Timer(1, open_browser, kwargs={
              "host": args.host, "port": args.port}).start()

    app.run(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
