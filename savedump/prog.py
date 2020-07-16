#
# Copyright 2020 Delphix
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
Utility to package crash dumps and core dumps together with
their symbol tables and debug info.
"""

import argparse
import distutils
from distutils import dir_util  # pylint: disable=unused-import
from enum import Enum
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple

import kdumpfile


def shell_cmd(cmd_and_args: List[str]) -> Tuple[bool, str]:
    """
    Executes shell command `cmd`. Returns:
        - (True, <string with command output>) on success.
        - (False, <error string>) on error.
    """
    cmd = cmd_and_args[0]
    if not shutil.which(cmd):
        return False, f"could not find program: {cmd}"

    proc = subprocess.Popen(cmd_and_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    retcode = proc.wait()
    if retcode != 0:
        return False, f"{cmd} exited with code: {retcode} - msg: {str(err)}"
    if err:
        print(f"{cmd} stderr start ---")
        print(f"{str(err, 'utf-8')}")
        print(f"{cmd} stderr end   ---")
    return True, str(out, 'utf-8')


def copy_from_root(src: str, dest: str) -> None:
    """
    In shell terms:
       $ mkdir $dest/sbin
       $ cp sbin/ztest $dest/sbin/ztest
    """
    src_dir = os.path.dirname(src)
    pathlib.Path(f"{dest}/{src_dir}").mkdir(parents=True, exist_ok=True)
    shutil.copy(src, f"{dest}/{src_dir}")


def multi_copy_from_root(files: List[str], dest: str) -> None:
    """
    Like copy from root but accepts multiple sources that will
    copy from their root into a single destination.
    """
    for src in files:
        copy_from_root(src, dest)


def compress_archive(archive_dir: str) -> Optional[str]:
    """
    Returns None for success and error message in string
    form for failure.
    """
    print("compressing archive...", end="")
    compressed_archive = f"{archive_dir}.tar.gz"
    success, msg = shell_cmd(
        ["tar", "-czf", compressed_archive, f"{archive_dir}"])
    if not success:
        return msg
    print("done")
    print(f"archive created: {compressed_archive}")
    return None


class DumpType(Enum):
    """
    Accepted dump formats.
    """
    CRASHDUMP = 'Kdump compressed dump'
    UCOREDUMP = 'core file'


def get_dump_type(path: str) -> Optional[DumpType]:
    """
    Examines the dump file specified by `path` and returns
    its type as DumpType.
    """
    success, output = shell_cmd(['file', path])
    if not success:
        sys.exit(output)

    for dump_type in DumpType:
        if dump_type.value in output:
            return dump_type
    return None


def archive_kernel_dump(path: str) -> None:
    """
    Packages the dump together with its vmlinux and modules in a
    gzipped archive in the working directory.
    """
    kdump_info = kdumpfile.kdumpfile(path)
    dumpname = os.path.basename(path)
    nodename = kdump_info.attr['linux.uts.nodename']
    osrelease = kdump_info.attr['linux.uts.release']

    vmlinux_path = f"/usr/lib/debug/boot/vmlinux-{osrelease}"
    if not os.path.exists(vmlinux_path):
        sys.exit(f"error: cannot find vmlinux at: {vmlinux_path}")
    print(f"vmlinux found: {vmlinux_path}")

    extra_mod_path = f"/usr/lib/debug/lib/modules/{osrelease}/extra"
    if not os.path.exists(extra_mod_path):
        sys.exit(f"error: cannot find extra mod path: {extra_mod_path}")
    print(f"using module path: {extra_mod_path}")

    archive_dir = f"{nodename}.archive-{dumpname}"
    pathlib.Path(archive_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy(path, archive_dir)
    shutil.copy(vmlinux_path, archive_dir)

    archive_extra_mod_path = f"{archive_dir}{extra_mod_path}"
    distutils.dir_util.copy_tree(extra_mod_path, archive_extra_mod_path)

    msg = compress_archive(archive_dir)
    shutil.rmtree(archive_dir)
    if msg:
        sys.exit(f"error: {msg}")


RUN_GDB_CONTENTS = """#!/bin/bash

script_path=$(readlink -f "$0")
script_dir=$(dirname "$script_path")

#
# Option explanations:
# "set print thread-events off"
#    Supress thread creation/exit messages.
#
# "set sysroot $script_dir"
#    Set the script's directory as system root. This is
#    needed to make GDB look at the correct symbols (e.g
#    the ones in the archive, not the ones from the
#    system).
#
# "set debug-file-directory $script_dir/usr/lib/debug"
#    Similarly to sysroot, point GDB to the right
#    debug info links.
#
gdb -iex "set print thread-events off" \\
    -iex "set sysroot $script_dir" \\
    -iex "set debug-file-directory $script_dir/usr/lib/debug" \\
    -iex "file $script_dir/{0}" \\
    -iex "core-file $script_dir/{1}"
"""


def get_libraries_through_gdb(bin_path: str,
                              dump_path: str) -> Optional[List[str]]:
    """
    Use GDB to examine the core's memory-mappings and return a list
    with all the paths of the shared object libraries loaded in its
    address space.
    """
    success, output = shell_cmd([
        'gdb', '--batch', '--nx', '--eval-command=info sharedlibrary', '-c',
        dump_path, bin_path
    ])
    if not success:
        print(output, file=sys.stderr)
        return None

    #
    # pylint: disable=line-too-long
    #
    # Example output of the above command:
    # ```
    #     [New LWP 19109]
    #     [Thread debugging using libthread_db enabled]
    #     Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    #     Core was generated by `ztest\'.
    #     #0  0x00007f2947ddf204 in __waitpid (pid=19122, stat_loc=0x7ffdb3ca4690, options=0) at ../sysdeps/unix/sysv/linux/waitpid.c:30
    #     From                To                  Syms Read   Shared Object Library
    #     0x00007f29489ba180  0x00007f29489c4cea  Yes         /lib/libnvpair.so.1
    #     0x00007f29483c6b00  0x00007f294857333f  Yes         /lib/libzpool.so.2
    #     0x00007f2947ff7a80  0x00007f29480b62f5  Yes         /lib/x86_64-linux-gnu/libm.so.6
    #     0x00007f2947dd2bb0  0x00007f2947de10f1  Yes         /lib/x86_64-linux-gnu/libpthread.so.0
    #     0x00007f29479fd2d0  0x00007f2947b75c3c  Yes         /lib/x86_64-linux-gnu/libc.so.6
    #     0x00007f29477d6200  0x00007f29477d970c  Yes         /lib/x86_64-linux-gnu/librt.so.1
    #     0x00007f2947590830  0x00007f29475bf1de  Yes         /lib/x86_64-linux-gnu/libblkid.so.1
    #     0x00007f2947383e50  0x00007f2947384bde  Yes         /lib/x86_64-linux-gnu/libdl.so.2
    #     0x00007f29471688c0  0x00007f294717aa83  Yes (*)     /lib/x86_64-linux-gnu/libudev.so.1
    #     0x00007f2946f5f640  0x00007f2946f62f19  Yes         /lib/x86_64-linux-gnu/libuuid.so.1
    #     0x00007f2946d42f90  0x00007f2946d56640  Yes (*)     /lib/x86_64-linux-gnu/libz.so.1
    #     0x00007f2948bccf10  0x00007f2948bebb20  Yes         /lib64/ld-linux-x86-64.so.2
    #     (*): Shared library is missing debugging information.
    # ```
    #
    libraries = []
    start_recording = False
    for line in output.splitlines():
        if start_recording:
            so_path_index = line.find(os.path.sep)
            if so_path_index >= 0:
                so_path = line[so_path_index:]
                if not os.path.exists(so_path):
                    print(f"warning: could not find shared object: {so_path}")
                    continue
                libraries.append(so_path)
        elif 'Shared Object Library' in line:
            start_recording = True
    return libraries


def get_libraries_through_ldd(bin_path: str) -> Optional[List[str]]:
    """
    Given a binary return a list with the paths of its shared object
    dependencies.
    """
    success, output = shell_cmd(['ldd', bin_path])
    if not success:
        print(output, file=sys.stderr)
        return None

    sys.exit("error: library detection through ldd(1) not implemented yet")
    return []


def binary_includes_debug_info(path: str) -> Optional[bool]:
    """
    Check whether a binary has been stripped of its DWARF info.
    """
    success, output = shell_cmd(['readelf', '-S', path])
    if not success:
        print(output, file=sys.stderr)
        return None

    #
    # Example output:
    # ```
    # $ readelf -S /sbin/ztest
    # There are 28 section headers, starting at offset 0x226f8:
    #
    # Section Headers:
    #   [Nr] Name              Type             Address           Offset
    #        Size              EntSize          Flags  Link  Info  Align
    #   [ 0]                   NULL             0000000000000000  00000000
    #        0000000000000000  0000000000000000           0     0     0
    #   [ 1] .interp           PROGBITS         0000000000000238  00000238
    #        000000000000001c  0000000000000000   A       0     0     1
    #   [ 2] .note.ABI-tag     NOTE             0000000000000254  00000254
    #   ...
    # ```
    #
    debug_info, debug_str = False, False
    for line in output.splitlines():
        if '.debug_info' in line:
            debug_info = True
        if '.debug_str' in line:
            debug_str = True
        if debug_info and debug_str:
            return False
    return False


def get_debug_info_path(path: str) -> Optional[str]:
    """
    Given a binary that's been stripped of its debug info
    but contains a debug link section, return the path
    to its DWARF info from that debug link.
    """
    assert not binary_includes_debug_info(path)

    success, output = shell_cmd(['readelf', '-n', path])
    if not success:
        print(output, file=sys.stderr)
        return None

    #
    # Example output:
    # ```
    # $ readelf -n /sbin/ztest
    #
    # Displaying notes found in: .note.ABI-tag
    #   Owner                 Data size	Description
    #   GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
    #     OS: Linux, ABI: 3.2.0
    #
    # Displaying notes found in: .note.gnu.build-id
    #   Owner                 Data size	Description
    #   GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    #     Build ID: 1bfce25bba922713a61e1929bbaae1beacdb64b7
    # ```
    #
    build_id = ""
    for line in output.splitlines():
        if 'Build ID:' in line:
            build_id = line.split()[2]
            debug_path = f"/usr/lib/debug/.build-id/{build_id[:2]}/{build_id[2:]}.debug"
            if os.path.exists(debug_path):
                return debug_path
            break
    return None


def get_binary_path_from_userland_core(path: str) -> Optional[str]:
    """
    Given the path of a userland core dump, return the path of the
    program binary in string form.
    """
    assert get_dump_type(path) == DumpType.UCOREDUMP
    success, output = shell_cmd(['file', path])
    if not success:
        sys.exit(output)

    match = re.search("execfn: '(.+?)',", output)
    if not match:
        return None
    return match.group(1)


def archive_userland_core_dump(path: str) -> None:
    """
    Packages the dump together with its binary and libraries in a
    gzipped archive in the working directory.
    """
    #
    # Find the binary program from the core.
    #
    bin_path = get_binary_path_from_userland_core(path)
    if not bin_path:
        sys.exit("error: could not find binary program from core")
    if not os.path.exists(bin_path):
        sys.exit(f"error: cannot find binary pointed by the core: {bin_path}")
    print(f"binary found: {bin_path}")

    #
    # Find all related libraries.
    #
    # Note we first try to get these libraries from the core using
    # gdb(1) and if that fails then we try with ldd(1). gdb is
    # preferable because it includes any libraries that have been
    # loaded during runtime with dlopen(3) which ldd misses.
    #
    libraries = get_libraries_through_gdb(bin_path, path)
    if libraries is None:
        libraries = get_libraries_through_ldd(bin_path)
        if libraries is None:
            sys.exit("error: both gdb(1) and ldd(1) fail to execute")

    #
    # Get all the debug info from the program binary and its
    # libraries.
    #
    debug_paths, bin_deps = [], [bin_path] + libraries
    for bin_dep in bin_deps:
        if binary_includes_debug_info(bin_dep):
            continue
        debug_info = get_debug_info_path(bin_dep)
        if debug_info is None:
            print(f"warning: could not find debug info of: {bin_dep}")
            continue
        debug_paths.append(debug_info)

    dumpname = os.path.basename(path)
    archive_dir = f"archive-{dumpname}"
    pathlib.Path(archive_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy(path, archive_dir)
    multi_copy_from_root([bin_path] + libraries + debug_paths, archive_dir)

    #
    # Generate run-gdb.sh.
    #
    run_gdb_path = f"{archive_dir}/run-gdb.sh"
    with open(run_gdb_path, "w") as gdb_script:
        print(RUN_GDB_CONTENTS.format(bin_path, dumpname), file=gdb_script)
    os.chmod(run_gdb_path, 0o755)

    msg = compress_archive(archive_dir)
    shutil.rmtree(archive_dir)
    if msg:
        sys.exit(f"error: {msg}")


def parse_arguments() -> argparse.Namespace:
    """
    Self-explanatory...
    """
    parser = argparse.ArgumentParser(prog="savedump",
                                     description="Archive Linux crash dumps")
    parser.add_argument("dump", help="the dump to be archived")
    return parser.parse_args()


def main() -> None:
    """ Entry point of the savedump "executable" """
    args = parse_arguments()

    dump_type = get_dump_type(args.dump)
    if dump_type == DumpType.CRASHDUMP:
        print('dump type: kernel crash dump')
        archive_kernel_dump(args.dump)
    elif dump_type == DumpType.UCOREDUMP:
        print('dump type: userland dump')
        archive_userland_core_dump(args.dump)
    else:
        sys.exit('unknown core type')


if __name__ == "__main__":
    main()
