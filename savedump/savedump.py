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
from enum import Enum
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple


def shell_cmd(cmd_and_args: List[str]) -> Tuple[bool, str]:
    """
    Executes shell command `cmd`. Returns:
        - (True, <string with command output>) on success.
        - (False, <error string>) on error.
    """
    cmd = cmd_and_args[0]
    if not shutil.which(cmd):
        return False, f"could not find program: {cmd}"

    with subprocess.Popen(cmd_and_args,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as proc:
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


RUN_CRASH_SDB_CONTENTS = """#!/bin/bash

script_path=$(readlink -f "$0")
script_dir=$(dirname "$script_path")

sdb -s $script_dir/usr/lib/debug/lib/modules \\
    $script_dir/{0} $script_dir/{1}
"""

RUN_PYCRASH_CONTENTS = """#!/bin/bash

script_path=$(readlink -f "$0")
script_dir=$(dirname "$script_path")

crash.sh -m $script_dir/usr/lib/debug/lib/modules \\
    $script_dir/{0} $script_dir/{1}
"""


def get_module_paths(osrelease: str, path: str) -> List[str]:
    """
    Use drgn on the crash dump specified by `path` and return list
    of paths from the `osrelease` kernel modules relevant to the
    crash dump.
    """
    #
    # Similarly to libkdumpfile we import these libraries locally
    # here so people who don't have drgn can still use savedump
    # for userland core dumps.
    #
    import drgn  # pylint: disable=import-outside-toplevel
    from drgn.helpers.linux.list import list_for_each_entry  # pylint: disable=import-outside-toplevel

    prog = drgn.program_from_core_dump(path)

    #
    # First go through all modules in the dump and create a map
    # of [key: module name] -> (value: module srcversion).
    #
    # Note:
    # It would be prefereable to be able to use the binary's
    # .build-id to do the matching instead of srcversion.
    # Unfortunately there doesn't seem to be a straightforward
    # way to get the build-id section of the ELF files recorded
    # in the dump. Hopefully that changes in the future.
    #
    mod_name_srcvers = {}
    for mod in list_for_each_entry('struct module',
                                   prog['modules'].address_of_(), 'list'):
        mod_name_srcvers[str(mod.name.string_(),
                             encoding='utf-8')] = str(mod.srcversion.string_(),
                                                      encoding='utf-8')

    #
    # Go through all modules in /usr/lib/debug/lib/modules/<osrelease>
    # and gather the file paths of the ones that are part of our
    # module name-to-srcversion map.
    #
    system_modules = pathlib.Path(
        f"/usr/lib/debug/lib/modules/{osrelease}/").rglob('*.ko')
    mod_paths = []
    for modpath in system_modules:
        modname = os.path.basename(modpath)[:-3]
        if not mod_name_srcvers.get(modname):
            continue

        success, output = shell_cmd(
            ['modinfo', '--field=srcversion',
             str(modpath)])
        if not success:
            sys.exit(output)
        output = output.strip()

        if output != mod_name_srcvers[modname]:
            continue

        mod_paths.append(str(modpath))
        del mod_name_srcvers[modname]

    print(f"found {len(mod_paths)} relevant modules with their debug info...")
    print("warning: could not find the debug info of the following modules:")
    print(f"  {', '.join(mod_name_srcvers.keys())}")
    return mod_paths


def archive_kernel_dump(path: str) -> None:
    """
    Packages the dump together with its vmlinux and modules in a
    gzipped archive in the working directory.
    """
    # pylint: disable=too-many-locals
    #
    # We import drgn and libkdumpfile specifically here and
    # not in the top-level to allow users that don't have
    # it installed to still be able to use savedump for
    # userland core files.
    #
    import kdumpfile  # pylint: disable=import-outside-toplevel

    kdump_info = kdumpfile.kdumpfile(path)
    dumpname = os.path.basename(path)
    nodename = kdump_info.attr['linux.uts.nodename']
    osrelease = kdump_info.attr['linux.uts.release']

    vmlinux_path = f"/usr/lib/debug/boot/vmlinux-{osrelease}"
    if not os.path.exists(vmlinux_path):
        sys.exit(f"error: cannot find vmlinux at: {vmlinux_path}")
    print(f"vmlinux found: {vmlinux_path}")

    mod_paths = get_module_paths(osrelease, path)

    archive_dir = f"{nodename}.archive-{dumpname}"
    pathlib.Path(archive_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy(path, archive_dir)
    shutil.copy(vmlinux_path, archive_dir)

    for mod_path in mod_paths:
        archive_mod_path = f"{archive_dir}{mod_path}"
        os.makedirs(os.path.dirname(archive_mod_path), exist_ok=True)
        shutil.copy(mod_path, archive_mod_path)

    #
    # Generate run-sdb.sh.
    #
    run_sdb_path = f"{archive_dir}/run-sdb.sh"
    with open(run_sdb_path, "w", encoding="utf-8") as sdb_script:
        print(RUN_CRASH_SDB_CONTENTS.format(os.path.basename(vmlinux_path),
                                            dumpname),
              file=sdb_script)
    os.chmod(run_sdb_path, 0o755)

    #
    # Generate run-pycrash.sh.
    #
    run_pycrash_path = f"{archive_dir}/run-pycrash.sh"
    with open(run_pycrash_path, "w", encoding="utf-8") as pycrash_script:
        print(RUN_PYCRASH_CONTENTS.format(os.path.basename(vmlinux_path),
                                          dumpname),
              file=pycrash_script)
    os.chmod(run_pycrash_path, 0o755)

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

    #
    # Example output of the above command:
    # ```
    #    $ ldd /sbin/ztest
    #       linux-vdso.so.1 (0x00007ffeeb9ac000)
    #       libnvpair.so.1 => /lib/libnvpair.so.1 (0x00007f607a568000)
    #       libzpool.so.2 => /lib/libzpool.so.2 (0x00007f6079f3c000)
    #       libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f6079b9e000)
    #       libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f607997f000)
    #       libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f607958e000)
    #       librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f6079386000)
    #       libblkid.so.1 => /lib/x86_64-linux-gnu/libblkid.so.1 (0x00007f6079139000)
    #       libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f6078f35000)
    #       libudev.so.1 => /lib/x86_64-linux-gnu/libudev.so.1 (0x00007f6078d17000)
    #       libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007f6078b10000)
    #       libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f60788f3000)
    #       /lib64/ld-linux-x86-64.so.2 (0x00007f607a9a2000)
    # ```
    #
    libraries = []
    for line in output.splitlines():
        line = line.strip()
        if '=>' in line:
            libraries.append(line.split()[2])
        elif 'ld-linux-' in line:
            #
            # Outside of ouf userland-linked libraries that are not part of
            # the runtime of the OS, we only care about the dynamic linker
            # used (e.g. ld-linux-x86-64.so.2) and even that is mostly there
            # for extreme situations.
            #
            libraries.append(line.split()[0])
    return libraries


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
            return True
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
    with open(run_gdb_path, "w", encoding="utf-8") as gdb_script:
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
