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
import os
import pathlib
import shutil
import subprocess
import sys
from typing import List, Tuple

import drgn
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

    proc = subprocess.Popen(cmd_and_args, stdout=subprocess.PIPE)
    out, err = proc.communicate()
    retcode = proc.wait()
    if retcode != 0:
        return False, f"{cmd} exited with code: {retcode} - msg: {str(err)}"
    return True, str(out)


def archive_kernel_dump(path: str) -> None:
    """
    Packages everything in a gzipped archive in the working
    directory.
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

    print("compressing archive...", end="")
    compressed_archive = f"{archive_dir}.tar.gz"
    success, msg = shell_cmd(
        ["tar", "-czf", compressed_archive, f"{archive_dir}"])
    if not success:
        shutil.rmtree(archive_dir)
        sys.exit(msg)
    print("done")

    shutil.rmtree(archive_dir)  # remove intermediate archive
    print(f"archive created: {compressed_archive}")


def parse_arguments() -> argparse.Namespace:
    """
    Self-explainatory...
    """
    parser = argparse.ArgumentParser(prog="savedump",
                                     description="Archive Linux crash dumps")
    parser.add_argument("dump", help="the dump to be archived")
    return parser.parse_args()


def main() -> None:
    """ Entry point of the savedump "executable" """
    args = parse_arguments()

    dump_target = drgn.program_from_core_dump(args.dump)
    if dump_target.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        print('dump type: kernel crash dump')
        archive_kernel_dump(args.dump)
    else:
        print('dump type: userland dump')
        sys.exit('userland core dumps not implemented yet!')


if __name__ == "__main__":
    main()
