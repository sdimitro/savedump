# savedump

![](https://github.com/delphix/savedump/workflows/.github/workflows/main.yml/badge.svg)

TL;DR; A Python script that creates a best-effort self-contained
archive of a kernel crash dump or userland core dump. The archive
contains the memory dump coupled together with any required
binaries and debug information that it could find at the time it
was invoked.

### Motivation

In illumos crash dumps (think kernel state dumps) and cores dumps
(think userspace dumps) are self-contained. You'd fire up the
debugger and the debugger would find the relevant binary (and
shared objects) within the memory dump's address space and resolve
symbols from there. In addition, illumos uses CTF which is a
space-efficient debugging format whose data are always part of
the binary they describe. All of the above facts make it easy
to decouple the system where the debugger is used from the
machine that generated the core, as dumps have all the info
the debugger will ever need.

In Linux this decoupling doesn't exist by default. Dumps tend
to point to binaries instead of including them in their address
space on-disk. Thus copying a core dump or a crash dump from a
machine is of no use if one doesn't also copy the relevant
binaries (which is hard to do correctly sometimes like in cases
where dlopen() was used during runtime to load a shared object).
On top of that, even if one finds the right binaries, they may
still need to track down their debug information, which in
Linux are generally decoupled by using partial DWARF, debug-links
or BuildID-based links.

These design choices in Linux were not made without reason. It
is an OS that is used in a vast variety of contexts and therefore
it is expected to have many configuration switches for generating
dumps. What it does lack though is proper tooling to capture a
self-contained dump from one system to analyze it in another.
This is what this utility is attempting to help with.

### Installation

Ensure you have the following dependencies:
* Python 3.6 or newer
* [libkdumpfile](https://github.com/ptesarik/libkdumpfile)
* [drgn](https://github.com/osandov/drgn/)
* [gdb](https://www.gnu.org/software/gdb/)

Note that `libkdumpfile` and `drgn` are only needed for kernel
crash dumps. If you only need `savedump` for userland core dumps
then you only need `python3`. `gdb` is not a hard dependency
either but it is recommeneded for accurate archival of shared
objects in userland core dumps.

Once all dependencies are installed clone this repo and
run the following command from the root of the repo:
```
sudo python3 setup.py install
```

### How do I use it?

To capture a crash dump or a core dump:
```
$ file core.19122
core.19122: ELF 64-bit LSB core file x86-64, version 1 (SYSV), SVR4-style, from '/sbin/ztest', real uid: 65433, effective uid: 65433, real gid: 50, effective gid: 50, execfn: '/sbin/ztest', platform: 'x86_64'

$ savedump core.19122
dump type: userland dump
binary found: /sbin/ztest
compressing archive...done
archive created: archive-core.19122.tar.gz
```

Here is a quick look at what the archive looks like:
```
$ tar xzf archive-core.19122.tar.gz
$ tree -a archive-core.19122
archive-core.19122
├── core.19122
├── lib
│   ├── libnvpair.so.1
│   ├── libzpool.so.2
│   └── x86_64-linux-gnu
│       ├── libblkid.so.1
│       ├── libc.so.6
│       ├── libdl.so.2
│       ├── libgcc_s.so.1
│       ├── libm.so.6
│       ├── libpthread.so.0
│       ├── librt.so.1
│       ├── libudev.so.1
│       ├── libuuid.so.1
│       └── libz.so.1
├── lib64
│   └── ld-linux-x86-64.so.2
├── run-gdb.sh
├── sbin
│   └── ztest
└── usr
    └── lib
        └── debug
            └── .build-id
                ├── 1b
                │   └── fce25bba922713a61e1929bbaae1beacdb64b7.debug
                ├── 1d
                │   └── 270ba4410fa316711611190e3b0fb17cab7cfb.debug
                ├── 28
                │   └── c6aade70b2d40d1f0f3d0a1a0cad1ab816448f.debug
                ├── 49
                │   └── 38b15a667a41cc98755418556ea492500a927a.debug
                └── bb
                    ├── b0d69dcb5f2935f3ba403fe9a87f7f58b473fe.debug
                    └── e20d3ad910e39003554ef3317a14ce834b57e7.debug

13 directories, 22 files
```

### Limitations/Future Work

As mentioned in the TL;DR; the utility is far from perfect but I do
hope to add more functionality to it as cases arise.

* [verify BuildID and/or SRCVERSION between dumps and binaries](https://github.com/sdimitro/savedump/issues/6)
* [make the gdb dependency optional](https://github.com/sdimitro/savedump/issues/9)
* [support custom paths for binaries and debug info](https://github.com/sdimitro/savedump/issues/5)
* [generate run-sdb.sh](https://github.com/sdimitro/savedump/issues/10)
* [support for plain vmcores](https://github.com/sdimitro/savedump/issues/3)
* [support for more DWARF-decoupling methods](https://github.com/sdimitro/savedump/issues/4)
