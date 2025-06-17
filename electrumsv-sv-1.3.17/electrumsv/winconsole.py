# Electrum SV - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This module is for to handling console attaching and / or creation in Windows binaries that are
built for the Windows subsystem and therefore do not automatically allocate a console.
"""

import ctypes
import os
import sys
from typing import Generator, Optional, Union

assert sys.platform == 'win32'

from electrumsv.logs import logs

STD_OUTPUT_HANDLE = -11
FILE_TYPE_DISK = 1


def _parent_process_pids() -> Generator[int, None, None]:
    """
    Returns all parent process PIDs, starting with the closest parent
    """
    try:
        import psutil
        pid = os.getpid()
        while pid > 0:
            pid = psutil.Process(pid).ppid()
            yield pid
    except psutil.NoSuchProcess:
        # Parent process not found, likely terminated, nothing we can do
        pass


def _create_or_attach_console(attach: bool=True,
                              create: bool=False,
                              title: Optional[str]=None) -> Union[bool, None]:
    """
    First this checks if output is redirected to a file and does nothing if it is. Then it tries
    to attach to the console of any parent process and if not successful it optionally creates a
    console or fails.
    If a console was found or created, it will redirect current output handles to this console.
    """
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    if std_out_handle > 0:
        if ctypes.windll.kernel32.GetFileType(std_out_handle) == FILE_TYPE_DISK:
            # Output is being redirected to a file, do nothing
            return None

    has_console = std_out_handle > 0

    if not has_console and attach:
        # Try to attach to a parent console
        for pid in _parent_process_pids():
            if ctypes.windll.kernel32.AttachConsole(pid):
                has_console = True
                break

    if not has_console and create:
        # Try to allocate a new console
        if ctypes.windll.kernel32.AllocConsole():
            has_console = True

    if not has_console:
        return False

    if title:
        # Set the console title
        ctypes.windll.kernel32.SetConsoleTitleW(title)

    # Reopen Pythons console input and output handles
    conout = open('CONOUT$', 'w')
    sys.stdout = conout
    sys.stderr = conout
    logs.set_stream_output(conout)
    sys.stdin = open('CONIN$', 'r')

    return True


def setup_windows_console():
    # On windows, allocate a console if needed. Detect and avoid mingw/msys and cygwin.
    if not sys.platform.startswith('win') or "MSYSTEM" in os.environ or "CYGWIN" in os.environ:
        return

    force_console = '-v' in sys.argv or '--verbose' in sys.argv
    if (not _create_or_attach_console(create=force_console, title='ElectrumSV Console') and
            force_console):
        # Force console specified and we couldn't get a console, fail
        MB_ICONERROR = 0x10
        MB_OK = 0
        ctypes.windll.user32.MessageBoxW(0, 'Failed to get a console', 'ElectronSV',
            MB_OK | MB_ICONERROR)
        sys.exit(1)

