<p align="center">
  <img alt="Headless IDA" src="https://raw.githubusercontent.com/DennyDai/headless-ida/main/headless-ida.png" width="128">
</p>
<h1 align="center">Headless IDA</h1>

[![Latest Release](https://img.shields.io/pypi/v/headless-ida.svg)](https://pypi.python.org/pypi/headless-ida/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/headless-ida.svg)](https://pypistats.org/packages/headless-ida)
[![License](https://img.shields.io/github/license/DennyDai/headless-ida.svg)](https://github.com/DennyDai/headless-ida/blob/main/LICENSE)

# Install
```bash
pip install headless-ida
```

# Usage

> [!TIP]
> Headless IDA supports the latest [idalib](https://docs.hex-rays.com/user-guide/idalib). Just provide the idalib path instead of idat64 to use it as the backend.

### Use it as a normal Python module.
```python
# Initialize HeadlessIda
from headless_ida import HeadlessIda
headlessida = HeadlessIda("/path/to/idat64", "/path/to/binary")

# Import IDA Modules (make sure you have initialized HeadlessIda first)
import idautils
import ida_name

# Or Import All IDA Modules at Once (idaapi is not imported by default)
# from headless_ida.ida_headers import *

# Have Fun
for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

### Use it as a command line tool.
```bash
# Interactive Console
$ headless-ida /path/to/idat64 /path/to/binary
Python 3.8.10 (default, Nov 14 2022, 12:59:47) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> import idautils
>>> list(idautils.Functions())[0:10]
[16384, 16416, 16432, 16448, 16464, 16480, 16496, 16512, 16528, 16544]
>>> 


# Run IDAPython Script
$ headless-ida /path/to/idat64 /path/to/binary idascript.py


# One-liner
$ headless-ida /path/to/idat64 /path/to/binary -c "import idautils; print(list(idautils.Functions())[0:10])"


# In case you like IPython
$ headless-ida /path/to/idat64 /path/to/binary -c "import IPython; IPython.embed();"
```

### Remote Exec/Eval/Remoteify

Referenced from https://github.com/justfoxing/jfx_bridge.

```python
def ida_remote_print_all_funcs():
    import idautils # type: ignore
    import ida_name # type: ignore
    for func in idautils.Functions():
        print(f"{hex(func)} {ida_name.get_ea_name(func)}")
    pass


def ida_remote_get_all_func_names():
    import idautils # type: ignore
    import ida_name # type: ignore
    func_names = []
    for func in idautils.Functions():
        func_names.append(ida_name.get_ea_name(func))
    return func_names

headless_ida = HeadlessIda(ida_dir=ida_dir_path, binary_path=bin_path)

print(headless_ida.remote_eval("1+1"))  # 2

if remote_fn := headless_ida.remoteify(ida_remote_get_all_func_names):
    all_funcs = remote_fn()
    all_funcs = list(all_funcs)
    print(all_funcs)
    pass
```

### Support for multiple headless-ida instances

In the original design, the server always bound to the default port 8000. With our updated approach, the system can intelligently allocate available ports, allowing multiple headless IDA instances to run concurrently.

**However, this enhancement imposes a constraint: direct use of IDA APIs is no longer feasible. All interactions must be performed via `remoteify` or `remote_*` calls to prevent cross-instance conflicts.**

```python
headless_ida = HeadlessIda(ida_dir=ida_dir_path, binary_path=bin_path)
headless_ida2 = HeadlessIda(ida_dir=ida_dir_path, binary_path=bin_path_2)

print("-----")
if remote_fn := headless_ida.remoteify(ida_remote_get_all_func_names):
    all_funcs = remote_fn()
    print(all_funcs)

print("-----")
if remote_fn2 := headless_ida2.remoteify(ida_remote_get_all_func_names):
    all_funcs2 = remote_fn2()
    print(all_funcs2)
```

# Advanced Usage
## Remote Server

### Start a Headless IDA server
```bash
$ headless-ida-server /path/to/idat64 localhost 1337 &
```

### Connect to the server in Python script
```python
# Initialize HeadlessIda
from headless_ida import HeadlessIdaRemote
headlessida = HeadlessIdaRemote("localhost", 1337, "/path/to/local/binary")

# Import IDA Modules (make sure you have initialized HeadlessIda first)
import idautils
import ida_name

# Have Fun
for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

### Connect to the server in command line
```bash
# Interactive Console
$ headless-ida localhost:1337 /path/to/local/binary
# Run IDAPython Script
$ headless-ida localhost:1337 /path/to/local/binary idascript.py
# One-liner
$ headless-ida localhost:1337 /path/to/local/binary -c "import idautils; print(list(idautils.Functions())[0:10])"
```


# Resources
- [Headless IDA Examples](https://github.com/DennyDai/headless-ida/tree/main/examples)
- [IDAPython Official Documentation](https://docs.hex-rays.com/developer-guide/idapython)
- IDAPython Official Examples: [1](https://docs.hex-rays.com/developer-guide/idapython/idapython-examples), [2](https://github.com/idapython/src/tree/master/examples)
# Known Issues
### `from XXX import *`
 - Using `from XXX import *` syntax with certain ida modules (like idaapi, ida_ua, etc.) is currently unsupported due to SWIG and RPyC compatibility issues. We recommend importing specific items with `from XXX import YYY, ZZZ`, or importing the entire module using `import XXX`.
 - The issue arises because SWIG, employed for creating Python bindings for C/C++ code, generates intermediary objects (SwigVarlink) that RPyC, our remote procedure call mechanism, cannot serialize or transmit correctly.
