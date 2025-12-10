from headless_ida import HeadlessIda
from pathlib import Path

# from config import config

bin_path = "/home/ruotoy/Desktop/allthings_ida/headless-ida/tests/testbin/hello_world"
assert Path(bin_path).exists(), f"Binary path does not exist: {bin_path}"
bin_path_2 = "/home/ruotoy/Desktop/allthings_ida/headless-ida/tests/testbin/foo"
assert Path(bin_path_2).exists(), f"Binary path does not exist: {bin_path_2}"

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


if __name__ == "__main__":
    ida_dir_path = "/home/ruotoy/Desktop/decompile_compare/tools/IDA/idapro-8.4"
    if ida_dir_path is None:
        raise ValueError("IDA directory path is not configured in config.py")
    if not Path(ida_dir_path).exists():
        raise ValueError(f"IDA directory path does not exist: {ida_dir_path}")
    
    headless_ida = HeadlessIda(ida_dir=ida_dir_path, binary_path=bin_path)
    headless_ida2 = HeadlessIda(ida_dir=ida_dir_path, binary_path=bin_path_2)
    # headless_ida.

    print("-----")
    if remote_fn := headless_ida.remoteify(ida_remote_get_all_func_names):
        all_funcs = remote_fn()
        print(all_funcs)
        pass
    
    print("-----")
    if remote_fn2 := headless_ida2.remoteify(ida_remote_get_all_func_names):
        all_funcs2 = remote_fn2()
        print(all_funcs2)
        pass

    pass



