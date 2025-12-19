import argparse
import angr
import claripy
import capstone
from functools import partial
from pathlib import Path
import logging
from colorama import Fore, Style, init
import tqdm
import os
import struct
    
angr.loggers.disable_root_logger()

init(autoreset=True)

class ColorFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        if record.levelno == logging.INFO:
            return Fore.GREEN + msg + Style.RESET_ALL
        elif record.levelno == logging.ERROR:
            return Fore.RED + msg + Style.RESET_ALL
        elif record.levelno == logging.WARNING:
            return Fore.YELLOW + msg + Style.RESET_ALL
        return msg

def get_logger(name: str, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = ColorFormatter("%(levelname)s - %(name)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False  
    return logger

DEFAULT_LIB = "./qnx800/target/qnx/x86_64/usr/lib/libiperf.so"
ALLOC_FUNCS = ["malloc", "calloc", "realloc", "object_alloc", "_scalloc", "_smalloc", "vm_kmem_alloc", "_srealloc", "pathmgr_node_alloc", "nto_context_alloc", "ksmalloc", "vm_pmem_alloc"]

logger = get_logger("malloc_checker")

def analyze_library(lib_path: str):

    logger.info(f"===== Analyzing {lib_path} =====")
    
    load_options={
        "auto_load_libs": False,
        "main_opts":{
            "base_addr":0x0,
        }
    }

    try:
        proj = angr.Project(lib_path, load_options=load_options)
    except Exception as exc:
        logger.error(f"[!] Failed to load {lib_path}: {exc}")
        return []

    cfg = proj.analyses.CFGFast()
    main_obj = proj.loader.main_object
    
    def rebase_addr(addr):
        return addr - main_obj.mapped_base

    def get_return_register_offset():
        arch = proj.arch
        if arch.name == "AMD64":
            reg_name = "rax"
        elif arch.name == "X86":
            reg_name = "eax"
        elif arch.name == "AARCH64":
            reg_name = "x0"
        else:
            raise Exception(f"Unsupported arch: {arch.name}")
        return arch.registers[reg_name][0]
    
    def debug(addr,ir=False):
        block = proj.factory.block(addr)
        if ir:
            block.vex.pp()
        else:
            block.pp()

    alloc_addrs = set()
    for name in ALLOC_FUNCS:
        sym = proj.loader.find_symbol(name)
        if sym:
            alloc_addrs.add(sym.rebased_addr)

        plt_table = getattr(main_obj, "plt", {})
        plt_addr = plt_table.get(name)
        if plt_addr:
            alloc_addrs.add(plt_addr)

        imports = getattr(main_obj, "imports", {})
        import_sym = imports.get(name)
        if import_sym:
            addr = getattr(import_sym, "rebased_addr", None)
            if addr is None and isinstance(import_sym, int):
                addr = import_sym
            if addr is not None:
                alloc_addrs.add(addr)

    if not alloc_addrs:
        logger.info("[!] No allocator symbols resolved; skipping")
        return []

    logger.info("[*] allocator entry addresses: " + ", ".join(hex(a) for a in sorted([rebase_addr(addr) for addr in alloc_addrs])))

    def resolve_call_target(insn):
        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type == capstone.CS_OP_IMM:
            return op.imm
        if proj.arch.name == "AMD64" and op.type == capstone.CS_OP_MEM:
            if op.mem.base == capstone.x86.X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp
        return None

    call_sites = set()
    for func in cfg.kb.functions.values():
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic.startswith("call"):
                    target = resolve_call_target(insn)
                    if target is not None and target in alloc_addrs:
                        call_sites.add((insn.address, insn.size))

    logger.info(f"[*] Found {len(call_sites)} malloc-call sites")
    for cs in sorted(call_sites):
        logger.info("    call @ " + hex(rebase_addr(cs[0])))

    vuln_reports = []
    vuln_seen = set()

    def _record_mem_access(state, access_type):
        nonlocal vuln_reports, vuln_seen

        sp = state.globals.get("malloc_ret")
        if sp is None:
            return

        addr_ast = None
        if access_type == "read":
            addr_ast = state.inspect.mem_read_address
        elif access_type == "write":
            addr_ast = state.inspect.mem_write_address

        if addr_ast is None or not hasattr(addr_ast, "variables"):
            return

        if not (addr_ast.variables & sp.variables):
            return

        callsite = state.globals.get("callsite")
        key = (callsite, access_type, state.addr)
        if key in vuln_seen:
            return

        vuln_seen.add(key)
        vuln_reports.append(
            {
                "library": lib_path,
                "callsite": callsite,
                "access_type": access_type,
                "pc": rebase_addr(state.addr),
                "history_len": len(state.history.bbl_addrs),
            }
        )

    for callsite in call_sites:
        ret_addr = callsite[0] + callsite[1]

        logger.info(f"[*] Analyzing malloc return @ {hex(rebase_addr(ret_addr))}")

        state = proj.factory.blank_state(addr=ret_addr)
        sym_ptr = claripy.BVS(f"malloc_ret_{hex(callsite[0])}", proj.arch.bits)
        state.registers.store(get_return_register_offset(), sym_ptr)

        state.globals["malloc_ret"] = sym_ptr
        state.globals["callsite"] = callsite[0]
        
        # NUll ret
        state.add_constraints(sym_ptr == 0x0)

        # assign suitable value, in case of overflow in rsp and rbp
        state.regs.rsp = 0x700000
        state.regs.rbp = 0x700000 + 0x500

        errno_addr = 0x800000
        state.libc.errno_location = errno_addr
        state.memory.store(errno_addr, claripy.BVV(0, state.arch.bits))

        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=partial(_record_mem_access, access_type="read"))
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=partial(_record_mem_access, access_type="write"))

        simgr = proj.factory.simulation_manager(state)

        max_step = 25
        
        while simgr.active and max_step > 0:
            try:
                simgr.step(num_inst=1)
            except Exception:
                # Due to unknown system, some funcs are not simulated, just skip
                break
            max_step -= 1
            # if encounter ret inst
            if simgr.unconstrained:
                break
            
    return vuln_reports


def is_elf_file(filepath: str) -> bool:
    """
    Check if a file is an ELF executable or shared library.
    
    Methods:
    1. Check ELF magic number (0x7F 'E' 'L' 'F')
    2. Check if it's ET_EXEC (executable) or ET_DYN (shared object)
    """
    try:
        with open(filepath, 'rb') as f:
            # Read ELF header magic number
            magic = f.read(4)
            if magic != b'\x7fELF':
                return False
            
            # Read EI_CLASS (32-bit or 64-bit)
            ei_class = f.read(1)[0]
            if ei_class not in (1, 2):  # ELFCLASS32=1, ELFCLASS64=2
                return False
            
            # Read EI_DATA (endianness)
            ei_data = f.read(1)[0]
            if ei_data == 1:  # ELFDATA2LSB (little-endian)
                endian = '<'
            elif ei_data == 2:  # ELFDATA2MSB (big-endian)
                endian = '>'
            else:
                return False
            
            # Skip to e_type field (offset 0x10)
            f.seek(0x10)
            e_type = struct.unpack(f'{endian}H', f.read(2))[0]
            
            # ET_EXEC=2 (executable), ET_DYN=3 (shared object)
            # Accept both executables and shared libraries
            return e_type in (2, 3)
            
    except Exception:
        return False


def is_executable_file(filepath: str) -> bool:
    """
    Check if a file is executable using multiple methods.
    
    1. Check execute permission bit
    2. Check ELF format
    """
    # Method 1: Check permission bits (Unix/Linux)
    if not os.access(filepath, os.X_OK):
        # Not executable by permission, but might still be an ELF binary
        pass
    
    # Method 2: Check ELF format (most reliable for binaries)
    return is_elf_file(filepath)


def collect_libraries(target: str, pattern: str = None):
    """
    Collect ELF binaries from target path.
    
    Args:
        target: File path or directory
        pattern: File pattern (e.g., "*.so", None for all ELF files)
    
    Returns:
        List of paths to ELF binaries
    """
    if os.path.isfile(target):
        return [target]
    
    if os.path.isdir(target):
        all_files = []
        for filename in os.listdir(target):
            filepath = os.path.join(target, filename)
            if not os.path.isfile(filepath):
                continue
            
            # Apply pattern filter if specified
            if pattern:
                if pattern == "*.so":
                    if not filename.endswith(".so"):
                        continue
                elif pattern == "*.exe":
                    if not (filename.endswith(".exe") or not '.' in filename):
                        continue
                # Add more patterns as needed
            
            # Check if it's an ELF file
            #if is_elf_file(filepath):
            all_files.append(filepath)
        
        return sorted(all_files)
    
    raise FileNotFoundError(f"Target path '{target}' not found")


def main():
    parser = argparse.ArgumentParser(description="Detect unchecked malloc dereferences across libraries and executables")
    parser.add_argument("path", nargs="?", default=DEFAULT_LIB, help="Binary file or directory containing binaries")
    parser.add_argument("--output", default=None, help="Write aggregated findings to this file")
    parser.add_argument("--pattern", default=None, help="File pattern filter (e.g., '*.so' for libs only)")
    parser.add_argument("--show-all", action="store_true", help="Show all ELF files found before analysis")
    args = parser.parse_args()

    target = args.path
    
    try:
        libraries = collect_libraries(target, pattern=args.pattern)
    except FileNotFoundError as exc:
        logger.error(exc)
        return

    if not libraries:
        logger.warning(f"No ELF binaries found under {target}")
        return
    
    if args.show_all:
        logger.info(f"Found {len(libraries)} ELF binaries:")
        for lib in libraries:
            logger.info(f"  - {lib}")
        print()

    aggregated_reports = []
    
    for lib in tqdm.tqdm(libraries, desc="Analyzing libraries"):
        aggregated_reports.extend(analyze_library(lib))

    report_lines = []
    if aggregated_reports:
        header = "=== Potential NULL deref candidates ===\n"
        report_lines.append(header)
        for rep in aggregated_reports:
            line = "[{lib}] call @ {cs}, access={typ}, pc={pc}, path_len={plen}".format(
                lib=rep["library"],
                cs=hex(rep["callsite"]),
                typ=rep["access_type"],
                pc=hex(rep["pc"]),
                plen=rep["history_len"],
            )
            report_lines.append(line)
        logger.info("")
    else:
        msg = "No potential NULL deref detected across analyzed libraries.\n"
        logger.info(msg)
        report_lines.append(msg)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text("\n".join(report_lines))
        logger.info(f"[+] Report written to {output_path}")


if __name__ == "__main__":
    main()

