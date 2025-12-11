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
ALLOC_FUNCS = ["malloc", "calloc", "realloc"]

logger = get_logger("malloc_checker")

def analyze_library(lib_path: str):

    logger.info(f"===== Analyzing {lib_path} =====")

    try:
        proj = angr.Project(lib_path, auto_load_libs=False)
    except Exception as exc:
        logger.error(f"[!] Failed to load {lib_path}: {exc}")
        return []

    cfg = proj.analyses.CFGFast()
    main_obj = proj.loader.main_object

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

    logger.info("[*] allocator entry addresses: " + ", ".join(hex(a) for a in sorted(alloc_addrs)))

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
        logger.info("    call @ " + hex(cs[0]))

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
                "pc": state.addr,
                "history_len": len(state.history.bbl_addrs),
            }
        )

    for callsite in call_sites:
        ret_addr = callsite[0] + callsite[1]

        logger.info(f"[*] Analyzing malloc return @ {hex(ret_addr)}")

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


def collect_libraries(target: str):
    if os.path.isfile(target):
        return [target]
    if os.path.isdir(target):
        libs = sorted(os.path.join(target, p) for p in os.listdir(target) if os.path.isfile(os.path.join(target, p)) and p.endswith(".so"))
        return libs
    raise FileNotFoundError(f"Target path '{target}' not found")


def main():
    parser = argparse.ArgumentParser(description="Detect unchecked malloc dereferences across libraries")
    parser.add_argument("path", nargs="?", default=DEFAULT_LIB, help="Library file or directory containing libraries")
    parser.add_argument("--output", default=None, help="Write aggregated findings to this file")
    args = parser.parse_args()

    target = args.path
    
    try:
        libraries = collect_libraries(target)
    except FileNotFoundError as exc:
        logger.error(exc)
        return

    if not libraries:
        logger.warning(f"No libraries under {target}")
        return

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

