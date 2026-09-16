#!/usr/bin/env python3
"""
TSDS Environment Check Script
CSCloud 2026 Submission Review & Audit Pack

Checks local system toolchain, Python environment, SMT solvers, and binary analysis backends.
"""

import sys
import shutil
import subprocess

def check_component(name, test_fn):
    try:
        ok, msg = test_fn()
        status = "[OK]  " if ok else "[WARN]"
        print(f"  {status} {name:<22}: {msg}")
        return ok
    except Exception as e:
        print(f"  [FAIL] {name:<22}: Exception ({e})")
        return False

def test_python():
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    return (v.major == 3 and v.minor >= 8), f"Python {ver_str}"

def test_z3():
    try:
        import z3
        return True, f"z3-solver {z3.__version__}"
    except ImportError:
        path = shutil.which("z3")
        if path:
            return True, f"CLI binary at {path}"
        return False, "Not installed (pip install z3-solver)"

def test_cvc5():
    path = shutil.which("cvc5")
    if path:
        return True, f"CLI binary at {path}"
    return False, "Optional CLI solver (cvc5 not found in PATH)"

def test_angr():
    try:
        import angr
        return True, f"angr {angr.__version__}"
    except ImportError:
        return False, "Not installed in current interpreter (optional for static exploration)"

def test_qemu():
    path = shutil.which("qemu-arm") or shutil.which("qemu-system-arm") or shutil.which("qemu-mipsel")
    if path:
        return True, f"Found at {path}"
    return False, "QEMU not in PATH (needed only for dynamic emulation rehosting)"

def main():
    print("\n" + "=" * 65)
    print("  TSDS Execution & Reproduction Environment Diagnostic")
    print("=" * 65)
    check_component("Python Runtime", test_python)
    check_component("Z3 SMT Solver", test_z3)
    check_component("CVC5 SMT Solver", test_cvc5)
    check_component("angr Framework", test_angr)
    check_component("QEMU Emulators", test_qemu)
    print("=" * 65)
    print("  Note: For standalone evidence audit (scripts/verify_all_receipts.py),")
    print("  only standard Python 3.8+ is required (0 external dependencies).")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
