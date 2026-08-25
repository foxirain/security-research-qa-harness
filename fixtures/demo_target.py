from __future__ import annotations

import os
import sys


def emit_heap_overflow() -> int:
    print("==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef")
    print("WRITE of size 4 at 0xdeadbeef thread T0")
    print("    #0 0x414141 in parse_packet demo_target.py")
    print("    #1 0x424242 in main demo_target.py")
    print("0xdeadbeef is located 8 bytes to the right of 32-byte region in heap")
    return 1


def emit_stack_overflow() -> int:
    print("==5678==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xabad1dea")
    print("WRITE of size 8 at 0xabad1dea thread T0")
    print("    #0 0x515151 in parse_header demo_target.py")
    print("    #1 0x525252 in main demo_target.py")
    print("0xabad1dea is located 16 bytes to the left of stack variable frame")
    return 1


def emit_uaf() -> int:
    print("==7777==ERROR: AddressSanitizer: use-after-free on address 0xfacefeed")
    print("READ of size 8 at 0xfacefeed thread T0")
    print("    #0 0x616161 in replay_request demo_target.py")
    print("    #1 0x626262 in main demo_target.py")
    print("0xfacefeed is located 0 bytes inside of 64-byte region in heap")
    print("freed by thread T0 here:")
    print("    #0 0x717171 in free demo_target.py")
    return 1


def main() -> int:
    path = sys.argv[1]
    parser_mode = os.getenv("PARSER_MODE", "default")
    data = open(path, "r", encoding="utf-8").read()
    if "STACK" in data:
        return emit_stack_overflow()
    if "UAF" in data:
        return emit_uaf()
    if "CRASH" in data and parser_mode in {"default", "legacy"}:
        return emit_heap_overflow()
    print(f"parse completed cleanly in mode={parser_mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
