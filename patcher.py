import os
import sys


NOP_ARM64 = b"\x1f\x20\x03\xd5"
SVC_ARM64 = b"\x01\x00\x00\xd4"



def peek_and_patch(pid, address_hex, do_patch=False):
    address = int(address_hex, 16)
    mem_path = f"/proc/{pid}/mem"
    
    if not os.path.exists(mem_path):
        print(f"[-] PID {pid} or memory access not found.")
        return

    try:
        # Open in binary mode. 'rb+' allows reading and writing.
        mode = 'rb+' if do_patch else 'rb'
        with open(mem_path, mode) as f:
            # 1. Read the instruction at the PC
            f.seek(address)
            instruction = f.read(4)
            
            # 2. "Disassemble" (Manual check for common Bipan targets)
            hex_code = instruction.hex()
            asm_label = "UNKNOWN"
            if instruction == SVC_ARM64: asm_label = "svc #0 (SYSCALL)"
            elif instruction == NOP_ARM64: asm_label = "nop (ALREADY PATCHED)"
            
            print(f"[*] Address: {hex(address)}")
            print(f"[*] Hex:     {hex_code}")
            print(f"[*] Assembly: {asm_label}")

            # 3. Patching logic
            if do_patch:
                if instruction == NOP_ARM64:
                    print("[!] already patched. Skipping.")
                else:
                    print(f"[!] Patching {hex_code} -> {NOP_ARM64.hex()} (NOP)...")
                    f.seek(address)
                    f.write(NOP_ARM64)
                    print("[+] Patch applied successfully.")
            else:
                print("[i] Run with 'patch' argument to apply.")

    except PermissionError:
        print("[-] Permission Denied. Run as root (su).")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python patcher.py <pid> <address_hex> [patch]")
        sys.exit(1)
    
    pid = sys.argv[1]
    addr = sys.argv[2]
    apply = len(sys.argv) > 3 and sys.argv[3] == "patch"
    
    peek_and_patch(pid, addr, apply)
