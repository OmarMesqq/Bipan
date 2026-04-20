import os
import re
import sys

def find_bipan(pid, search_string="amphoras"):
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    
    if not os.path.exists(maps_path):
        print(f"[-] PID {pid} not found.")
        return

    print(f"[*] Hunting in PID {pid}...")
    
    # ELF Magic Header for ARM64
    ELF_MAGIC = b"\x7fELF"
    
    try:
        with open(maps_path, 'r') as maps_file, open(mem_path, 'rb', 0) as mem_file:
            for line in maps_file:
                # We prioritize executable (r-xp) or anonymous (deleted) regions
                # as that is where Zygisk hides modules.
                if 'r-x' in line or '(deleted)' in line or '[anon]' in line:
                    parts = line.split()
                    addr_range = parts[0]
                    path = parts[-1] if len(parts) > 5 else "[Anonymous]"
                    
                    start_addr, end_addr = [int(x, 16) for x in addr_range.split('-')]
                    size = end_addr - start_addr
                    
                    try:
                        mem_file.seek(start_addr)
                        chunk = mem_file.read(size)
                        
                        # 1. Search for ELF Header (The start of the library)
                        if chunk.startswith(ELF_MAGIC):
                            print(f"[!] FOUND ELF HEADER at {hex(start_addr)} - Map: {path}")
                        
                        # 2. Search for your specific Bipan strings
                        if search_string.encode() in chunk:
                            offset = chunk.find(search_string.encode())
                            print(f"[!] FOUND STRING '{search_string}' at {hex(start_addr + offset)}")
                            print(f"    Region: {addr_range} | Perms: {parts[1]} | Name: {path}")
                            
                    except Exception as e:
                        # Skip regions we can't read (kernel protection)
                        continue
    except PermissionError:
        print("[-] Permission Denied. Run as root (su).")

if __name__ == "__main__":
    target_pid = 10133 
    find_bipan(target_pid)
