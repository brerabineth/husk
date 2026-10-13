#!/usr/bin/env python3
"""mangle benign.elf into husk's opacity fixtures:

  hollower.elf — section header table erased entirely (e_shoff/e_shnum/
                 e_shstrndx zeroed). what sstrip-style tools leave behind.
  shrouded.elf — only the section-name index is destroyed (e_shstrndx=0),
                 so every section name resolves to nothing.

both stay valid enough to load-parse. synthetic, deterministic."""
import sys

def u16(b, off): return int.from_bytes(b[off:off+2], "little")

def mangle(src, dst, mode):
    b = bytearray(open(src, "rb").read())
    assert b[:4] == b"\x7fELF", "not an elf"
    assert b[4] == 2, "expect elf64 little endian"
    if mode == "hollower":
        # e_shoff (0x28, 8 bytes) = 0 ; e_shnum (0x3c) = 0 ; e_shstrndx (0x3e) = 0
        b[0x28:0x30] = b"\x00" * 8
        b[0x3c:0x3e] = b"\x00\x00"
        b[0x3e:0x40] = b"\x00\x00"
    elif mode == "shrouded":
        # e_shstrndx (0x3e) = 0  -> shstrtab resolves to the NULL section
        b[0x3e:0x40] = b"\x00\x00"
    else:
        raise ValueError(mode)
    open(dst, "wb").write(bytes(b))
    print(f"{dst}: {mode} written ({len(b)} bytes)")

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "fixtures/bin/benign.elf"
    mangle(src, "fixtures/bin/hollower.elf", "hollower")
    mangle(src, "fixtures/bin/shrouded.elf", "shrouded")
