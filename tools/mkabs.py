#!/usr/bin/env python3
"""mkabs: pack a raw Linux kernel into an ALi C3503D (Ferguson Ariva 54) .abs.

The .abs is the whole 8 MiB SPI NOR image: a chain of ALi chunks starting at
offset 0, each header's span field pointing at the next chunk.  The only chunk
that changes is `maincode` (ID 0x01FE0101, flash 0x130000): the boot ROM and
the HASH1 bootloader decode it (LZMA-alone) to 0x80000200 and jump there with
a0 = 0x80000200.  This tool replaces that one chunk and leaves every other
byte of the donor image as it was.

Pipeline:  raw kernel -> LZMA-alone stream (Python lzma = system liblzma)
           -> 128-byte chunk header (donor's header, new LENGTH/CRC/name)
           -> written over the donor's maincode allocation (span).

Stdlib only (Python 3.8+).  Run with `python3 -I tools/mkabs.py ...`.

  chunk:    mkabs.py --board-conf boards/<board>/board.conf --kernel raw.bin --chunk-out maincode.abs
            (what the SDK uses: the header layout comes from the board configuration, no donor)
  image:    mkabs.py --donor DONOR.abs --kernel raw.bin --out NEW.abs [options]   (diagnostic: a full flash image)
  verify:   mkabs.py --verify IMAGE.abs [--donor DONOR.abs] [--kernel raw.bin]
  extract:  mkabs.py --extract IMAGE.abs --out maincode_raw.bin

Exit status: 0 ok, 1 verification failed (any CRC mismatch, broken chain,
decode failure, kernel or donor mismatch), 2 usage error or refused input.
"""
import argparse
import hashlib
import lzma
import os
import struct
import sys
import tempfile

# ---- format constants (A54 / C3503D; see README-mkabs.md) -------------------
HEADER_LEN = 128            # chunk header; LZMA stream starts at +128
LENGTH_BIAS = 112           # LENGTH = stream bytes + 112 (= header from +16 to +127)
NCRC = 0x4E435243           # "NCRC": chunk without CRC
MAIN_ID = 0x01FE0101        # maincode
HASH1_ID = 0x23010010       # bootloader (must stay byte-identical)
EXPECT_MAIN_OFFSET = 0x130000
DEFAULT_SPAN = 0x45D400      # maincode allocation of the A54 layout
LOAD_ADDR = 0x80000200      # the loader decodes to here and jumps here (a0 too)
SCRATCH_BASE = 0x81000000   # loader's copy of HASH1 / stack live above this
DECODE_LIMIT = SCRATCH_BASE - LOAD_ADDR     # 0xFFFE00 bytes: the decoded image must fit
LZMA_PROPS = 0x6C           # lc=0 lp=2 pb=2: (2*5+2)*9+0
LZMA_DICT = 0x00800000      # 8 MiB
SECTOR = 0x10000            # flash sector size (for the UART payload note only)
DEFAULT_VERSION = "ALiLinux"
SLED_MAX = 0x400           # leading zero words allowed before the kernel's first j/b (kernel .fill reserve)


class MkabsError(Exception):
    """A refused input or a failed check; reported without a traceback."""


# ---- CRC-32/MPEG-2: poly 0x04C11DB7, init 0xFFFFFFFF, no reflection, no xorout
_CRC_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = (((_c << 1) ^ 0x04C11DB7) if (_c & 0x80000000) else (_c << 1)) & 0xFFFFFFFF
    _CRC_TABLE.append(_c)


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    tab = _CRC_TABLE
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ tab[((crc >> 24) ^ b) & 0xFF]
    return crc


def _crc_selftest():
    assert crc32_mpeg2(b"123456789") == 0x0376E6E7, "CRC-32/MPEG-2 check value mismatch"


# ---- chunk chain --------------------------------------------------------------
def _cstr(raw):
    return raw.split(b"\0", 1)[0].decode("latin-1")


def walk_chunks(flash):
    """Chunk chain from offset 0 following the span field (+8).  Each entry:
    offset, id, length, span, crc, name, version, time."""
    chunks, off = [], 0
    while True:
        if off + HEADER_LEN > len(flash):
            raise MkabsError(f"chunk header at {off:#x} lies beyond the image ({len(flash):#x} bytes)")
        cid, length, span, crc = struct.unpack_from(">4I", flash, off)
        chunks.append({
            "offset": off, "id": cid, "length": length, "span": span, "crc": crc,
            "name": _cstr(flash[off + 16:off + 32]),
            "version": _cstr(flash[off + 32:off + 48]),
            "time": _cstr(flash[off + 48:off + 64]),
        })
        if span == 0:
            break
        if len(chunks) > 64:
            raise MkabsError("chunk chain longer than 64 entries (span loop?)")
        if off + span > len(flash):
            raise MkabsError(f"chunk at {off:#x} has span {span:#x} past the image end")
        off += span
    last = chunks[-1]
    if last["offset"] + HEADER_LEN + max(last["length"] - LENGTH_BIAS, 0) > len(flash):
        raise MkabsError("last chunk runs past the image end")
    return chunks


def find_chunk(chunks, cid):
    for c in chunks:
        if c["id"] == cid:
            return c
    return None


def chunk_crc_ok(flash, c):
    """True/False for a chunk with a CRC, None for NCRC."""
    if c["crc"] == NCRC:
        return None
    end = c["offset"] + 16 + c["length"]
    if end > len(flash):
        return False
    return crc32_mpeg2(flash[c["offset"] + 16:end]) == c["crc"]


# ---- LZMA ---------------------------------------------------------------------
def lzma_alone_encode(raw):
    """LZMA-alone stream (props 0x6C, dict 8 MiB) with the true size stored.

    liblzma's alone encoder is given no size, so it writes size=-1 and an end
    marker after the data.  The size field is overwritten with the real size;
    the end marker stays in the stream and is never reached by a decoder that
    stops at the declared size.  (The stock stream carries no marker; see
    README-mkabs.md, "LZMA stream".)"""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": LZMA_DICT, "lc": 0, "lp": 2, "pb": 2}]
    s = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=filters))
    if s[0] != LZMA_PROPS or struct.unpack_from("<I", s, 1)[0] != LZMA_DICT:
        raise MkabsError(f"liblzma wrote props {s[0]:#x} / dict {struct.unpack_from('<I', s, 1)[0]:#x}, "
                         "expected 0x6c / 0x800000")
    s[5:13] = struct.pack("<Q", len(raw))
    return bytes(s)


def lzma_alone_decode(stream, expect_size=None):
    """Decode an LZMA-alone stream using its declared size.  Returns (data, info)."""
    if len(stream) < 13:
        raise MkabsError("LZMA stream shorter than its 13-byte header")
    props = stream[0]
    info = {"props": props, "lc": props % 9, "lp": (props // 9) % 5, "pb": props // 45,
            "dict": struct.unpack_from("<I", stream, 1)[0],
            "size": struct.unpack_from("<Q", stream, 5)[0]}
    if info["size"] == 0xFFFFFFFFFFFFFFFF:
        raise MkabsError("LZMA stream has an unknown size (the loader needs an explicit size)")
    if expect_size is not None and info["size"] != expect_size:
        raise MkabsError(f"declared size {info['size']} != expected {expect_size}")
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        out = dec.decompress(stream, max_length=info["size"])
        while len(out) < info["size"] and not dec.eof and dec.needs_input is False:
            more = dec.decompress(b"", max_length=info["size"] - len(out))
            if not more:
                break
            out += more
    except lzma.LZMAError as e:
        raise MkabsError(f"LZMA decode failed: {e}")
    if len(out) != info["size"]:
        raise MkabsError(f"decoded {len(out)} bytes, declared {info['size']}")
    return out, info


def maincode_stream(flash, c):
    """The LZMA stream of a chunk: from +128 up to +16+LENGTH."""
    return flash[c["offset"] + HEADER_LEN:c["offset"] + 16 + c["length"]]


# ---- kernel checks -------------------------------------------------------------
def check_kernel(kernel, entry, skip_entry_check=False):
    """Refuse kernels the loader cannot start.  The loader jumps to LOAD_ADDR and
    runs whatever is there, so the image must begin with at most SLED_MAX bytes of
    zero words (MIPS nop), followed by the kernel's own j / b (__kernel_entry).
    Returns {"entry": target, "nop_sled": bytes} (None with --skip-entry-check)."""
    if len(kernel) < 4 or len(kernel) % 4:
        raise MkabsError(f"kernel is {len(kernel)} bytes; must be a non-empty multiple of 4 (MIPS words)")
    if len(kernel) > DECODE_LIMIT:
        raise MkabsError(f"kernel is {len(kernel)} bytes; the decoded image must end below "
                         f"{SCRATCH_BASE:#x}, i.e. at most {DECODE_LIMIT} bytes")
    if entry != LOAD_ADDR:
        raise MkabsError(f"--entry {entry:#x}: the A54 loader always jumps to {LOAD_ADDR:#x} "
                         "(a0 = 0x80000200); link the kernel there")
    if skip_entry_check:
        return None
    words = struct.unpack_from("<%dI" % (len(kernel) // 4), kernel, 0)
    i = 0
    while i < len(words) and i * 4 <= SLED_MAX and words[i] == 0:
        i += 1
    if i * 4 > SLED_MAX:
        raise MkabsError(f"the first {SLED_MAX + 4:#x} bytes at {LOAD_ADDR:#x} are not a short nop sled; "
                         "the kernel's first instruction must be within 0x400 bytes of the start")
    if i >= len(words):
        raise MkabsError("kernel has no instruction after its nop sled")
    w = words[i]
    pc = LOAD_ADDR + 4 * i
    if (w >> 26) == 0x02:                                   # j
        target = ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
    elif (w & 0xFFFF0000) == 0x10000000:                    # b (beq $0, $0)
        imm = w & 0xFFFF
        imm = imm - 0x10000 if imm & 0x8000 else imm
        target = (pc + 4 + imm * 4) & 0xFFFFFFFF
    else:
        raise MkabsError(
            f"first instruction after the nop sled, at {pc:#x}, is {w:#010x}, not a j/b to the kernel's "
            "real entry. Keep __kernel_entry (j kernel_entry) as the first real instruction "
            "(README-mkabs.md, 'Kernel entry'), or pass --skip-entry-check")
    if not (LOAD_ADDR <= target < LOAD_ADDR + len(kernel)):
        raise MkabsError(f"first jump goes to {target:#x}, outside the kernel image")
    return {"entry": target, "nop_sled": i * 4, "jump_at": pc}


# ---- image construction ---------------------------------------------------------
def fixed_str16(text, what):
    raw = text.encode("ascii")
    if len(raw) > 15:
        raise MkabsError(f"--{what} {text!r} is longer than 15 characters")
    return raw + b"\0" + b"\xff" * (15 - len(raw))


def build_maincode_chunk(donor_header, stream, name=None, version=None, time_=None):
    """The new chunk bytes: donor header (ID, span, CODESTART, ENTRY, user version
    kept) with LENGTH, CRC and the optional NAME/VERSION/TIME replaced."""
    hdr = bytearray(donor_header)
    total = HEADER_LEN + len(stream)
    struct.pack_into(">I", hdr, 4, total - 16)              # LENGTH = stream + 112
    if name is not None:
        hdr[16:32] = fixed_str16(name, "name")
    if version is not None:
        hdr[32:48] = fixed_str16(version, "version")
    if time_ is not None:
        hdr[48:64] = fixed_str16(time_, "time")
    chunk = bytearray(hdr) + stream
    struct.pack_into(">I", chunk, 12, crc32_mpeg2(bytes(chunk[16:total])))
    return bytes(chunk)


def assemble(donor, kernel, name, version, time_, entry, skip_entry_check, allow_other_layout):
    """Returns (image bytes, report dict)."""
    chunks = walk_chunks(donor)
    hash1 = chunks[0]
    if hash1["id"] != HASH1_ID:
        raise MkabsError(f"donor chunk 0 is {hash1['name']!r} (ID {hash1['id']:#010x}), not HASH1 "
                         f"({HASH1_ID:#010x}); not an A54 image")
    mc = find_chunk(chunks, MAIN_ID)
    if mc is None:
        raise MkabsError("donor has no maincode chunk (ID 0x01FE0101)")
    if mc["offset"] != EXPECT_MAIN_OFFSET and not allow_other_layout:
        raise MkabsError(f"donor maincode is at {mc['offset']:#x}, the A54 layout has it at "
                         f"{EXPECT_MAIN_OFFSET:#x} (use --allow-other-layout to override)")
    span = mc["span"]
    if span < HEADER_LEN:
        raise MkabsError(f"donor maincode span {span:#x} is too small")
    entry_info = check_kernel(kernel, entry, skip_entry_check)
    stream = lzma_alone_encode(kernel)
    total = HEADER_LEN + len(stream)
    if total > span:
        raise MkabsError(f"compressed kernel is {len(stream)} bytes; the maincode allocation (span) "
                         f"{span:#x} holds at most {span - HEADER_LEN} stream bytes. Shrink the kernel "
                         "(smaller initramfs / fewer modules / -Os) or move the chunks after maincode.")
    chunk = build_maincode_chunk(donor[mc["offset"]:mc["offset"] + HEADER_LEN], stream, name, version, time_)
    out = bytearray(donor)
    out[mc["offset"]:mc["offset"] + span] = chunk + b"\xff" * (span - total)
    report = {"kernel_bytes": len(kernel), "stream_bytes": len(stream), "LENGTH": total - 16,
              "CRC": struct.unpack_from(">I", chunk, 12)[0], "offset": mc["offset"], "span": span,
              "free_bytes": span - total, "chunk": chunk, "entry": entry_info}
    return bytes(out), report


def verify_image(flash, donor=None, kernel=None, out=sys.stdout, quiet=False):
    """Parse every chunk, print a table, return the list of failures."""
    fails = []
    try:
        chunks = walk_chunks(flash)
    except MkabsError as e:
        print(f"chain: {e}", file=out)
        return [str(e)]
    if not quiet:
        print(f"{'offset':>10}  {'name':<12} {'ID':<10} {'LENGTH':>10} {'span':>10}  {'CRC':<22} version / time", file=out)
    for c in chunks:
        ok = chunk_crc_ok(flash, c)
        if c["crc"] == NCRC:
            crc_txt = "NCRC (none)"
        elif ok:
            crc_txt = f"ok {c['crc']:08X}"
        else:
            crc_txt = f"BAD {c['crc']:08X}"
            fails.append(f"CRC mismatch on {c['name']} at {c['offset']:#x}")
        if not quiet:
            print(f"{c['offset']:#10x}  {c['name']:<12} {c['id']:#010x} {c['length']:#10x} {c['span']:#10x}  "
                  f"{crc_txt:<22} {c['version']} {c['time']}", file=out)
    mc = find_chunk(chunks, MAIN_ID)
    decoded = None
    if mc is None:
        fails.append("no maincode chunk")
    else:
        try:
            decoded, info = lzma_alone_decode(maincode_stream(flash, mc))
            if not quiet:
                print(f"maincode: props {info['props']:#04x} (lc{info['lc']} lp{info['lp']} pb{info['pb']}) "
                      f"dict {info['dict']:#x} size {info['size']} ({info['size']:#x}) "
                      f"first word {struct.unpack_from('<I', decoded, 0)[0]:#010x}", file=out)
            if info["size"] > DECODE_LIMIT:
                fails.append(f"decoded maincode {info['size']} bytes exceeds {DECODE_LIMIT}")
        except MkabsError as e:
            fails.append(f"maincode: {e}")
    if donor is not None:
        dch = walk_chunks(donor)
        if [(c["offset"], c["id"], c["span"]) for c in dch] != [(c["offset"], c["id"], c["span"]) for c in chunks]:
            fails.append("chunk layout (offset, ID, span) differs from donor")
        if len(donor) != len(flash):
            fails.append(f"size {len(flash)} differs from donor {len(donor)}")
        else:
            dmc = find_chunk(dch, MAIN_ID)
            if dmc is not None and mc is not None:
                a, b = dmc["offset"], dmc["offset"] + dmc["span"]
                same = donor[:a] == flash[:a] and donor[b:] == flash[b:]
                if not quiet:
                    print(f"bytes outside the maincode allocation {a:#x}..{b:#x} identical to donor: {same}", file=out)
                if not same:
                    fails.append("bytes outside the maincode allocation differ from donor")
    if kernel is not None:
        if decoded is None:
            fails.append("kernel comparison: no decoded maincode")
        else:
            same = decoded == kernel
            if not quiet:
                print(f"decoded maincode identical to kernel ({len(kernel)} bytes): {same}", file=out)
            if not same:
                fails.append("decoded maincode differs from kernel")
    print("VERIFY " + ("PASS" if not fails else "FAIL"), file=out)
    for f in fails:
        print(f"  - {f}", file=out)
    return fails


# ---- file helpers ---------------------------------------------------------------------
def read_file(path, what):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise MkabsError(f"cannot read {what} {path}: {e.strerror}")


def write_atomic(path, data):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".mkabs-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def refuse_same_file(out_path, *inputs):
    if not os.path.exists(out_path):
        return
    for p in inputs:
        if p and os.path.exists(p) and os.path.samefile(out_path, p):
            raise MkabsError(f"refusing to overwrite the input {p}")


# ---- commands ----------------------------------------------------------------------
def cmd_build(a):
    donor = read_file(a.donor, "donor")
    kernel = read_file(a.kernel, "kernel")
    refuse_same_file(a.out, a.donor, a.kernel)
    if a.maincode_only:
        refuse_same_file(a.maincode_only, a.donor, a.kernel)
    image, rep = assemble(donor, kernel, a.name, a.version, a.time, a.entry,
                          a.skip_entry_check, a.allow_other_layout)
    if a.check:
        with open(os.devnull, "w") as devnull:
            fails = verify_image(image, donor=donor, kernel=kernel, quiet=True, out=devnull)
        if fails:
            raise MkabsError("self-check failed: " + "; ".join(fails))
    write_atomic(a.out, image)
    if a.maincode_only:
        write_atomic(a.maincode_only, rep["chunk"])
    print(f"kernel           {rep['kernel_bytes']} bytes  sha256 {hashlib.sha256(kernel).hexdigest()}")
    e = rep["entry"]
    if e is None:
        print("entry            not checked (--skip-entry-check)")
    else:
        print(f"entry            loader jumps to {LOAD_ADDR:#x}; nop sled {e['nop_sled']:#x} bytes, "
              f"j/b at {e['jump_at']:#x} -> {e['entry']:#x}")
    print(f"stream           {rep['stream_bytes']} bytes  (LENGTH {rep['LENGTH']:#x}, CRC {rep['CRC']:08X})")
    print(f"maincode         offset {rep['offset']:#x}, span {rep['span']:#x}, free {rep['free_bytes']} bytes")
    print(f"image            {a.out}  {len(image)} bytes  sha256 {hashlib.sha256(image).hexdigest()}")
    if a.maincode_only:
        print(f"maincode-only    {a.maincode_only}  {len(rep['chunk'])} bytes (chunk header + stream)")
    if a.check:
        print("check            PASS (CRCs, decode == kernel, bytes outside maincode == donor)")
    return 0


def default_header(span=DEFAULT_SPAN, name="maincode", version=DEFAULT_VERSION, time_="2019-9-26"):
    """128-byte maincode chunk header, built from constants (no binary template): ID, LENGTH/CRC (filled in
    later), span, NAME, VERSION, TIME, rest 0xFF.  The values come from the board configuration."""
    hdr = bytearray(b"\xff" * HEADER_LEN)
    struct.pack_into(">IIII", hdr, 0, MAIN_ID, 0, span, 0)
    hdr[16:32] = fixed_str16(name, "name")
    hdr[32:48] = fixed_str16(version, "version")
    hdr[48:64] = fixed_str16(time_, "time")
    return bytes(hdr)


def board_conf(path):
    """Read MAINCODE_SPAN / _NAME / _VERSION / _TIME from a board.conf (shell-style KEY="value" lines)."""
    vals = {}
    for line in read_file(path, "board config").decode().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("MAINCODE_") and "=" in line:
            k, v = line.split("=", 1)
            vals[k] = v.strip().strip('"')
    if "MAINCODE_SPAN" not in vals:
        raise MkabsError(f"{path}: no MAINCODE_SPAN")
    return vals


def cmd_chunk(a):
    """Standalone: kernel + 128-byte header template -> maincode chunk only (no donor, no flash image)."""
    if a.header:
        hdr = read_file(a.header, "header")
    elif a.board_conf:
        v = board_conf(a.board_conf)
        hdr = default_header(int(v["MAINCODE_SPAN"], 0), v.get("MAINCODE_NAME", "maincode"),
                             v.get("MAINCODE_VERSION", DEFAULT_VERSION), v.get("MAINCODE_TIME", "2019-9-26"))
    else:
        hdr = default_header()
    kernel = read_file(a.kernel, "kernel")
    if len(hdr) != HEADER_LEN or struct.unpack_from(">I", hdr, 0)[0] != MAIN_ID:
        raise MkabsError(f"--header must be {HEADER_LEN} bytes with maincode ID {MAIN_ID:#010x}")
    span = struct.unpack_from(">I", hdr, 8)[0]
    refuse_same_file(a.chunk_out, a.header, a.kernel)
    entry_info = check_kernel(kernel, a.entry, a.skip_entry_check)
    stream = lzma_alone_encode(kernel)
    total = HEADER_LEN + len(stream)
    if total > span:
        raise MkabsError(f"compressed kernel is {len(stream)} bytes; the maincode span {span:#x} holds "
                         f"at most {span - HEADER_LEN}")
    chunk = build_maincode_chunk(hdr, stream, a.name, a.version, a.time)
    write_atomic(a.chunk_out, chunk)
    print(f"kernel           {len(kernel)} bytes  sha256 {hashlib.sha256(kernel).hexdigest()}")
    print(f"stream           {len(stream)} bytes  (CRC {struct.unpack_from('>I', chunk, 12)[0]:08X}), "
          f"span {span:#x}, free {span - total} bytes")
    print(f"maincode chunk   {a.chunk_out}  {len(chunk)} bytes  sha256 {hashlib.sha256(chunk).hexdigest()}")
    return 0


def cmd_verify(a):
    flash = read_file(a.verify, "image")
    donor = read_file(a.donor, "donor") if a.donor else None
    kernel = read_file(a.kernel, "kernel") if a.kernel else None
    fails = verify_image(flash, donor=donor, kernel=kernel)
    return 1 if fails else 0


def cmd_extract(a):
    flash = read_file(a.extract, "image")
    mc = find_chunk(walk_chunks(flash), MAIN_ID)
    if mc is None:
        raise MkabsError("no maincode chunk")
    raw, info = lzma_alone_decode(maincode_stream(flash, mc))
    if not a.out:
        raise MkabsError("--extract needs --out")
    write_atomic(a.out, raw)
    print(f"wrote {len(raw)} bytes to {a.out} (sha256 {hashlib.sha256(raw).hexdigest()})")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--donor", help="A54 .abs whose bootloader and layout are kept (required to build)")
    ap.add_argument("--kernel", help="raw kernel binary linked at 0x80000200 (objcopy -O binary)")
    ap.add_argument("--out", help="output .abs (never the donor)")
    ap.add_argument("--maincode-only", metavar="CHUNK.bin", help="also write the maincode chunk alone")
    ap.add_argument("--name", help="chunk NAME (max 15 chars); default: keep donor's 'maincode'")
    ap.add_argument("--version", default=DEFAULT_VERSION, help=f"chunk VERSION (default {DEFAULT_VERSION!r})")
    ap.add_argument("--time", help="chunk TIME string; default: keep donor's")
    ap.add_argument("--entry", default=f"{LOAD_ADDR:#x}", type=lambda s: int(s, 0),
                    help="address the kernel's first instruction runs at (must be 0x80000200)")
    ap.add_argument("--check", action="store_true", help="verify the built image before writing; fail if not PASS")
    ap.add_argument("--skip-entry-check", action="store_true", help="do not require a j/b as the first word")
    ap.add_argument("--allow-other-layout", action="store_true", help="accept a donor whose maincode is not at 0x130000")
    ap.add_argument("--header", metavar="HDR.bin", help="optional 128-byte maincode header (default: generated from constants); "
                    "with --chunk-out builds the chunk with no donor")
    ap.add_argument("--chunk-out", metavar="CHUNK.bin", help="write only the maincode chunk (needs --kernel)")
    ap.add_argument("--board-conf", metavar="board.conf",
                    help="with --chunk-out: take the chunk header layout (MAINCODE_SPAN/NAME/VERSION/TIME) from this "
                    "board configuration; no donor image is needed")
    ap.add_argument("--verify", metavar="IMAGE.abs", help="parse every chunk, print a table, exit 1 on any failure")
    ap.add_argument("--extract", metavar="IMAGE.abs", help="write the decoded maincode of IMAGE to --out")
    a = ap.parse_args(argv)
    if a.name is not None and len(a.name) > 15:
        ap.error("--name longer than 15 characters")
    try:
        if a.verify:
            return cmd_verify(a)
        if a.extract:
            return cmd_extract(a)
        if a.chunk_out:
            if not a.kernel:
                ap.error("--chunk-out needs --kernel")
            return cmd_chunk(a)
        if not (a.donor and a.kernel and a.out):
            ap.error("build needs --donor, --kernel and --out (or use --verify / --extract)")
        return cmd_build(a)
    except MkabsError as e:
        print(f"mkabs: error: {e}", file=sys.stderr)
        return 2


_crc_selftest()

if __name__ == "__main__":
    sys.exit(main())
