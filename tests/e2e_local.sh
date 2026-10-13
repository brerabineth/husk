#!/bin/sh
# e2e_local.sh — end-to-end verification for husk.
# exercises the real binary against real files, including hostile ones.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

HUSK=./husk
TMP=test_tmp_e2e
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
check() { # check <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want='$2' got='$3')"; fi
}

rm -rf "$TMP"
mkdir -p "$TMP"

echo "husk e2e"

# 1. verdict matrix over fixtures
check "benign verdict"        "clean"      "$($HUSK --plain --no-banner fixtures/bin/benign.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "benign_static verdict" "clean"      "$($HUSK --plain --no-banner fixtures/bin/benign_static.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "ioring verdict"        "suspicious" "$($HUSK --plain --no-banner fixtures/bin/ioring.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "hollower verdict"      "suspicious" "$($HUSK --plain --no-banner fixtures/bin/hollower.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "shrouded verdict"      "suspicious" "$($HUSK --plain --no-banner fixtures/bin/shrouded.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "packed verdict"        "malicious"  "$($HUSK --plain --no-banner fixtures/bin/packed.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"
check "imposter verdict"      "critical"   "$($HUSK --plain --no-banner fixtures/bin/imposter.elf 2>/dev/null | sed -n 2p | awk '{print $1}')"

# 2. exit codes per file
$HUSK --plain --no-banner fixtures/bin/benign.elf >/dev/null 2>&1; check "exit clean"      0 $?
$HUSK --plain --no-banner fixtures/bin/ioring.elf >/dev/null 2>&1;  check "exit suspicious" 1 $?
$HUSK --plain --no-banner fixtures/bin/packed.elf >/dev/null 2>&1;  check "exit malicious"  2 $?
$HUSK --plain --no-banner fixtures/bin/imposter.elf >/dev/null 2>&1; check "exit critical"  3 $?

# 3. batch scan: aggregate exit carries the worst verdict; not-elf skipped
$HUSK --plain --no-banner fixtures/bin/ > "$TMP/batch.txt" 2>&1
check "batch exit" 3 $?
check "batch not-elf skip" "1 skipped" "$(tail -1 "$TMP/batch.txt" | grep -o '1 skipped')"
check "batch counts" "2 clean" "$(tail -1 "$TMP/batch.txt" | grep -o '2 clean')"

# 4. json output: valid per-file objects + summary
$HUSK --json fixtures/bin/ > "$TMP/out.json" 2>/dev/null
python3 - "$TMP/out.json" << 'EOF'
import json, sys
lines = [l for l in open(sys.argv[1]) if l.strip()]
objs = [json.loads(l) for l in lines]
files = [o for o in objs if "summary" not in o]
summ = [o for o in objs if "summary" in o][0]["summary"]
assert len(files) == 8 and summ["files"] == 7, f"file count {len(files)} vs {summ[chr(39)+chr(102)+chr(105)+chr(108)+chr(101)+chr(115)+chr(39)]}"
by = {o["path"].split("/")[-1]: o for o in files}
assert by["benign.elf"]["verdict"] == "clean" and by["benign.elf"]["score"] == 0
assert by["imposter.elf"]["verdict"] == "critical"
assert any(f["id"] == "H-203" for f in by["imposter.elf"]["findings"])
assert by["imposter.elf"]["hardening"]["pie"] is True
assert by["decoy.txt"]["verdict"] == "not-elf"
assert by["packed.elf"]["entropy"]["max"] > 7.5
assert len(by["benign.elf"]["needed"]) >= 1
assert by["benign.elf"]["needed"][0] == "libc.so.6"
print("json ok")
EOF
if [ $? -eq 0 ]; then ok "json structure + verdicts"; else bad "json structure"; fi

# 5. io_uring rule detail: imposter + ioring both flag H-203
$HUSK --json fixtures/bin/ioring.elf 2>/dev/null | head -1 | grep -q '"id":"H-203"'
check "io_uring rule fires" 0 $?

# 6. json hygiene: no host paths anywhere in output
if $HUSK --json fixtures/bin/ 2>/dev/null | grep -q '/home/'; then
    bad "host path leak in json"
else
    ok "json path hygiene"
fi
if $HUSK --plain --no-banner fixtures/bin/ 2>/dev/null | grep -q '/home/'; then
    bad "host path leak in term output"
else
    ok "term path hygiene"
fi

# 7. truncation resilience through the CLI (worst-case cuts)
size=$(wc -c < fixtures/bin/imposter.elf)
crash=0
for cut in 1 4 16 52 64 100 4096; do
    head -c "$cut" fixtures/bin/imposter.elf > "$TMP/cut.elf" 2>/dev/null
    $HUSK --plain --no-banner "$TMP/cut.elf" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ge 4 ] || [ "$rc" -lt 0 ]; then crash=1; fi
done
$HUSK --plain --no-banner "$TMP/cut.elf" >/dev/null 2>&1
check "truncation never crashes" 0 "$crash"

# 8. byte flips never crash
python3 - "$TMP" << 'EOF'
import random, sys
rng = random.Random(777)
src = open("fixtures/bin/imposter.elf", "rb").read()
for i in range(100):
    b = bytearray(src)
    for _ in range(12):
        b[rng.randrange(len(b))] = rng.randrange(256)
    open(f"{sys.argv[1]}/flip_{i:03d}.bin", "wb").write(bytes(b))
EOF
crash=0
for f in "$TMP"/flip_*.bin; do
    $HUSK --plain --no-banner "$f" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ge 4 ] || [ "$rc" -lt 0 ]; then crash=$((crash+1)); fi
done
check "100 byte-flip mutations, zero crashes" 0 "$crash"

# 9. missing file handled, not counted as scan
$HUSK --plain --no-banner "$TMP/does_not_exist" >/dev/null 2>&1
check "missing file exit" 0 $?

# 10. --rules listing sanity
check "rules listing" "1" "$($HUSK --rules | grep -c 'H-203')"

# 11. --version / usage
check "version" "husk 0.1.0" "$($HUSK --version)"
$HUSK >/dev/null 2>&1; check "no args usage exit" 64 $?

# 12. elf32 synthetic through the real CLI
python3 - "$TMP" << 'EOF'
import sys
e = bytearray(200)
e[0:4] = b"\x7fELF"
e[4] = 1                    # elf32
e[5] = 2                    # big endian
e[0x11] = 2                 # e_type exec
e[0x13] = 8                 # e_machine mips
e[0x1b] = 0x10              # e_entry = 0x1000 (be)
e[0x1f] = 0x34              # e_phoff = 0x34
e[0x2b] = 32                # e_phentsize = 32
e[0x2d] = 1                 # e_phnum = 1
e[0x37] = 1                 # p_type = PT_LOAD
e[0x3e] = 0x10              # p_vaddr = 0x1000 (be)
e[0x46] = 200 >> 8          # p_filesz = 200 (be)
e[0x47] = 200 & 0xff
e[0x4c] = 5                 # p_flags = R+X
open(f"{sys.argv[1]}/mips32be.elf", "wb").write(bytes(e))
EOF
check "elf32 be verdict" "suspicious" "$($HUSK --plain --no-banner "$TMP/mips32be.elf" 2>/dev/null | sed -n 2p | awk '{print $1}')"

# 13. self-scan (linux elf builds only: on macos the host binary is mach-o,
# and husk correctly refuses it as not-elf)
case "$(uname -s)" in
    Linux)
        selfv=$($HUSK --plain --no-banner $HUSK 2>/dev/null | sed -n 2p | awk '{print $1}')
        case "$selfv" in
            clean|suspicious|malicious|critical) ok "self-scan sane ($selfv — it finds its own rule strings)" ;;
            *) bad "self-scan ($selfv)" ;;
        esac
        ;;
    *)
        ok "self-scan n/a (host binary is not elf, husk must refuse it)"
        ;;
esac

echo
echo "$PASS passed, $FAIL failed"
rm -rf "$TMP"
[ "$FAIL" -eq 0 ] || exit 1
