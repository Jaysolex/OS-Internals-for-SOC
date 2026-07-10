# L06 — Memory Management & Analysis

**Module:** Linux/05-Memory-Management  
**Time:** 35 minutes  
**Objective:** Understand process memory layout, find anonymous executable mappings, detect memfd usage, and understand what attackers look for in memory.

---

## Exercise 1 — Process Memory Layout

```bash
# Examine your bash shell's full memory layout
cat /proc/$$/maps

# Label each section
echo "=== Text segment (executable code) ==="
grep " r-xp.*bash" /proc/$$/maps

echo "=== Stack ==="
grep "\[stack\]" /proc/$$/maps

echo "=== Heap ==="
grep "\[heap\]" /proc/$$/maps

echo "=== Loaded shared libraries ==="
grep "\.so" /proc/$$/maps | awk '{print $6}' | sort -u

echo "=== vDSO (kernel-provided fast syscall) ==="
grep "vdso\|vvar" /proc/$$/maps
```

---

## Exercise 2 — ASLR Verification

```bash
# Verify ASLR is active by running the same program twice
# Stack and library addresses should differ each time

cat /proc/sys/kernel/randomize_va_space
# Should be 2 (full ASLR)

# Check stack address varies between runs
for i in 1 2 3; do
  bash -c 'cat /proc/$$/maps | grep "\[stack\]"'
done
# Addresses should differ each run — ASLR working
```

---

## Exercise 3 — Find Anonymous Executable Mappings

```bash
# Scan all processes for rwx or anonymous executable mappings
# These are shellcode/injection indicators in real IR
echo "=== Anonymous executable memory regions ==="
for pid in $(ls /proc | grep '^[0-9]'); do
  maps=/proc/$pid/maps
  [ -r "$maps" ] || continue
  anon_exec=$(awk '$2~/x/ && $6=="" {print}' "$maps" 2>/dev/null)
  if [ -n "$anon_exec" ]; then
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    echo "PID $pid ($exe):"
    echo "$anon_exec"
  fi
done

echo ""
echo "Note: JIT compilers (Java, Node, Python with JIT) legitimately have these"
echo "Flag if the process is not a known JIT runtime"
```

---

## Exercise 4 — memfd_create Detection

```bash
# Check for processes with memfd in their exe path
# memfd files show as /memfd:name (deleted) in /proc/pid/exe
ls -la /proc/*/exe 2>/dev/null | grep "memfd"

# Also check maps for memfd-backed regions
for pid in $(ls /proc | grep '^[0-9]'); do
  maps=/proc/$pid/maps
  [ -r "$maps" ] || continue
  if grep -q "memfd" "$maps" 2>/dev/null; then
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    echo "PID $pid ($exe) has memfd regions:"
    grep "memfd" "$maps"
  fi
done
```

---

## Exercise 5 — Swap and Memory Forensics

```bash
# Check swap configuration
cat /proc/swaps
free -h

# Check if swap is encrypted
if [ -f /proc/swaps ]; then
  swap_dev=$(awk 'NR>1{print $1}' /proc/swaps | head -1)
  [ -n "$swap_dev" ] && cryptsetup status "$swap_dev" 2>/dev/null || \
    echo "Swap device: $swap_dev (check if encrypted)"
fi

# Memory usage overview
cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree"
```

---

## Validation

```bash
# Run log parser to check memory-related indicators
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/log-parser.sh evasion
```
