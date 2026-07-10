# L04 — Process Investigation

**Module:** Linux/03-Process-Internals  
**Time:** 35 minutes  
**Objective:** Use /proc to investigate running processes, find deleted binaries, detect ptrace tracing, and analyse process memory maps for anomalies.

---

## Exercise 1 — Process Enumeration via /proc

```bash
# List all running processes via /proc (bypasses ps hooks)
for pid in $(ls /proc | grep '^[0-9]'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  [ -n "$exe" ] && echo "PID:$pid | EXE:$exe | CMD:$cmdline"
done | head -30

# Compare with ps output
ps aux | wc -l
ls /proc | grep '^[0-9]' | wc -l
# Should be similar counts — difference = suspicious
```

---

## Exercise 2 — Deleted Binary Simulation

```bash
# Create a script, run it in background, then delete it
cat > /tmp/lab_process.sh << 'SCRIPT'
#!/bin/bash
while true; do sleep 5; done
SCRIPT
chmod +x /tmp/lab_process.sh

# Run in background
/tmp/lab_process.sh &
BG_PID=$!
echo "Background PID: $BG_PID"

# Delete the binary
rm /tmp/lab_process.sh

# Verify it still runs but binary is deleted
ls -la /proc/$BG_PID/exe
# Should show: /tmp/lab_process.sh (deleted)

# Recover the binary from /proc
cp /proc/$BG_PID/exe /tmp/recovered_script
file /tmp/recovered_script
cat /tmp/recovered_script

# Cleanup
kill $BG_PID
rm /tmp/recovered_script
```

---

## Exercise 3 — Memory Map Analysis

```bash
# Look at your bash shell's memory map
cat /proc/$$/maps

# Identify each region type
echo "=== Executable regions ==="
cat /proc/$$/maps | grep " r-xp"

echo "=== Writable regions ==="
cat /proc/$$/maps | grep " rw"

echo "=== Loaded libraries ==="
cat /proc/$$/maps | grep "\.so" | awk '{print $6}' | sort -u

echo "=== Anonymous mappings (no file backing) ==="
cat /proc/$$/maps | awk '$6=="" {print}'
```

---

## Exercise 4 — ptrace Detection

```bash
# Check if any process is being traced
echo "=== Processes being ptrace traced ==="
for pid in $(ls /proc | grep '^[0-9]'); do
  tracer=$(grep TracerPid /proc/$pid/status 2>/dev/null | awk '{print $2}')
  if [ -n "$tracer" ] && [ "$tracer" != "0" ]; then
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    echo "PID $pid ($exe) is traced by PID $tracer"
  fi
done

# Use strace on a simple command to see what ptrace looks like
strace -e trace=execve ls /tmp 2>&1 | head -10
# Now check the strace process — it shows as tracer
```

---

## Exercise 5 — Namespace Investigation

```bash
# Check your current namespaces
ls -la /proc/$$/ns/

# Compare with PID 1 (host namespaces)
ls -la /proc/1/ns/

# Check if running in a container
# If any namespace inode differs from PID 1 = containerized
diff <(ls -la /proc/$$/ns/ | awk '{print $1,$NF}') \
     <(ls -la /proc/1/ns/ | awk '{print $1,$NF}') 2>/dev/null || \
     echo "Namespace differences detected — may be containerized"
```

---

## Validation

```bash
# Run persistence hunter to see process-level findings
sudo bash ~/OS-Internals-for-SOC/Scripts/Linux/persistence-hunter.sh 2>/dev/null | \
  grep -A2 "VOLATILE\|DELETED\|PROCESS"
```
