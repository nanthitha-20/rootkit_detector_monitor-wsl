#!/bin/bash

REPORT="rootkit_hunter_report_$(date +%Y%m%d_%H%M%S).txt"
SUSPICIOUS_DIR="/var/quarantine_rootkit"
SCORE=0


EMAIL_TO="nanthithaxd@gmail.com"
EMAIL_SUBJECT="Rootkit Scan Report - $(hostname) - $(date)"


exec > >(tee -a "$REPORT") 2>&1

echo "=============================================="
echo "🛡️ Rootkit Hunter Report - $(date)"
echo "=============================================="
echo "Initial Suspicion Score: $SCORE"
echo "----------------------------------------------"


if mkdir -p "$SUSPICIOUS_DIR" 2>/dev/null; then
  echo "Quarantine directory: $SUSPICIOUS_DIR"
else
  SUSPICIOUS_DIR="$HOME/quarantine_rootkit"
  mkdir -p "$SUSPICIOUS_DIR"
  echo "Note: lacked permission for /var — using quarantine: $SUSPICIOUS_DIR"
fi



echo -e "\n[1] Scanning for hidden processes..."

ps aux > /tmp/pslist1.txt
ps -ef > /tmp/pslist2.txt

DIFF=$(diff /tmp/pslist1.txt /tmp/pslist2.txt || true)

if [ -n "$DIFF" ]; then
  echo "⚠️ Hidden process mismatch detected!"
  echo "$DIFF"
  SCORE=$((SCORE+2))
else
  echo "✅ No hidden processes detected."
fi



echo -e "\n[2] Checking for suspicious kernel modules..."

lsmod | grep -E "hide|root|kit|infect|hack|ghost" > /tmp/suspicious_mods.txt || true

if [ -s /tmp/suspicious_mods.txt ]; then
  echo "⚠️ Suspicious kernel modules found:"
  cat /tmp/suspicious_mods.txt
  SCORE=$((SCORE+3))
else
  echo "✅ No suspicious kernel modules found."
fi



echo -e "\n[3] Searching for hidden or suspicious files..."

find /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp /dev/shm -type f -name ".*" 2>/dev/null > /tmp/hidden_files.txt || true

if [ -s /tmp/hidden_files.txt ]; then
  echo "⚠️ Hidden files found:"
  cat /tmp/hidden_files.txt
  SCORE=$((SCORE+2))

  echo "Moving suspicious files to quarantine..."

  while read -r FILE; do
    [ -f "$FILE" ] || continue
    BASENAME=$(basename "$FILE")
    DST="$SUSPICIOUS_DIR/${BASENAME}_$(date +%s)"

    cp -a -- "$FILE" "$DST" 2>/dev/null && echo "Quarantined: $FILE -> $DST"

  done < /tmp/hidden_files.txt

else
  echo "✅ No hidden system files found."
fi


echo -e "\n[4] Checking for suspicious network connections..."

ss -tunap 2>/dev/null | grep -E "unknown|malware|hidden|suspicious|backdoor" > /tmp/netcheck.txt || true

if [ -s /tmp/netcheck.txt ]; then
  echo "⚠️ Suspicious network connections detected:"
  cat /tmp/netcheck.txt
  SCORE=$((SCORE+2))
else
  echo "✅ No suspicious network connections found."
fi



echo -e "\n[5] Checking for abnormal permissions or executables..."

find /bin /usr/bin /sbin /usr/sbin -perm -4000 -type f 2>/dev/null > /tmp/suid_files.txt || true

SUID_COUNT=$(wc -l < /tmp/suid_files.txt || echo 0)

echo "SUID count: $SUID_COUNT"

if [ "$SUID_COUNT" -gt 0 ]; then
  echo "List of SUID files (first 50 shown):"
  head -n 50 /tmp/suid_files.txt
else
  echo "✅ No abnormal SUID files detected."
fi

if [ "$SUID_COUNT" -gt 50 ]; then
  echo "⚠️ Excessive SUID files detected (possible risk)."
  SCORE=$((SCORE+2))
fi



echo -e "\n[6] Running external rootkit scanners..."

if command -v chkrootkit &> /dev/null; then
  echo "Running chkrootkit..."
  chkrootkit -q || true
  SCORE=$((SCORE+1))
else
  echo "ℹ️ chkrootkit not installed. Install using: sudo apt install chkrootkit"
fi

if command -v rkhunter &> /dev/null; then
  echo "Running rkhunter (may require sudo)..."
  sudo rkhunter --check --sk || true
  SCORE=$((SCORE+1))
else
  echo "ℹ️ rkhunter not installed. Install using: sudo apt install rkhunter"
fi



echo -e "\n[Summary]"

echo "Final Suspicion Score: $SCORE"

if [ "$SCORE" -ge 6 ]; then
  echo "🚨 High Suspicion – Malware/Rootkit likely. Quarantined items in: $SUSPICIOUS_DIR"

elif [ "$SCORE" -ge 3 ]; then
  echo "⚠️ Moderate Suspicion – Investigate quarantined files carefully: $SUSPICIOUS_DIR"

else
  echo "✅ System Safe – No malware indicators detected. Your environment appears clean!"
fi

echo "----------------------------------------------"
echo "Report saved to $REPORT"



echo "📧 Sending report..."

echo "Scan attached" | mutt -s "$EMAIL_SUBJECT" -a "$REPORT" -- "$EMAIL_TO"

if [ $? -eq 0 ]; then
  echo "✅ Email sent successfully to $EMAIL_TO"
else
  echo "❌ Email failed to send"
fi

echo "Scan complete."
echo "----------------------------------------------"