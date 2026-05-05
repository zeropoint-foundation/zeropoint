#!/bin/bash

# Extract all href links from nav and check if files exist
files_to_check="theory.html whitepaper.html for-agents.html playground.html integrate.html architecture.html constraints.html footprint.html trust-triangle.html learn.html setup.html letter.html exhibits.html sentinel/"

for file in $files_to_check; do
  if [ -e "$file" ]; then
    echo "✓ $file exists"
  else
    echo "✗ $file MISSING"
  fi
done

# Check learn.html specifically links to course.html and course-sdk.html
echo ""
echo "=== learn.html internal links ==="
grep -o "href=['\"].*['\"]" /sessions/nifty-determined-turing/mnt/projects/zeropoint/zeropoint.global/learn.html | head -10
