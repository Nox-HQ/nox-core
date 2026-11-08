#!/bin/sh
# Prints rpm.vercmp(a, b) for every "a<TAB>b" line of /w/pairs.txt, one per
# line. Run inside an rpm-based image; see vulnsource/rpm_oracle_test.go.
rpm --eval '%{lua:
for line in io.lines("/w/pairs.txt") do
  local a, b = line:match("^(.-)\t(.*)$")
  print(rpm.vercmp(a, b) .. "\n")
end
}'
