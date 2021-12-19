# @TEST-EXEC: zeek -C -r $TRACES/obfuscated-regexp.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

