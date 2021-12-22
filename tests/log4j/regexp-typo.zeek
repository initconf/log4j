# @TEST-EXEC: zeek -C -r $TRACES/regexp-typo.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

