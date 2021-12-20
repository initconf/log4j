# @TEST-EXEC: zeek -C -r $TRACES/multiple-name-values.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

