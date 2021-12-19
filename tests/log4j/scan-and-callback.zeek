# @TEST-EXEC: zeek -C -r $TRACES/scan-and-callback.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

