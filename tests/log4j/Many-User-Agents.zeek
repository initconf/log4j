# @TEST-EXEC: zeek -C -r $TRACES/Many-User-Agents.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

