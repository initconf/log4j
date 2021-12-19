# @TEST-EXEC: zeek -C -r $TRACES/HTTP-POSTS.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

