# @TEST-EXEC: zeek -C -r $TRACES/FTP-bruteforce.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

