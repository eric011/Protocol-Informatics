
# get data
teradata1 = rdpcap("data/teradata/tcpdump-113/teradata_sel1.dump")
teradata2 = rdpcap("data/teradata/tcpdump-113/teradata_sel2.dump")
teradata3 = rdpcap("data/teradata/tcpdump-113/teradata_sel3.dump")

# get load
def get_load(packets):
    data = []
    for i in packets:
        if i.len > 60 and (i.sport == 1025 or i.dport == 1025):
            data.append(i.load)
    return data



def check_len(load):
    for i in load:
        l = len(i);
        print " 10: %d, 32: %d, 36: %d\n" % ord(i[9]) - l, ord(i[31]) - l, ord(i[35]) - l


# test offset 79
map(lambda x: len(x) - ord(x[79]), t3_load)
# get packet length, SQL length, sequence number
calc_len(t3_load[6], [[8,9],[82,81,80,79],[34,35]])

def calc_len(array, indics):
    result = []
    for i in indics:
        data = 0
        for j in i:
            data = 256 * data + ord(array[j])
        result.append(data)
    return result


def extract_sql(dump):
    #dump = rdpcap(dump_file);
    for pkt in dump:
        if pkt.type != 0x800 or pkt.len <= 60:
            continue
        pkt_cap = pkt.len
        load = pkt.load
        pkt_full = 256 * ord(load[8]) + ord(load[9])
        print "Packet Length: ", pkt.len, "full: ", pkt_full
        if len(load) < 84:
            continue;
        if ((pkt.dport == 1025) and ord(load[0]) == 3 and ord(load[1]) == 1):
            sql_len = 256 * ord(load[80]) + ord(load[79])
            print "SQL Length: ", sql_len
            sql_len = sql_len - (pkt_full - pkt_cap)
            hexdump(load[83 : 83 + sql_len - 4]);
    print "End."


        
