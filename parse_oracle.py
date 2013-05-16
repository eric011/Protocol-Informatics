



def found_tns035e(dumpdata):
    total = len(dumpdata)
    for i in range(0, total):
        p = dumpdata[i]
        try:
            if ((p.sport == 1521) or (p.dport == 1521)) and (len(p.load) > 0):
                bytes = map(ord, p.load)
                for j in range(0, len(bytes) - 1):
                    if (bytes[j] == 3 and bytes[j+1] == 0x5e):
                        print "Found %d" % i
        except AttributeError:
            pass
    return

def filter_035e(packets):
    data = []
    for p in packets:
        bytes = map(ord, p)
        for i in range(0, len(bytes) - 1):
            if (bytes[i] == 3 and bytes[i+1] == 0x5e):
                data.append(p)
    return data


def tns035e(packet):
    try:
        if ((packet.sport == 1521 or packet.dport == 1521) and (len(packet.load) > 0)):
            # packet.show()
            bytes = map(ord, packet.load)
            for i in range(0, len(bytes) - 1):
                if (bytes[i] == 3 and bytes[i+1] == 0x5e):
                    return True
    except AttributeError:
        return False
    return False


# Usage:
# f3 = rdpcap("oracle/plsql_select.dump")
# o3 = filter(lambda x: tnsseq(x, seq1), f3)
# len(o3)
# wrpcap("select_from_a.dump", o3)
def tnsseq(packet, dataseq):
    try:
        if ((packet.sport == 1521 or packet.dport == 1521) and (len(packet.load) > 0)):
            bytes = map(ord, packet.load)
            for i in range(len(bytes) - len(dataseq)):
                match = True
                for j in range(len(dataseq)):
                    if (bytes[i + j] != dataseq[j]):
                        match = False
                        break
                if (match):
                    return True
    except AttributeError:
        return False
    return False

def bin(x):
    return ''.join(x & (1 << i) and '1' or '0' for i in range(7, -1, -1))

def locate_seq(bytes, seq):
    for i in range(len(bytes) - len(seq)):
        match = True
        for j in range(len(seq)):
            if (bytes[i+j] != seq[j]):
                match = False
                break
        if (match):
            return i
    return -1

def diff_1169_035e(packet_load, index):
    bytes = map(ord, packet_load)
    pos1 = locate_seq(bytes, [0x11, 0x69])
    pos2 = locate_seq(bytes, [0x03, 0x5e])
    if (pos1 < 0 or pos2 < 0):
        return [0, 0, 0, 0]
    return [pos2 - pos1 -2, bytes[index], pos1, pos2];

def flag1169(packets):
    arr = []
    count = 0
    for p in packets:
        ret = diff_1169_035e(p.load, 1)
        ret.append(count)
        arr.append(ret)
        count += 1
        
    arr = sorted(arr)
    return arr

def diff_035e_select(packet_load, index):
    bytes = map(ord, packet_load)
    pos1 = locate_seq(bytes, [0x03, 0x5e])
    pos2 = locate_seq(bytes, [0x73, 0x65, 0x6c, 0x65, 0x63, 0x74])
    if (pos1 < 0 or pos2 < 0):
        return None
    return [pos2 - pos1 -2, bytes[pos1 + index], pos1, pos2];

def flag035e(packets):
    arr = []
    count = 0
    for p in packets:
        ret = diff_035e_select(p.load, 1)
        if (ret):
            ret.append(count)
            arr.append(ret)
        count += 1
        
    arr = sorted(arr)
    return arr

def show_flags(arr):
    for i in range(len(arr)):
        print "%d, %4d (%s), %d" % (arr[i][0], arr[i][1], bin(arr[i][1]))
    




