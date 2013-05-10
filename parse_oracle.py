



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





            
