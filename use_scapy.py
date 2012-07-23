

# search select SQL
for i in range(len(full_dump)):
    pkt = full_dump[i]
    if re.search("test_qixin", pkt.load):
        print i, pkt.seq, pkt.load[126:]


full_load = []
for i in range(len(full_dump)):
    d = []
    for k in full_dump[i].load:
        d.append(float(ord(k)))
    if len(d) > 120:
        full_load.append(d[:120])

def get_load(packets):
    d = []
    for i in range(len(packets)):
        d.append(packets[i].load)
    return d

def similarity(vectors):
    count = len(vectors)
    dist = []
    for i in range(count):
        d = []
        for j in range(count):
            d.append(nltk.metrics.edit_distance(vectors[i], vectors[j]))
            #print  i, j, d[j]
        dist.append(d)
    return dist

def smatrix_stats(matrix):
    data = []
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            data.append(matrix[i][j])
    print collections.Counter(data)
    pyplot.plot(sorted(data), 'o')
    pyplot.show()

def cluster_ed(similar, std):
    m = []
    for i in range(len(similar)):
        for j in range(len(similar[i])):
            if similar[i][j] == 0 or similar[i][j] > std:
                continue
            print i, j, similar[i][j]
            add_new = 1
            for t in range(len(m)):
                aset = m[t]
                if i in aset:
                    m[t].add(j)
                    add_new = 0
                    break
                elif j in aset:
                    m[t].add(i)
                    add_new = 0
                    break
            if add_new:
                m.append(set([i, j]))
    return m

def save_clusters(packets, groups, prefix):
    for i in range(len(groups)):
        filename = prefix + str(i+1)
        data = []
        for j in groups[i]:
            data.append(packets[j])
        wrpcap(filename, data);

def save_clusters_bylen(packets, bounds, prefix):
    data = []
    for i in range(len(bounds)):
        data.append([])
    for i in range(len(packets)):
        for j in range(len(bounds)):
            l = len(packets[i].load)
            if l >= bounds[j][0] and l <= bounds[j][1]:
                data[j].append(packets[i])        
    for i in range(len(bounds)):
        filename = prefix + str(i+1)
        wrpcap(filename, data[i]);


def hist_packet_len(packets):
    lens = []
    for i in range(len(packets)):
        lens.append(len(packets[i].load))
    print collections.Counter(lens)
    pyplot.plot(sorted(lens), 'o')
    pyplot.show()


select_dump = rdpcap("data/oracle_select.pcap")
sel_load = []
for pkt in select_dump:
    d = []
    for i in pkt.load:
        d.append(float(ord(i)))
    sel_load.append(d)

u = sel_load[1][:126]
for i in range(len(sel_load)):
     nltk.cluster.util.cosine_distance(sel_load[i][:126], u)
for i in range(len(sel_load)):
     nltk.metrics.edit_distance(sel_load[i][:126], u)

def cluster_block(data, start, end):
    count = len(data)
    digitized = []
    for i in range(count):
        v = []
        for j in range(len(data[i])):
            v.append(float(ord(data[i][j])))
        digitized.append(v)

def compute_distances(float_data, start, end):
    v = float_data
    count = len(v)
    # take the middle item as base
    u = v[count / 2][start : end]
    # compute distances
    dist = []
    for i in range(count):
        dist.append(nltk.cluster.util.cosine_distance(u, v[i][start : end]))
    return dist
    
