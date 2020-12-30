from dht import *
from random import randint
from hashlib import sha256
import csv

# a ring with 4096 IDs
d = DHT(12)
# replication degree
degree = 4
# get node and file's ID


def get_ID(input_name):
    hash_value = sha256(input_name.encode())
    hash_value = hash_value.hexdigest()
    # print(hash_value)
    # print(int(hash_value, 16))
    return int(int(hash_value, 16) % 4096)


# Add nodes
IP_file = open("data/nodes.txt")
for IP in IP_file:
    # print(IP)
    IP = IP.rstrip('\n')
    n = Node(get_ID(IP.rstrip('\n')))
    # print(n.ID)
    d.join(n)
IP_file.close()

# print("\nDHT has " + str(d._numNodes) + " nodes")


d.updateAllFingerTables()


# Store Objects
name_file = open("data/files.txt")
for name in name_file:
    # print(name.rstrip('\n'))
    name = name.rstrip('\n')
    name_ID = get_ID(name)
    d.store(d._startNode, name_ID, name, degree)

# Get all the stored item
stored_item = []
start_node = d._startNode
temp0 = [str(start_node.ID)]
temp0 = temp0 + list(start_node.data.values())
stored_item.append(temp0)
node = start_node.fingerTable[0]
while(node != start_node):
    # print(node.ID)
    temp = [str(node.ID)]
    temp = temp + list((node.data.values()))
    stored_item.append(temp)
    node = node.fingerTable[0]
    # print(node.data.values())
    # node = node.fingerTable[0]

# # print(stored_item)

# Write all the stored item into csv file
with open("ring_structure_with_rep.csv", 'w') as file:
    writer = csv.writer(file, delimiter='\t')
    for item in stored_item:
        writer.writerow(item)

# Do quries in query file
hops = []
with open("data/queries.txt") as file:
    for query in file:
        query = query.rstrip("\n")
        temp = query.split(",")
        start_IP = temp[0]
        key = temp[1]
        # First find the start node
        start_node = d.findNode(d._startNode, get_ID(start_IP))
        # print(start_node.ID)'
        # Second get the hops
        hop = d.lookup(start_node, get_ID(key), degree)
        if hop[-1] != None:
            hop_new = [node.ID for node in hop]
        else:
            hop_new = [node.ID for node in hop[:-1]]
            hop_new.append("None")
        hops.append(hop_new)

with open("routes_with_rep.csv", 'w') as file:
    writer = csv.writer(file, delimiter='\t')
    for item in hops:
        writer.writerow(item)

# print("malicious1" + str(get_ID("24.121.88.210")))
# print("malicious2" + str(get_ID("184.15.113.235")))
# print("start")
# d.lookup(d.findNode(d._startNode, 2858), get_ID("note30ef7dde.mp3"), 4)
