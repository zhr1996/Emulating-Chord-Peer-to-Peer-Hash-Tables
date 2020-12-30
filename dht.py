# A Distributed Hash Table implementation

from hashlib import sha256


class Node:
    def __init__(self, ID, nxt=None, prev=None):
        self.ID = ID
        self.data = dict()
        self.prev = prev
        self.fingerTable = [nxt]

    # Update the finger table of this node when necessary
    def updateFingerTable(self, dht, k):
        del self.fingerTable[1:]
        for i in range(1, k):
            self.fingerTable.append(dht.findNode(
                dht._startNode, self.ID + 2 ** i))


class DHT:
    # The total number of IDs available in the DHT is 2 ** k
    def __init__(self, k):
        self._k = k
        self._size = 2 ** k
        self._startNode = Node(0, k)
        self._startNode.fingerTable[0] = self._startNode
        self._startNode.prev = self._startNode
        self._startNode.updateFingerTable(self, k)
        self._numNodes = 1

    # Hash function used to get the ID
    def getHashId(self, key):
        return key % self._size

    # Get distance between two IDs
    def distance(self, n1, n2):
        if n1 == n2:
            return 0
        if n1 < n2:
            return n2 - n1
        return self._size - n1 + n2

    # Get number of nodes in the system
    def getNumNodes(self):
        if self._startNode == None:
            return 0
        node = self._startNode
        n = 1
        while node.fingerTable[0] != self._startNode:
            n = n + 1
            node = node.fingerTable[0]
        return n

    # Find the node responsible for the key
    def findNode(self, start, key):
        hashId = self.getHashId(key)
        curr = start
        numJumps = 0
        while True:

            if curr.ID == hashId:
                # print("number of jumps: ", numJumps)
                return curr
            if self.distance(curr.ID, hashId) <= self.distance(curr.fingerTable[0].ID, hashId):
                # print("number of jumps: ", numJumps)
                return curr.fingerTable[0]
            tabSize = len(curr.fingerTable)
            i = 0
            nextNode = curr.fingerTable[-1]
            while i < tabSize - 1:
                if self.distance(curr.fingerTable[i].ID, hashId) < self.distance(curr.fingerTable[i + 1].ID, hashId):
                    nextNode = curr.fingerTable[i]
                i = i + 1
            curr = nextNode
            numJumps += 1

    # Custom lookup: to lookup a key and return the hops along the way
    def custom_findNode(self, start, key):
        hashId = self.getHashId(key)
        curr = start
        numJumps = 0
        # Store hops in array
        hops = []
        while True:
            hops.append(curr.ID)
            if curr.ID == hashId:
                # print("number of jumps: ", numJumps)
                hops.append(curr.ID)
                return hops
            if self.distance(curr.ID, hashId) <= self.distance(curr.fingerTable[0].ID, hashId):
                # print("number of jumps: ", numJumps)
                hops.append(curr.fingerTable[0].ID)
                return hops
            tabSize = len(curr.fingerTable)
            i = 0
            nextNode = curr.fingerTable[-1]
            while i < tabSize - 1:
                if self.distance(curr.fingerTable[i].ID, hashId) < self.distance(curr.fingerTable[i + 1].ID, hashId):
                    nextNode = curr.fingerTable[i]
                i = i + 1
            curr = nextNode
            numJumps += 1

    # Edited: design a second findnode funcion for 1b to count hops
    def custom_findNode2(self, start, key):
        hashId = self.getHashId(key)
        curr = start
        numJumps = 0
        while True:
            if curr.ID == hashId:
                # print("number of jumps: ", numJumps)
                return numJumps
            if self.distance(curr.ID, hashId) <= self.distance(curr.fingerTable[0].ID, hashId):
                # print("number of jumps: ", numJumps)
                return numJumps + 1
            tabSize = len(curr.fingerTable)
            i = 0
            nextNode = curr.fingerTable[-1]
            while i < tabSize - 1:
                if self.distance(curr.fingerTable[i].ID, hashId) < self.distance(curr.fingerTable[i + 1].ID, hashId):
                    nextNode = curr.fingerTable[i]
                i = i + 1
            curr = nextNode
            numJumps += 1

    def get_ID(self, input_name):
        hash_value = sha256(input_name.encode())
        hash_value = hash_value.hexdigest()
        # print(hash_value)
        # print(int(hash_value, 16))
        return int(int(hash_value, 16) % 4096)

    # Edited: design a third findnode function for 2 to include malicious nodes
    # Edited: return hops
    def custom_findeNode3(self, start, key):
        hashId = self.getHashId(key)
        curr = start
        numJumps = 0

        malicious1 = self.get_ID("24.121.88.210")
        malicious2 = self.get_ID("184.15.113.235")
        malicious = []
        # malicious_debug = self.get_ID("11.144.17.27")
        malicious.append(malicious1)
        malicious.append(malicious2)
        hops = []
        # print(malicious)
        # print("start")
        while True:
            # print(curr.ID)
            hops.append(curr)
            # If numJumps = 0, then malicious node is start node
            if (curr.ID in malicious) and numJumps > 0:
                hops.append(None)
                return hops

            if curr.ID == hashId:
                # print("number of jumps: ", numJumps)
                return hops

            if self.distance(curr.ID, hashId) <= self.distance(curr.fingerTable[0].ID, hashId):
                # print("number of jumps: ", numJumps)
                hops.append(curr.fingerTable[0])
                if curr.fingerTable[0].ID in malicious:
                    hops.append(None)
                return hops

            tabSize = len(curr.fingerTable)
            i = 0
            nextNode = curr.fingerTable[-1]
            while i < tabSize - 1:
                if self.distance(curr.fingerTable[i].ID, hashId) < self.distance(curr.fingerTable[i + 1].ID, hashId):
                    nextNode = curr.fingerTable[i]
                i = i + 1
            curr = nextNode
            numJumps += 1

    # Edited: so when met with malicious node, will return none
    # Edited: a lookup will look up nodes in
    # Look up a key in the DHT
    def lookup(self, start, key_ID, degree):
        # malicious1 = self.get_ID("24.121.88.210")
        # malicious2 = self.get_ID("184.15.113.235")
        # if start.ID == malicious1 or start.ID == malicious2:
        #     return None
        hops = []
        # key_ID = self.get_ID(key)
        if key_ID in start.data:
            # print("The key is in node: ", start.ID)
            return [start]

        for i in range(0, degree):
            # print("key_ID: " + str(key_ID + i * degree))

            hops = self.custom_findeNode3(
                start, (key_ID + i * (self._size/degree)) % self._size)

            # Edited so when returned with None, lookup will return none
            if hops[-1] == None:
                continue

            if key_ID in hops[-1].data:

                return hops
            else:
                # print([x.ID for x in hops])
                hops.append(None)

        return hops

    # Edited: create equally spaced replica
    # Store a key-value pair in the DHT
    def store(self, start, key, value, degree):
        for i in range(0, degree):
            nodeForKey = self.findNode(start, key + i * (self._size / degree))
            nodeForKey.data[key] = value

    # When new node joins the system

    def join(self, newNode):
        # Find the node before which the new node should be inserted
        origNode = self.findNode(self._startNode, newNode.ID)

        # print(origNode.ID, "  ", newNode.ID)
        # If there is a node with the same id, decline the join request for now
        if origNode.ID == newNode.ID:
            print("There is already a node with the same id!")
            return

        self._numNodes = self._numNodes+1

        # Copy the key-value pairs that will belong to the new node after
        # the node is inserted in the system
        for key in origNode.data:
            hashId = self.getHashId(key)
            if self.distance(hashId, newNode.ID) < self.distance(hashId, origNode.ID):
                newNode.data[key] = origNode.data[key]

        # Update the prev and next pointers
        prevNode = origNode.prev
        newNode.fingerTable[0] = origNode
        newNode.prev = prevNode
        origNode.prev = newNode
        prevNode.fingerTable[0] = newNode

        # Set up finger table of the new node
        newNode.updateFingerTable(self, self._k)

        # Delete keys that have been moved to new node
        for key in list(origNode.data.keys()):
            hashId = self.getHashId(key)
            if self.distance(hashId, newNode.ID) < self.distance(hashId, origNode.ID):
                del origNode.data[key]

    def leave(self, node):
        # Copy all its key-value pairs to its successor in the system
        for k, v in node.data.items():
            node.fingerTable[0].data[k] = v
        # If this node is the only node in the system.
        if node.fingerTable[0] == node:
            self._startNode = None
        else:
            node.prev.fingerTable[0] = node.fingerTable[0]
            node.fingerTable[0] = prev = node.prev
            # If this deleted node was an entry point to the system, we
            # need to choose another entry point. Simply choose its successor
            if self._startNode == node:
                self._startNode = node.fingerTable[0]

    def updateAllFingerTables(self):
        self._startNode.updateFingerTable(self, self._k)
        curr = self._startNode.fingerTable[0]
        while curr != self._startNode:
            curr.updateFingerTable(self, self._k)
            curr = curr.fingerTable[0]
