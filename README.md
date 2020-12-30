# Emulating-Chord-Peer-to-Peer-Hash-Tables

Chord is a protocol and algorithm to peer-to-peer distributed hash tables(Wikipedia). Basically Chord describes a way to store files on different nodes based on hashes. Later, if someone wants to retrieve the file, he or she can again retrieve the file by hash. 
To increase the look up speed, fingle table is saved on each node. A fingle table is much like the idea of binary search. By storing fingle table, the search can be accomplished in O(logN) time. N is the maximum number of nodes allowed on a chord ring.
