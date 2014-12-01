WPA_DECRYPTION_MPI
==================

WPA/WPA2 for cluster processing.

This program uses some code of the Aircrack-ng from Aircrack suite. The difference is that it uses MPICH for cluster
processing. 

The workflow is the next:
Each node has its own dictionary and pcap file.
Each node proccesses the dictionary until the same WPA handshake is generated.
When a node finds the correct password in the dictionary it will tell the master the password and the master will tell 
the other nodes to finish their jobs.
In case the master node finds the password first, it will tell all the nodes to finish.
If a node doesn't find a password it will wait until the finish signal is received.

Currently each node in the cluster needs its own dictionary to work, so we can improve it creating a central dictionary 
over a cloud filesystem so each node works with a certain number of passwords, if a node doesn't find any password in the 
first section, it can continue working with a new set.

Requirements:
MPICH 3
GCC 4.8 or superior
OpenSSL Devel library
Crypto Devel library

It works currently on GNU/Linux, it can probably work on other Unix system such as FreeBSD or OSX.
