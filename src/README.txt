-Files Submitted:
	-Client.java - class for the client
	-Server.java - class for the server
	-ServerThreads.java - class for the server threads
	-CryptoUtilities.java - class containing all the cryptographic utilities to be used

-To run the program, make sure that the server runs before the client, i.e. run the server on one CMD and then run the client on another one.
	-NOTE: make sure that the most updated version of java is run, as the code I tested only runs on the latest version, if it gives you an error, you have to copy the contents of all files into a new java file and then compile it

-The problem is fully solved

-No known bugs

-DH protocol:
	-I have implemented it simply by using the BigInteger class in java. At first I keep on generating 511 probable prime q and p while it is not of probability 3. Then after that is established, I go to my primitive root test
	function to test the current value of g, and if it doesn't pass it, then I increment g by 1, then I send p and g to the server. After that is established, I generate 2 random big integers 0< a,b < p-1 and calculate g^a in the
	client and send it to the server and calculate g^b and it to the client. After that, I simply calcuate g^ab in both classes which is the DH key used as the seed for the AES key.  