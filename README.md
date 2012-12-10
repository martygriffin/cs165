Run instructions:

Open terminal

cd to project root

Run make.

cd to server directory.

Run server.
	./server <portnumber>
	./server 2008

Open second terminal

cd to project root

cd to client

run client
	./client <host>:<portnumber> <file name to request>
	./client localhost:2008 griffin.txt

If file is found on server, it will be written to a file with the same name in the client folder. If the file already exists it will be overwritten. 

Note:griffin.txt is the only file include on the server as of now.

Note: The RSA public and Private key files have been generated, the server has access to both, and the client only has the public key, the change them, generate new .pem files with opensll and replace them in the directories, naming them exactly the same.

Email marty.griffin@me.com with questions


