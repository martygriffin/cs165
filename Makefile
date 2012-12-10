COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto
#CXXFLAGS=-g -W -Wall -Werror -ansi -pedantic

all: ./server/ssl_server.cpp ./client/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o ./server/server ./server/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o ./client/client ./client/ssl_client.cpp $(LIBRARIES)
clean:
	rm -rf *.o a.out *~ *# Server/server Client/client Client/*.txt Server/*.o Server/*~ Server/*# Client/*.o Client/*~ Client/*#
