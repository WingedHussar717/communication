all:demo client server
demo:demo.cpp
	g++ -g demo.cpp -o demo test_mysql.cpp security.cpp -lcrypto -lmysqlclient -std=c++11
client:client.cpp
	g++ -g client.cpp -o client test_mysql.cpp security.cpp -lcrypto -lmysqlclient -std=c++11
server:server.cpp
	g++ -g server.cpp -o server test_mysql.cpp security.cpp -lcrypto -lmysqlclient -std=c++11	 

