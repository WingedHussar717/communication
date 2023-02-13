all:demo client server
demo:demo.cpp
	g++ -g demo.cpp -o demo test_mysql.cpp security.cpp -lcrypto -lmysqlclient -std=c++11
client:client.cpp
	g++ -g client.cpp -o client test_mysql.cpp security.cpp -lcrypto -lmysqlclient -std=c++11
server:server.cpp
	g++ -g epoll_server.cpp -o epoll_server test_mysql.cpp security.cpp thread_pool.cpp  -lpthread -lcrypto -lmysqlclient -std=c++11	 

