all :
	g++ -o 1m-block main.cpp -lnetfilter_queue -lsqlite3

clean :
	rm 1m-block