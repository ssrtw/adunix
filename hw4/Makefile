CXX = g++
CFLAG = -std=c++17
LIBFLAG = -lcapstone
PACK_PATH = B102011_hw4
all:
	$(CXX) $(CFLAG) main.cpp sdb.cpp $(LIBFLAG) -o hw4

zip:
	rm -rf $(PACK_PATH)
	rm -rf $(PACK_PATH).zip
	mkdir $(PACK_PATH)
	cp -t $(PACK_PATH) main.cpp sdb.cpp sdb.hpp Makefile
	zip -r $(PACK_PATH).zip $(PACK_PATH)/
	rm -rf $(PACK_PATH)