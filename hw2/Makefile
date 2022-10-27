CC = gcc
CFLAG = -g -Wall
SHARE_FLAG = -shared -fPIC

.PHONY: all test clean

all: logger.so logger

logger: logger.c
	$(CC) $(CFLAG) -o $@ $^ -g

logger.so: hw2.c
	$(CC) $(CFLAG) $(SHARE_FLAG) -o $@ $^ -ldl

test: logger.so logger
	./logger -p ./logger.so ls

clean:
	rm -rf logger.so logger