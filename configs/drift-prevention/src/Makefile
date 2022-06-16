CC = gcc
CFLAGS = -shared -fPIC -std=c99 -D_XOPEN_SOURCE=700
LIBS= -ldl
DEBUGFLAGS = -g -O0 -D_DEBUG

SRCS := preload.c log.c
EXEC = dp.so



all:
	$(CC) $(CFLAGS) -o $(EXEC) $(SRCS) $(LIBS)

debug:
	$(CC) $(DEBUGFLAGS) -o test $(SRCS) $(LIBS)

.PHONY: clean
clean:
	rm -f $(EXEC) *.test *.out
