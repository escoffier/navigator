CC = gcc
CFLAGS = -shared -fPIC
LIBS = -ldl -lssl -lcrypto
DEBUGFLAGS = -g -O0 -D_DEBUG -D READ_FROM_DISK

SRCS := preload.c log.c
EXEC = dp.so
EXTRA_CFLAGS = -std=c11 -D_XOPEN_SOURCE=700



all:
	$(CC) $(CFLAGS) -o $(EXEC) $(SRCS) $(LIBS)
	# $(CC) $(CFLAGS)  -D_HASH -o hash.so $(SRCS) $(LIBS)
	# $(CC) $(CFLAGS)  -D_TRIE -o trie.so $(SRCS) $(LIBS)

debug:
	rsync ../test/whitelist.txt.100 /tmp/whitelist.txt
	$(CC) $(DEBUGFLAGS) -D_TEST -o trie.test trie_search.c log.c $(LIBS)

test_trie:
	$(CC) -g -D_TEST -o trie.test trie_search.c log.c $(LIBS)
	rsync ../test/whitelist.txt.100 /tmp/whitelist.txt
	./trie.test
	rm -f /tmp/whitelist.txt && sync

centoscompile:
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $(EXEC) $(SRCS) $(LIBS)
	# $(CC) $(EXTRA_CFLAGS) $(CFLAGS)  -D_HASH -o hash.so $(SRCS) $(LIBS)
	# $(CC) $(EXTRA_CFLAGS) $(CFLAGS)  -D_TRIE -o trie.so $(SRCS) $(LIBS)

.PHONY: clean
clean:
	rm -f $(EXEC) *.test *.out
