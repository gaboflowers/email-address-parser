CC=gcc

all: tests

tests:
	$(CC) rfc5322.c tests.c -o tests

clean:
	rm tests

.PHONY: clean
