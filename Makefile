all: netfilter-test

netfilter-test: netfilter-test.c
	gcc -o netfilter-test netfilter-test.c -lnetfilter_queue

clean:
	rm -f netfilter-test
