all:
	clang brute.c -o brute -O3 -Wall -lpthread -maes -march=native -msse2 -msse -msse4.1
clean:
	rm brute
