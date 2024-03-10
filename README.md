# alulas_cpu_bruteforcer
Alula's (Perfect) CPU ECB Bruteforcer

Original non-working mess fixed by alula

The AES-NI code seems to be taken from https://gist.github.com/acapola/d5b940da024080dfaf5f

DO NOT USE ORIGINAL MAKEFILE

IT COMPILES WITHOUT OPTIMIZATIONS (THIS CODE ALSO REQUIRES SSE4.1)

Compilation: (I recommend clang).

clang brute.c -o brute -O3 -Wall -lpthread -maes -march=native -msse2 -msse -msse4.1

If you prefer gcc:

gcc brute.c -o brute -O3 -Wall -lpthread -maes -march=native -msse2 -msse -msse4.1

Usage: ./brute [num_threads]