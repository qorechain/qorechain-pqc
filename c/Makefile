# qorechain-pqc C binding (over liboqs).
#
# Requires liboqs (>= 0.10, FIPS-204/203) and its crypto backend (OpenSSL).
#   macOS:  brew install liboqs openssl@3
#   Linux:  build/install liboqs; apt install libssl-dev
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
OQS_CFLAGS := $(shell pkg-config --cflags liboqs 2>/dev/null)
OQS_LIBS := $(shell pkg-config --libs liboqs 2>/dev/null || echo -loqs)
CRYPTO_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS := $(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)

ALL_CFLAGS := $(CFLAGS) $(OQS_CFLAGS) $(CRYPTO_CFLAGS)
ALL_LIBS := $(OQS_LIBS) $(CRYPTO_LIBS)

.PHONY: all test clean lib
all: test

libqorechain_pqc.a: qorechain_pqc.c qorechain_pqc.h
	$(CC) $(ALL_CFLAGS) -c qorechain_pqc.c -o qorechain_pqc.o
	ar rcs $@ qorechain_pqc.o

lib: libqorechain_pqc.a

test_vectors: test_vectors.c libqorechain_pqc.a
	$(CC) $(ALL_CFLAGS) test_vectors.c libqorechain_pqc.a $(ALL_LIBS) -o $@

test: test_vectors
	./test_vectors $(if $(VECTORS),$(VECTORS),../vectors/flat.txt)

clean:
	rm -f *.o *.a test_vectors
