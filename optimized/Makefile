CC ?= cc
CFLAGS ?= -O3 -Wall -Wextra -Wno-deprecated
LIBS ?= -lcrypto -lm -lpthread

OBJS = taproot_optimized_vanitygen.o bech32.o segwit_addr.o
BIN = taproot_optimized_vanitygen

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS) $(LIBS)

taproot_optimized_vanitygen.o: taproot_optimized_vanitygen.c segwit_addr.h bech32.h
bech32.o: bech32.c bech32.h
segwit_addr.o: segwit_addr.c segwit_addr.h bech32.h

cross-check: $(BIN)
	./test_harness.sh

clean:
	rm -f $(OBJS) $(BIN)

.PHONY: all clean cross-check
