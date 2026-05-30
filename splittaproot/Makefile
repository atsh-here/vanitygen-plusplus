CC ?= cc
CFLAGS ?= -O3 -Wall -Wextra -Wno-deprecated
LIBS ?= -lcrypto -lm -lpthread

OBJS = taproot_vanitygen.o bech32.o segwit_addr.o
BIN = splittaproot_vanitygen
ORIG_REF_OBJS = original_taproot_ref.o original_simplevanitygen.o original_bech32.o original_segwit_addr.o original_util_stub.o
ORIG_REF_BIN = original_taproot_ref

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS) $(LIBS)

taproot_vanitygen.o: taproot_vanitygen.c segwit_addr.h bech32.h
bech32.o: bech32.c bech32.h
segwit_addr.o: segwit_addr.c segwit_addr.h bech32.h

run-bc1pp: $(BIN)
	./$(BIN) -1 bc1pp

cross-check: $(BIN) $(ORIG_REF_BIN)
	./test_harness.sh

clean:
	rm -f $(OBJS) $(BIN) $(ORIG_REF_OBJS) $(ORIG_REF_BIN)

.PHONY: all clean run-bc1pp cross-check

$(ORIG_REF_BIN): $(ORIG_REF_OBJS)
	$(CC) $(ORIG_REF_OBJS) -o $@ $(CFLAGS) $(LIBS)

original_taproot_ref.o: original_taproot_ref.c
	$(CC) $(CFLAGS) -I.. -c -o $@ $<

original_simplevanitygen.o: ../simplevanitygen.c
	$(CC) $(CFLAGS) -I.. -c -o $@ $<

original_bech32.o: ../bech32.c
	$(CC) $(CFLAGS) -I.. -c -o $@ $<

original_segwit_addr.o: ../segwit_addr.c
	$(CC) $(CFLAGS) -I.. -c -o $@ $<

original_util_stub.o: original_util_stub.c
	$(CC) $(CFLAGS) -I.. -c -o $@ $<
