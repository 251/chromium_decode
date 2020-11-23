LIBS = -lsqlite3 -lmbedcrypto

.PHONY: all clean

all: chromium_decode

chromium_decode:
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)

clean:
	rm -f chromium_decode
