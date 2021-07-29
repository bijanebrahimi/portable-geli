.PHONY: clean check

SOURCES	:= $(wildcard *.c)
OBJECTS	:= $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGET	:= geli

CFLAGS	= -Wall -I. -O2
LDFLAGS	= -lcrypto -lbsd

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) $(LDFLAGS) -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(TARGET) $(OBJECTS) key

check:
	$(MAKE) -C tests
