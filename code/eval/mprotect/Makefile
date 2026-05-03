CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/mprotectcode

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): mprotectcode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
