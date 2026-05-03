CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET  = $(BINDIR)/killcode
TARGET1 = $(BINDIR)/killcode_inv

all: $(TARGET) $(TARGET1)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): killcode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

$(TARGET1): killcode_invalid.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)