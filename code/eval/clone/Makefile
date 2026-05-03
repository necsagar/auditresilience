CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/clonecode

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): clonecode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
