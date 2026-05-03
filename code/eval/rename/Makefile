CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/renamecode

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): renamecode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
