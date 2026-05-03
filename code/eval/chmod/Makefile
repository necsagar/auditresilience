CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/chmodcode

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): chmodcode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
