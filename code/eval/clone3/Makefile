CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/clone3code

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): clone3code.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
