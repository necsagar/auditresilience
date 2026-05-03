CC     = gcc
CFLAGS = -O2 -Wall

BINDIR = bin
TARGET = $(BINDIR)/execveatcode

all: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): execveatcode.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
