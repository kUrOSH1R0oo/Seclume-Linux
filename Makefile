# Makefile for Seclume
# Builds and installs the Seclume binary, linking with OpenSSL and zlib.

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lssl -lcrypto -lz -llzma

# Directories
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# Source files
SOURCES = compression.c archive.c extract.c encryption.c file_ops.c list.c seclume_main.c utils.c view_comment.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = seclume

# Default target
all: $(TARGET)

# Link object files to creat the executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install the binary to the system
install: $(TARGET)
	mkdir -p $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)
	@echo "Seclume has been successfully installed to $(BINDIR)/$(TARGET)!"
	@echo "For detailed usage, run 'seclume -h' or refer to the README.md."
	@echo "Enjoy using Seclume!"

# Uninstall the binary
uninstall:
	rm -f $(BINDIR)/$(TARGET)
	@echo "Seclume has been uninstalled from $(BINDIR)/$(TARGET)."

# Clean up build artifacts
clean:
	rm -f $(BINDIR)/$(TARGET)
	@echo "Seclume has been uninstalled from $(BINDIR)/$(TARGET)."

# Phony targets
.PHONY: all install uninstall clean
	
