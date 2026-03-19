CC      = gcc
CFLAGS  = -std=c99 -Wall -Os -I/usr/include/freetype2
LDFLAGS = -lX11 -lXft -lpam
PREFIX  = /usr/local
TARGET  = mrlogin

all: $(TARGET)

$(TARGET): mrlogin.c
	$(CC) $(CFLAGS) -o $(TARGET) mrlogin.c $(LDFLAGS)

install: $(TARGET)
	install -Dm755 $(TARGET) $(PREFIX)/bin/$(TARGET)
	install -Dm644 mrlogin.service /etc/systemd/system/mrlogin.service
	install -Dm644 mrlogin.pam /etc/pam.d/mrlogin

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -f /etc/systemd/system/mrlogin.service
	rm -f /etc/pam.d/mrlogin

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean
