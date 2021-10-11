cstore: cstore.o 
	g++ *.cpp */*.c -o cstore

debug: DEBUG = -DDEBUG

debug: cstore

.PHONY: clean
clean:
	rm *.o cstore

PREFIX = /usr/local
export PATH := $(PREFIX)/bin:$(PATH)
.PHONY: install
install: cstore
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/cstore

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cstore

