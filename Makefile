cstore: cstore.o 
	g++ *.cpp */*.c -o cstore

debug: DEBUG = -DDEBUG

debug: cstore

.PHONY: clean
clean:
	rm *.o cstore cstore_add cstore_delete cstore_extract cstore_list cstore_utils list.txt error.txt *.dSYM

PREFIX = /usr/local
export PATH := $(PREFIX)/bin:$(PATH)
.PHONY: install
install: cstore
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/cstore

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cstore

