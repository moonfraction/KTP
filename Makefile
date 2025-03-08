all: library init users

library:
	$(MAKE) -f Makefile.lib

init: library
	$(MAKE) -f Makefile.init

users: library
	$(MAKE) -f Makefile.users

clean:
	$(MAKE) -f Makefile.lib clean
	$(MAKE) -f Makefile.init clean
	$(MAKE) -f Makefile.users clean
	rm -f debug*

.PHONY: all library init users clean