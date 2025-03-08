# Top-level Makefile for KTP Protocol
# Builds library, daemon, and user applications

all: library daemon applications

library:
	$(MAKE) -f Makefile.lib

daemon: library
	$(MAKE) -f Makefile.daemon

applications: library
	$(MAKE) -f Makefile.applications

clean:
	$(MAKE) -f Makefile.lib clean
	$(MAKE) -f Makefile.daemon clean
	$(MAKE) -f Makefile.applications clean
	rm -f *.o *~

.PHONY: all library daemon applications clean