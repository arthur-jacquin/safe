# safe - simple symmetric-key password encrypter
# See LICENSE file for copyright and license details.

include config.mk

default: tests

tests: crypto.tests safe
	./crypto.tests
	@echo "[TESTS] All tests passed"

.PHONY: tests

clean:
	rm -f safe crypto.tests *.o safe-${VERSION}.tar.gz

.PHONY: clean

dist: clean
	mkdir -p safe-${VERSION}
	cp -R LICENSE Makefile README config.mk safe.1 \
		safe.c crypto.h crypto.c crypto.tests.c safe-${VERSION}
	tar -cf safe-${VERSION}.tar safe-${VERSION}
	gzip safe-${VERSION}.tar
	rm -rf safe-${VERSION}

.PHONY: dist

install: safe
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f safe ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	sed "s/VERSION/${VERSION}/g" < safe.1 > ${DESTDIR}${MANPREFIX}/man1/safe.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/safe.1

.PHONY: install

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/safe ${DESTDIR}${MANPREFIX}/man1/safe.1

.PHONY: uninstall

safe: %: %.o crypto.o

crypto.tests: %.tests: %.tests.c %.o

.c.o:
	${CC} ${CPPFLAGS} -DVERSION=\"${VERSION}\" ${CFLAGS} -c $<
