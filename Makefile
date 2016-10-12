PROG=	login_hotp

COPTS+=	-DDEBUG -DNULL_TERMINATED -DWIN_WIN
LDADD+=	-lssl -lcrypto -lm
OBJS=	oath.o


WARNINGS=yes
NOMAN=1

BINOWN= root
BINGRP= auth
BINMODE=2555
BINDIR=	/usr/libexec/auth

LINKS=	${BINDIR}/login_hotp ${BINDIR}/login_totp

.include <bsd.prog.mk>

backup:
		mkdir -p /tmp/nas
		mount_nfs -T -a0 fasu2:/vol/vol18/bsd /tmp/nas
		ls Makefile README *.h *.c *.py *.bak | \
			pax -wv -d -x cpio > /tmp/nas/incoming/oath.cpio
		umount -f /tmp/nas
		rmdir /tmp/nas

keys.db:	keys
		makemap btree ${@:R} < ${@:R}

