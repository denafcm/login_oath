/*	$OpenBSD: login.c,v 1.10 2012/06/01 01:43:19 dlg Exp $	*/

/*-
 * Copyright (c) 1995 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Berkeley Software Design,
 *      Inc.
 * 4. The name of Berkeley Software Design, Inc.  may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN, INC. BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	BSDI $From: login_passwd.c,v 1.11 1997/08/08 18:58:24 prb Exp $
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/param.h>

#include <signal.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <login_cap.h>
#include <bsd_auth.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <err.h>
#include <util.h>

#include "oath.h"

#define MODE_LOGIN	0
#define MODE_CHALLENGE	1
#define MODE_RESPONSE	2

#define MODE_TOTP30	30
#define MODE_TOTP60	60
#define MODE_HOTP	0

#define AUTH_OK 0
#define AUTH_FAILED -1

static FILE *back = NULL;

static int authorise(struct oath_data *, char *, char *, int, int);

static int
authorise(struct oath_data *cp, char *u, char *p, int win, int totp)
{
	int ret = AUTH_FAILED;
	uint64_t nr = cp->counter;

	if (totp) 
		nr = (uint64_t) time(NULL) / totp;

#ifdef WIN_WIN
	syslog(LOG_NOTICE, "N %08qx is now\n", nr);
	nr = nr - win;
	win = win * 2;
#endif

	do {
		if (!get_otp(cp->key, nr, cp->otp, OTP_DIGITS)) {
			syslog(LOG_ERR, "get_otp error");
			return ret;
		}
#ifdef DEBUG
		syslog(LOG_NOTICE, "N %08qx (%+d) OTP %s INPUT %s\n",
		       nr, win, cp->otp, p);
#endif

		if (!strncmp(cp->pin, &p[0], PIN_LENGTH) &&
		    !strncmp(cp->otp, &p[PIN_LENGTH],
		             OTP_DIGITS)) {
			if (!totp)
				cp->counter++;
			if (upd_user(u, cp) == 0)
				ret = AUTH_OK;
			else
				syslog(LOG_ERR, "upd_user: %m");
			break;
		}
		nr++;
	} while (win--);

	return ret;
}

int
main(int argc, char **argv)
{
	int opt, mode = 0, count, ret, r;
	char *username, *password = NULL;
	char response[1024];
	char invokinguser[MAXLOGNAME];
	char *class = NULL;
	struct oath_data ctx;
	extern char *__progname;

	invokinguser[0] = '\0';

	setpriority(PRIO_PROCESS, 0, 0);

	openlog(NULL, LOG_ODELAY, LOG_AUTH);

	while ((opt = getopt(argc, argv, "ds:v:")) != -1) {
		switch (opt) {
		case 'd':
			back = stdout;
			break;
		case 's':	/* service */
			if (strcmp(optarg, "login") == 0)
				mode = MODE_LOGIN;
			else if (strcmp(optarg, "challenge") == 0)
				mode = MODE_CHALLENGE;
			else if (strcmp(optarg, "response") == 0)
				mode = MODE_RESPONSE;
			else {
				syslog(LOG_ERR, "%s: invalid service", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'v':
			if (strncmp(optarg, "invokinguser=", 13) == 0)
				snprintf(invokinguser, sizeof(invokinguser),
				         &optarg[13]);
#ifdef DEBUG
			syslog(LOG_INFO, "v-opt: %s", optarg);
#endif
			break;
		default:
			syslog(LOG_ERR, "usage error1");
			exit(EXIT_FAILURE);
		}
	}

	switch (argc - optind) {
	case 2:
		class = argv[optind + 1];
		/*FALLTHROUGH*/
	case 1:
		username = argv[optind];
		break;
	default:
		syslog(LOG_ERR, "usage error2");
		exit(EXIT_FAILURE);
	}

	if (back == NULL && (back = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "reopening back channel: %m");
		exit(EXIT_FAILURE);
	}

	/*
	 * Read password, either as from the terminal or if the
	 * response mode is active from the caller program.
	 *
	 * XXX  This is completely ungrokkable, and should be rewritten.
	 */
	switch (mode) {
	case MODE_RESPONSE:
		mode = 0;
		count = -1;
		while (++count < sizeof(response) &&
		    read(back == stdout ? STDIN_FILENO : fileno(back),
		         &response[count], (size_t)1) == (ssize_t)1) {
			if (response[count] == '\0' && ++mode == 2)
				break;
			if (response[count] == '\0' && mode == 1) 
				password = response + count + 1;
		}
		if (mode < 2) {
			syslog(LOG_ERR, "protocol error on back channel");
			exit(EXIT_FAILURE);
		}
		break;
	case MODE_LOGIN:
		password = getpass("Password:");
		break;
	case MODE_CHALLENGE:
#ifdef DEBUG
		syslog(LOG_INFO, "challenge requested");
#endif
		if (strncmp(__progname, "totp", 4) == 0 ||
		    get_user(username, &ctx)) {
			fprintf(back, BI_SILENT "\n");
		} else {
			fprintf(back, BI_VALUE " challenge H/%qx Password:" "\n",
			        ctx.counter);
			fprintf(back, BI_CHALLENGE "\n");
		}
		exit(EXIT_SUCCESS);
		break;
	default:
		syslog(LOG_ERR, "%d: unknown mode", mode);
		exit(EXIT_FAILURE);
		break;
	}

#ifdef DEBUG
	syslog(LOG_INFO, "user %s pass %s prog %s",
	       username, password, __progname);
	if (invokinguser[0] != '\0')
		syslog(LOG_INFO, "invokinguser %s", invokinguser);
#endif

	ret = AUTH_FAILED;


	if ((r = get_user(username, &ctx)) == 0) {
		if (!strcmp(__progname, "totp60"))
			mode = MODE_TOTP60;
		else if (!strncmp(__progname, "totp", 4))
			mode = MODE_TOTP30;
		else
			mode = MODE_HOTP;
		ret = authorise(&ctx, username, password, 2, mode);
	} else {
#ifdef DEBUG
		fprintf(back, BI_VALUE " errormsg get_user failed" "\n");
#endif
		if (r == -1)
			syslog(LOG_ERR, "get_user: %m");
		else
			syslog(LOG_ERR, "get_user error %d", r);
	}

	if (password != NULL)
		memset(password, 0, strlen(password));

	if (ret == AUTH_OK)
		fprintf(back, BI_SECURE "\n");
	else
		fprintf(back, BI_REJECT "\n");

	closelog();

	exit(0);
}
