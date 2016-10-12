#include <sys/types.h>
#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <db.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "oath.h"

static char *separator = "| \t:";

int
get_otp(u_char *key, uint64_t counter, char *res, int num)
{
	const EVP_MD *md = EVP_sha1();
	u_char *h;
	int hlen, otp;
	int o;
	char *fmt;
	char msg[8];

	for (o = 8; o--; counter >>= 8) 
		msg[o] = counter & 0xff;

	h = HMAC(md, key, KEY_LENGTH, msg, sizeof(msg), NULL, &hlen);

	if ((h == NULL) || (hlen != EVP_MD_size(md)))
		return 0;

        o = h[19] & 15;

        otp = (((u_int)h[o]   << 24) |
               ((u_int)h[o+1] << 16) |
               ((u_int)h[o+2] << 8)  |
               ((u_int)h[o+3])) & 0x7fffffff;

	switch (num) {
	case 6: otp = otp % 1000000;   fmt = "%06d"; break;
	case 7: otp = otp % 10000000;  fmt = "%07d"; break;
	case 8: otp = otp % 100000000; fmt = "%08d"; break;
	default:
		return 0;
		break;
	}

	snprintf(res, num + 1, fmt, otp);
	/* XXX; */

	return 1;
}


static void
bytes_to_hex(u_char *in, char *out, int bytes)
{
	int i;
	u_char b;

	for (i = 0; i < bytes; i++) {
		b = (in[i] & 0xf0) >> 4;
		*out++ = b >= 0x0a ? b + 0x57 : b + 0x30;
		b = (in[i] & 0x0f);
		*out++ = b >= 0x0a ? b + 0x57 : b + 0x30;
	}
	return;
}

static int
hex_to_bytes(char *in, u_char *out, int bytes)
{
	int i;
	char c;
	u_char b;

	if (!*in)
		return 0;
	/* strlen(in) is already checked? */

	for (i = 0; i < bytes; i++) {
		b = 0;
		c = *in++; if (!(isdigit(c) || islower(c))) return 1; 
		b = (c >= 0x30 && c < 0x3a) ? (c - 0x30) << 4 : (c - 0x57) << 4;

		c = *in++; if (!(isdigit(c) || islower(c))) return 1; 
		b |= (c >= 0x30 && c < 0x3a) ? (c - 0x30) : (c - 0x57);

		out[i] = b;
	}
	return i;
}

#define MAX_DATA_LENGTH 80

int
upd_user(char *user, struct oath_data *ctx)
{
	DB *oathdb;
	DBT k, v;
	int r;

	char data[MAX_DATA_LENGTH], *d, *ep;

	oathdb = dbopen(PATH_DB, O_RDWR|O_EXLOCK, 0666, DB_BTREE, NULL);
	if (oathdb == NULL)
		return -1;

	k.data = user;
	k.size = strlen(user);

	d = data;
	ep = data + sizeof(data);

	memcpy(d, ctx->pin, PIN_LENGTH); d += PIN_LENGTH;
	
	*d = *separator; d += 1;
	bytes_to_hex(ctx->key, d, KEY_LENGTH); d += KEY_LENGTH << 1;

	*d = *separator; d += 1;
	snprintf(d, ep - d, "%016qx", ctx->counter); d += 16;

	v.data = data;
	v.size = d - data;

	r = oathdb->put(oathdb, &k, &v, 0);
	oathdb->close(oathdb);

	return r;
}

int
get_user(char *user, struct oath_data *ctx)
{
	DB *oathdb;
	DBT k, v;
	int r;
	char *s, *tok;

	char data[MAX_DATA_LENGTH + 1000];

	if (!user)
		return 2;

	oathdb = dbopen(PATH_DB, O_RDWR|O_EXLOCK, 0666, DB_BTREE, NULL);
	if (oathdb == NULL)
		return -1;

	k.data = user;
#ifdef NULL_TERMINATED
	k.size = strlen(user) + 1;
#else
	k.size = strlen(user);
#endif
	v.size = 0;

	if ((r = oathdb->get(oathdb, &k, &v, 0))) {
		oathdb->close(oathdb);
		return r;
	}
	if (!v.size || v.size >= (MAX_DATA_LENGTH - 1)) {
		oathdb->close(oathdb);
		return 3;
	}

	strncpy(data, v.data, v.size);
#ifndef NULL_TERMINATED
	data[v.size] = '\0';
#endif
	oathdb->close(oathdb);

#ifdef DEBUG2
	puts(data);
#endif

	tok = data;
	s = strsep(&tok, separator);
	if (!s)
		return 4;
	if (strlen(s) != PIN_LENGTH)
		return 5;
	memcpy(ctx->pin, s, PIN_LENGTH);

	s = strsep(&tok, separator);
	if (!s || strlen(s) != (KEY_LENGTH * 2))
		return 6;

	if (!hex_to_bytes(s, ctx->key, KEY_LENGTH)) 
		return 7;

	if ((s = strsep(&tok, separator)) == NULL)
		return 8;

	ctx->counter = strtoull(s, (char **)NULL, 16);

	return 0;
}

#ifdef MAIN

int
main()
{
	int r;
	struct oath_data ctx;

	memset(&ctx, 0, sizeof(ctx));
	r = get_user("john", &ctx);
	if (r == -1)
		err(1, "check_user");
	if (r != 0)
		errx(2, "get_user returned %d", r);

	printf("Key ");
	for (r = 0; r < KEY_LENGTH; r++)
		printf("%02x ", ctx.key[r]);
	putchar('\n');
	printf("Counter 0x%qx\n", ctx.counter);
	printf("Pin ");
	for (r = 0; r < PIN_LENGTH; r++)
		printf("%c ", ctx.pin[r]);
	putchar('\n');

	if (!get_otp(ctx.key, ctx.counter, ctx.otp, OTP_DIGITS))
		errx(3, "get otp error");

	puts(ctx.otp);

	ctx.counter++;
	upd_user("lindroos", &ctx);

	return 0;
}
#endif /* MAIN */

