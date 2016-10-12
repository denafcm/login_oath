#ifndef _OATH_H_INCLUDED_
#define _OATH_H_INCLUDED_

#define KEY_LENGTH 10
#define PIN_LENGTH 4
#define OTP_DIGITS 6

#define PATH_DB "/var/db/oathkeys.db"

struct oath_data {
	uint64_t	counter;
	u_char		key[KEY_LENGTH];
	char		pin[PIN_LENGTH];
	char		otp[OTP_DIGITS + 1];
};

int get_user(char *, struct oath_data *);
int upd_user(char *, struct oath_data *);

int get_otp(u_char *, uint64_t, char *, int);

#endif /* _OATH_H_INCLUDED_ */


