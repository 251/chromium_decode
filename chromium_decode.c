#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/pkcs5.h>

#include <sqlite3.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static const unsigned char pass[7] = "peanuts";
static const unsigned char salt[9] = "saltysalt";
static unsigned char key[16];

static mbedtls_aes_context aes;
static mbedtls_md_context_t ctx;
static sqlite3 * db;
static sqlite3_stmt * read_stmt;


static int init_crypto() {
	const unsigned char * const ppass = pass;
	const unsigned char * const psalt = salt;
	const mbedtls_md_info_t * info;
	unsigned char * const pkey = key;

	mbedtls_md_init(&ctx);
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
	if(info == NULL)
		return 10;
	if(mbedtls_md_setup(&ctx, info, 1) != 0)
		return 11;
	if (mbedtls_pkcs5_pbkdf2_hmac(&ctx, ppass, 7, psalt, 9, 1, 16, pkey))
		return 12;

	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, key, 128);

	return 0;
}


static void cleanup_crypto() {
	mbedtls_aes_free(&aes);
	mbedtls_md_free(&ctx);
}


static int init_sqlite(const char * db_path) {
	if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 20;
	}

	if (sqlite3_prepare_v3(db, "SELECT signon_realm, username_value, password_value FROM logins;", -1, 0, &read_stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Can't prepare statement: %s\n", sqlite3_errmsg(db));
		return 21;
	}

	return 0;
}


static void cleanup_sqlite() {
	sqlite3_finalize(read_stmt);
	sqlite3_close(db);
}


static void print_row(const unsigned char * site,
                      const unsigned char * user,
                      const unsigned char * buffer, int size) {
	printf("site: %s\nuser: %s\npass: ", site, user);

	if (size <= 3) {
		puts("(none)\n");
		return;
	}

	if (strncmp("v10", (const char *)buffer, 3)) {
		puts("(not encrypted with default password)\n");
		return;
	}


	const size_t real_size = (size_t)size - 3U;
	if (real_size >= 128) {
		puts("(password too long for internal buffer)\n");
		return;
	}

	const unsigned char * const pbuf = &buffer[3];
	unsigned char iv[16] = "                ";
	unsigned char * const piv = iv;

	unsigned char decoded[128] = {0};
	unsigned char * const pdecoded = decoded;

	if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, real_size, piv, pbuf, pdecoded))
		puts("(decoding error)\n");

	for (size_t i = 0; i < real_size; ++i) {
		if (!isprint(pdecoded[i])) {
			pdecoded[i] = '\0';
			break;
		}
	}
	printf("%s\n\n", (char *)pdecoded);
}


static int read_rows() {
	int rc;
	for (;;) {
		rc = sqlite3_step(read_stmt);
		if (rc == SQLITE_ROW) {
			const unsigned char * site = sqlite3_column_text(read_stmt, 0);
			const unsigned char * user = sqlite3_column_text(read_stmt, 1);
			int size = sqlite3_column_bytes(read_stmt, 2);
			const unsigned char * blob = (const unsigned char *)sqlite3_column_blob(read_stmt, 2);
			print_row(site, user, blob, size);
		} else if (rc == SQLITE_DONE) {
			break;
		} else {
			fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
			return 22;
		}
	}
	sqlite3_reset(read_stmt);

	return 0;
}


int main(int argc, char * argv[]) {
	if (argc != 2) {
		puts("usage: chromium_decode <Login Data>");
		exit(1);
	}

	int ret = 0;
	if((ret = init_crypto()) != 0)
		exit(ret);
	if((ret = init_sqlite(argv[1])) != 0)
		exit(ret);

	ret = read_rows();

	cleanup_sqlite();
	cleanup_crypto();
	exit(ret);
}
