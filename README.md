## About the project

`chromium_decode` is a quick hack for [Chromium](https://www.chromium.org/)
to dump the login credentials stored in `.config/chromium/Default/Login Data`.

## Usage

```bash
> chromium_decode <path/Login Data>
site: https://example.com
user: me
pass: secret
...
```

## Use case

Be aware that Chromium already has an import/export mechanism for login
credentials. This tool might come in handy when you need to recover the
data from a backup because your SSD spontaneously shredded all the
data... :disappointed:

## Limitations

* Only applicable if Chromium used its default password (`peanuts`) to store
the credentials.
* Only tested on Linux.
* Not tested with non-ASCII characters.

## Requirements

* [Mbed TLS](https://tls.mbed.org/)
* [SQLite](https://www.sqlite.org/)

## Notes

* relevant Chromium sources in `components/os_crypt/os_crypt_posix.cc`
