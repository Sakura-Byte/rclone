---
title: "rclone config encryption set"
description: "Set or change the config file encryption password"
# autogenerated - DO NOT EDIT, instead edit the source code in cmd/config/encryption/set/ and as part of making a release run "make commanddocs"
---
# rclone config encryption set

Set or change the config file encryption password

## Synopsis

This command sets or changes the config file encryption password.

If there was no config password set then it sets a new one, otherwise
it changes the existing config password.

Note that if you are changing an encryption password using
`--password-command` then this will be called once to decrypt the
config using the old password and then again to read the new
password to re-encrypt the config.

When `--password-command` is called to change the password then the
environment variable `RCLONE_PASSWORD_CHANGE=1` will be set. So if
changing passwords programmatically you can use the environment
variable to distinguish which password you must supply.

Alternatively you can remove the password first (with `rclone config
encryption remove`), then set it again with this command which may be
easier if you don't mind the unencrypted config file being on the disk
briefly.


```
rclone config encryption set [flags]
```

## Options

```
  -h, --help   help for set
```

See the [global flags page](/flags/) for global options not listed here.

## See Also

* [rclone config encryption](/commands/rclone_config_encryption/)	 - set, remove and check the encryption for the config file

