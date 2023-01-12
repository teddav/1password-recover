# 1Password recover passwords

This is a really quick and dirty script to parse the local 1Password SQLite database where you passwords are kept encrypted.

> This is entirely based on [David Schuetz's work](https://darthnull.org/1pass-roundtrip/) ([@dschuetz](https://github.com/dschuetz)). I only copy pasted his work.  
> https://darthnull.org/1pass-roundtrip/  
> https://github.com/dschuetz/1password

## Why?

1Password unfortunately doesn't allow to make a proper encrypted backup of your passwords. Only option currently is to export an unencrypted list of your passwords 👎  
If you're a developer and know how to navigate the filesystem, you can copy the SQLite database. But the format of the file is not open source.  
@dschuetz seemed to be able to just open the file and query it like a regular SQL database, unfortunately that didn't work for me so I had to parse it manually to get the info out.

## Unfinished business...

This work is not finished 😕  
The SQLite file stores the username/password and the rest of the info (title and extra fields...) separately.
Because the parsing of the file is annoying, it should successfully extract the passwords but doesn't associate it to the rest of the data. Which seems kind of useless for now...

I haven't looked too deep in the SQLite file, but I'm sure there must be an easy way to associate the title to the password. [Here](https://darthnull.org/1pass-roundtrip/#:~:text=Decrypting%20a%20Vault%20Item) we can see that the metadata is stored in the `overview` field and the password in the `details` field of the same item.

## Instructions

Copy your 1password.sqlite file to `recover_op`  
You can find it in "~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data"

```bash
cp ~/Library/Group\ Containers/2BUA8C4S2C.com.1password/Library/Application\ Support/1Password/Data/1password.sqlite recover_op
```

Build docker image, run it, and run the `get_items.py` script:

```bash
docker build -t op .
docker run -it -w /app op
python2 get_items.py
```
