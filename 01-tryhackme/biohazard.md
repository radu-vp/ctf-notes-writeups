# Biohazard

Link: [Biohazard](https://tryhackme.com/room/biohazard)

## High-Level Overview

## Tools Needed

* Nmap
* CyberChef
* Exiftool; steghide; strings; binwalk

## Walkthrough

### Initial Scan

```bash
$ nmap -A -p- MACHINE:IP
```

Ports open:

* 21 - ftp
* 22 - ssh
* 80 - http

### Web Application

Exploring the web application, it seems it's laid out like an adventure game, each page having references to other web pages, either in comments or by making use of its functionality.

* `http://MACHINE:IP/artRoom/` has a "map" of the mansion
	* `http://MACHINEIP/artRoom/MansionMap.html`
* `http://MACHINE:IP/diningRoom/`
	* Contains a base64 encoded strings in the comments that is one of the flags
	* Has an input for a flag submission - takes the golden emblem
	* `http://MACHINE:IP/diningRoom/emblem_slot.php` - contains a string encrypted with Vignere; the key is *rebecca*
* `http://MACHINE:IP/barRoom` this is where you can use the lockpick
	* `http://MACHINE:IP/barRoom357162e3db904857963e6e0b64b96ba7/`
	* `http://MACHINE:IP/barRoom357162e3db904857963e6e0b64b96ba7/musicNote.html` - base32 encoded
	* `http://MACHINE:IP/barRoom357162e3db904857963e6e0b64b96ba7/barRoomHidden.php`
	* `http://MACHINE:IP/barRoom357162e3db904857963e6e0b64b96ba7/emblem_slot.php` - *rebecca*
* `http://MACHINE:IP/diningRoom2F` contains an encrypted message in the comments
* `http://MACHINE:IP/diningRoom/sapphire.html` contains a flag
* `http://MACHINE:IP/teaRoom/master_of_unlock.html` contains a flag
* `http://MACHINE:IP/diningRoom/the_great_shield_key.html` contains a flag
* `http://MACHINE:IP/tigerStatusRoom/gem.php` contains the note below

```
crest 1:
S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9
Hint 1: Crest 1 has been encoded twice
Hint 2: Crest 1 contanis 14 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

* Crest 1 has been encoded twice, with base64 first then with base32
	* Decoded crest 1: `RlRQIHVzZXI6IG`

* `http://MACHINE:IP/galleryRoom/note.txt` contains the note below

```
crest 2:
GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 18 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

* Crest 2 has been encoded twice, with base 32 first then with base 58
	* Decoded crest 2: `h1bnRlciwgRlRQIHBh`

* `http://1MACHINE:IP/armorRoom547845982c18936a25a9b37096b21fc1/note.txt` contains the note below

```
crest 3:
MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA=
Hint 1: Crest 3 has been encoded three times
Hint 2: Crest 3 contanis 19 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

* Crest 3 has been encoded three times, first with base 64, then binary, then hexadecimal
	* Decoded crest 3: `c3M6IHlvdV9jYW50X2h`

* `http://MACHINE:IP/attic909447f184afdfb352af8b8a25ffff1d/note.txt` contains the note below

```
crest 4:
gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 17 characters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

* Crest 4 has been encoded twice, first with base58, then binary
	* Decodec crest 4: `pZGVfZm9yZXZlcg==`
* Combined crest below:
	* `RlRQIHVzZXI6IGh1bnRlciwgRlRQIHBhc3M6IHlvdV9jYW50X2hpZGVfZm9yZXZlcg==`
	* It is encoded once with base64, decoding it gives us a username and a password for the FTP service running on this machine

### Exploiting FTP

```bash
$ ftp MACHINE:IP
# download all the files
> mget *
> exit
```

From the ftp server we have found the following files:

* 3 `.jpg` files: `001-key.jpg`, `002-key.jpg`, `003-key.jpg`
* `important.txt`
* `helmet_key.txt.gpg`

The `important.txt` file mentions of a hidden folder located at `http://MACHINE:IP/hidden_closet/`

The images provide no extra information when using `exiftool` on them however `steghide` shows the first image contains an embedded and encrypted file called `key-001.txt`

```bash
$ steghide info 001-key.jpg
$ steghide extract -sf 001-key.jpg
# hit enter when prompted for passphrase
$ cat key-001.txt
```

We extract a `.txt` file that contains the string `cGxhbnQ0Ml9jYW`

Using `strings` we can see that the second jpg file has contains the comment `5fYmVfZGVzdHJveV9`

```bash
$ strings 002-key.jpg
```

The final `.jpg` file seems to also have a `.txt` file embedded however it is passphrase protected. Using `steghide` to extract wont work, se we need to use `binwalk` instead. We identify the string `3aXRoX3Zqb2x0`

```bash
$ binwalk -e 003-key.jpg
$ cd _003-key.jpg.extracted
$ cat key-003.txt
```

Combining all the strings we get: `cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0`, which we can base64 decode to get the passphrase for the encrypted helmet file.

We can now decrypt the helmet file using `gpg`.

```bash
$ gpg helmet_key.txt.gpg
```

Now we have the helmet_key_flag.

Visiting the `/hidden_closet/` and using the helmet flag we can now see a new page at:

`http://MACHINE:IP/hiddenCloset8997e740cb7f5cece994381b9477ec38/`

We can find the SSH password here as well as a new cipher string `wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk`. This is a vigenere cipher and we can decode it without a password.

We get `ALBERT	weasker login password, stars_members_are_my_guinea_pig`

The helmet flag should also open the page at `http://MACHINE:IP/studyRoom/`. This leads us to `http://MACHINE:IP/studyRoom28341c5e98c93b89258a6389fd608a3c/` where we can download an archive called `doom.tar.gz`.

We can extract this archive and inside the `eagle_medal.txt` file we have the SSH username.

```bash
$ tar -xf doom.tar.gz
$ cat eagle_medal.txt
```

### Exploting SSH

```bash
$ ssh umbrella_client@MACHINE:IP
```

We can see an interesting folder named `.jailcell`. Inside we can find the file `chris.txt` which allows us to answer some questions in the final challenge part.

An additional interesting file is located at `/home/weasker/weasker_note.txt`

We need to login as weasker, but luckily we already know their password (`stars_members_are_my_guinea_pig`). Using this we can get the root flag. Seems like `weasker` has sudo privileges and we can upgrade the shell to root.

```bash
$ su weasker
$ sudo su
$ cat /root/root.txt
```