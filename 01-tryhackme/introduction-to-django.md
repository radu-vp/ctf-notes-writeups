# Introduction to Django

Room Link: [Introduction to Django](https://tryhackme.com/room/django)

## High-Level Overview

This is a room containing some introductory information about Django and also has a CTF challenge.

## Tools Needed

* Nmap
* Python
* Django
* Hashes.com

## Walkthrough

We are given a set of credentials (`django-admin` - `roottoor1212`) and we are tasked with finding the 3 flags on this machine.

Initial scan of the machine using Nmap:

```bash
$ sudo nmap -sS -p- -Pn IP:ADDR
```

The following ports & services are open:

* 22 - ssh
* 8000 - http

HTTP is inaccessible from outside the internal network, however we can use the supplied credentials in order to log in on the box.

```bash
$ ssh django-admin@IP:ADDR
```

Here we can find a django project named `messagebox`. Exploring this file we can add the IP of this machine to the list of allowed hosts found in `messagebox/messagebox/settings.py`:

```python
ALLOWED_HOSTS = ['IP:ADDR', '0.0.0.0', '127.0.0.1']
```

We can now access the website but we can't log in the admin panel. 

We can enumerate users by going into the root of the `messagebox` project and opening a python3 shell using the manage.py file so we can use built-in django functions:

```bash
$ python3 manage.py shell

> from django.contrib.auth import get_user_model; User = get_user_model(); users = User.objects.all(); print(users)
```

There seem to be 3 possible users: `THMAdmin`, `Flag`, `SSH`. Now that we know some usernames, we can change their passwords using commands such as:

```bash
$ python3 manage.py changepassword THMAdmin
```

With our new `THMAdmin` password, we can log in with `THMAdmin` on the admin panel found at `http://IP_ADDR:8000/admin/`.

In the recent actions tab we can get the first flag (Admin panel flag) if we click on the edit action for the user `Flag`.

Additionally, clicking on the other recent action regarding the user SSH, we can see some personal information listed:

* Username: `StrangeFox`
* Password hash: `https://pastebin.com/nmKt4BSf`

We can easily decrypt the hash if we go to a website such as `https://hashes.com/en/decrypt/hash` or we attempt to do it on the attacking machine. Seems like the decrypted string is `WildNature`

Further exploring this machine we can see another named `StrangeFox`. In their home folder we can get the second flag (User flag). We don't even have to switch user, the `django-admin` user has sufficient privileges to read this file using the command`cat user.txt`.

Our hint for the final flag is `Did you see any identical files?`

Going to the Django project folder `messagebox` of our `django-admin` user, we can run the command `find . -type d > list.txt` to list all the items.

The `/messagebox/lmessages/templates` folder contains all the `.html` files, however there seems to be a `home.html` file in the `/messagebox/messagebox` app that does not belong there. It contains our third and final flag.