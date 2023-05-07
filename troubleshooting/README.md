# Troubleshooting

Attempting to solve CTFs can prove frustrating if you don't know how to troubleshoot common issues. Below are some things to try if you can't progress but you think you did everything right.

## Reverse shell fails

Things to check for in case you can't get a reverse shell to connect:

* Check if using the correct IP address (listening host)
* Check if using the correct port
* Check if your firewall isn't blocking the incoming connection using a utility like `ufw`
	* `sudo ufw disable` to disable your firewall temporarily
* Check for typos & spelling mistakes
* Check if you have the correct permissions to execute your payload (`chmod 777 /folder/payload`)
* Check if the `-e` flag is available when using `netcat`
* Check if using a common port - hardened environment might have restrictions in place for ports like `4444`, `1337`, etc;
	* Use common ports like `80`, `443,` etc.
* Check if there are any AV/EDR/Firewall products running
* If shell connects then gets closed instantly or very soon after, try to use `migrate` to migrate the session to a different process on the target

## Cookies - where are they?

When trying to exploit web applications make sure your web browser isn't blocking cookies or trackers by default. This way you can see what cookies the application normally creates and if theres a way of exploiting them, without catching the request using a proxy.

On firefox, use the address bar to search for `about:config`

Modify `privacy.purge_trackers.enabled = false`

## SSH won't let me connect

If you are trying to solve older CTF machines it is possible you might run into some issues trying to connect using SSH. To continue solving the box you must identify a mutually supported algorithm and add it to your list.

* Key Exchange Issues
	* `ssh user@host` - will display their key exchange offers
	* `ssh -Q kex` - list your available key exchange methods
	* `ssh -oKexAlgorithms=+common_supported_algorithm_name`
* Cipher Issues - connecting to a host requires a common cipher suite
	* `ssh -c matching_cipher_name user@host`