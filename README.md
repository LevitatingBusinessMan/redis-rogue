# Redis Rogue (WIP)
After making [redis-ssh](https://github.com/LevitatingBusinessMan/redis-ssh) I wanted to take it a step further and make a redis rogue server. The previously mentioned exploit was only applicable on servers where the home directory of the user running Redis was known, and contained a .ssh folder. This new exploit should be able to target far more Redis servers.

### How it works
The exploit works by telling the victim master server to become a slave of the rogue server.
After this the rogue server can overwrite all cached data and save the database to aanywhere on the system.
This way the rogue server can upload arbitrary files to the system, including uploading a RedisModule. We can then force the victim to load this module. After the malicious module has been loaded we can connect to the redis server, and run the command `pwn.revshell lhost lport`, which will give us a shell.
This works as long as the Redis version used isn't 6.x.x or newer, because this version requires every module to have executable rights before being loaded.

Included in this repository is the source of the malicious RedisModule I wrote. You can use this to write your own malicious RedisModules.

### Vulnerable hosts
For this exploit a host has to run redis with persistence enabled, no authentication. The redis version can't be 6 or higher.
The exploit has been tested on redis 5, and might work on older versions.
If the server is running Redis 6 and the configuration reveils the username of the user running it, you might want to give [redis-ssh](https://github.com/LevitatingBusinessMan/redis-ssh) a try instead.

### TODO
* Finish this readme
* Confirm ports are open and host is up
* Timeout on the connect-back
* Timeout on all receive and send commands
* Check if server is vulnerable (by checking for persistence, auth, redis version)
* Copy some features from redis-ssh (like switching from a slave to the master)
* Ability to spawn a shell and accepting it elsewhere
* Ability to insert the module without running it
* Ability to specify a module to upload
