## LCX Port Mapper

***

### Example diagram

***

### Version 1

this version is implemented by myself

#### Usage

```bash
-m 		choose mode,'listen' for Remote Listen,'slave' for Local Slave

Remote Listen
-p		specify inward listening port
-u		specify username and password, The username and password are separated by ':' and separated by ',' between multiple users. 

example: python port_trans.py -m listen -p 8000 -u bob:123,mary:456,Brian:7894

Local Slave
-r		Specify Remote Listen inward listening address, address and port separated by ':'.
-u		Specify the username and password. The username and password are separated by ':'.
-p		Specify the port to be opened by Remote Listen, set to 0, and randomly selected by Remote Listen.
-l		Specify the listening address, address and port of Local Server to be separated by ':'.

example: python port_trans.py -m slave -r 127.0.0.1:8000 -u Brian:789 -p 8001 -l 127.0.0.1:8002 
```

***

### Version 2

this version is implemented by teacher

#### Usage

```bash
the first parameter:	'listen' for Remote Listen,'slave' for Local Slave

Remote Listen
-p		specify inward listening port
-u		specify username and password, The username and password are separated by ':' and separated by ',' between multiple users. 

example: python b4lcx.py listen -p 8000 -u bob:123,mary:456,Brian:789

Local Slave
-r		Specify Remote Listen inward listening address, address and port separated by ':'.
-u		Specify the username and password. The username and password are separated by ':'.
-b		Specify the port to be opened by Remote Listen, set to 0, and randomly selected by Remote Listen.
-l		Specify the listening address, address and port of Local Server to be separated by ':'.

example: python b4lcx.py slave -r 127.0.0.1:8000 -u Brian:789 -b 8001 -l 127.0.0.1:8002 
```
***

### test tools

b4lcxt.py

#### Usage

```bash
-b		Bind address in remote-listen
-l		Local-server port
-s		Shut mode, c:client s:server
-t		Times for remote-client connect remote-listen(default 10)

example: python b4lcxt.py -b 127.0.0.1:8001 -l 8002 -s s -t 100
```

