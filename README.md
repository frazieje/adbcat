# adbcat
Securely bridge ADB clients &amp; servers across networks

## Why?

Have you ever been working with a remote developer or QA engineer, and needed to access their locally-connected 
ADB devices? adbcat is a tool that allows you to do just that. adbcat works across the internet and requires basically
zero setup.

## Basics

From the machine where you have adb devices connected, start sharing with adbcat:
```shell
$ adbcat
```
You'll see output something like:
```shell
$ adbcat
Starting adbcat v0.1
Running in server mode
Connected to gateway at adbcat.frazieje.com
adbcat sharing local adb server at 91a8544851cadb10869f61b069bd409a
```
Then from a remote machine where you want to access the devices, start a client and provide the sharing key:
```shell
$ adbcat 91a8544851cadb10869f61b069bd409a
```
You'll see output something like:
```shell
$ adbcat 91a8544851cadb10869f61b069bd409a
Starting adbcat v0.1
Running in client mode
Connected to gateway at adbcat.frazieje.com
adbcat sharing local adb commands to 91a8544851cadb10869f61b069bd409a
```
Now you can execute adb commands on the remote machine:
```shell
$ adb devices
List of devices attached
9A251F38298E9	device
```

## How does it work?

adbcat works by relaying data between the sharing (server) machine and the remote (client) machine through an adbcat
gateway. The adbcat gateway manages connections from clients and servers and forwards data between them as necessary.

You can start an adbcat gateway on your own server with:
```shell
$ adbcat gateway
```
You'll see output something like:
```shell
$ adbcat gateway
Starting adbcat v0.1
Running in gateway mode
```

## The adbcat gateway
By default, adb clients and servers try to access a gateway at `adbcat.frazieje.com`, but if you want 
to use your own gateway server, just make sure it's available online and use the `-h` option when starting the client
and server pieces. For example:
On your gateway machine, let's say it's hosted at adbcat.example.com:
```shell
$ adbcat gateway
```
On your sharing (server) machine:
```shell
$ adbcat -h adbcat.example.com
Starting adbcat v0.1
Running in server mode
Connected to gateway at adbcat.example.com
adbcat sharing local adb server at 91a8544851cadb10869f61b069bd409a
```
And on your client machine:
```shell
$ adbcat -h adbcat.example.com 91a8544851cadb10869f61b069bd409a
Starting adbcat v0.1
Running in client mode
Connected to gateway at adbcat.example.com
adbcat sharing local adb commands to 91a8544851cadb10869f61b069bd409a
```