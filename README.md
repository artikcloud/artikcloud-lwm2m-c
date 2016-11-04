# Artik Cloud LWM2M C SDK

This SDK helps developers to create C applications to connect to Artik Cloud LightWeight M2M server.

It is based on [Wakaama](README-wakaama.md) (formerly liblwm2m), to which Artik Cloud specifics are added to generate a
shared library ("libwakaama") containing read-to-use APIs to connect any device to the monitoring
features offered by the Artik Cloud LWM2M server.

Source code
-----------

The relevant code for the Artik Cloud LWM2M C SDK can be found under the following locations:
  * core: LWM2M core code for accessing and manipulating objects
  * examples/lwm2mclient: LWM2M client layer offering several APIs to expose well-known LWM2M objects
  * examples/akc_client: Sample program using the LWM2M client API to connect to the server and expose some objects

Prerequisites
-------------

The Artik Cloud LWM2M C SDK should compile and run on most UNIX based systems. It has been tested against Mac OS X, Ubuntu 16.04, and Fedora 24 (ARM). It only depends on the OpenSSL library, which is compiled along and linked as a static library. Therefore only the following build tools need to be installed before launching compilation:
  * cmake
  * gcc
  * g++
  * git

See examples below for installation on various operating systems and Linux distributions:

**Mac OS X**
~~~shell
$ sudo brew install git cmake
~~~

**Ubuntu 16.04**
~~~shell
$ sudo apt-get install git cmake gcc g++
~~~

**Fedora 24**
~~~shell
$ sudo dnf install git cmake gcc gcc-c++ make
~~~

Fetch the sources
-----------------

~~~shell
$ cd <workdir>
$ git clone https://github.com/artikcloud/artikcloud-lwm2m-c.git
~~~

Compilation
-----------

~~~shell
$ cd <workdir>/artikcloud-lwm2m-c
$ mkdir build
$ cd build
$ cmake ..
$ make
~~~

After the build completes successfully, the following binaries are generated:

  * build/examples/lwm2mclient//libwakaama-client.(so|dylib): The shared library containing the Wakaama and Artik Cloud specific code
  * build/examples/akc_client/akc_client: The Artik Cloud sample program

Run the sample program
----------------------

The **akc_client** sample program takes the following parameters:

~~~shell
Usage: akc_client [options]
	-u <server URI> : LWM2M server URI
	-d <device ID> : AKC device ID
	-t <device token> : AKC device token
	-n : don't verify SSL certificate
	-p <port> : local source port to connect from
	-h : display help
~~~

The server URL should comply with the following format depending on the protocol to use:

| Protocol | URL format                |
| -------- | --------------------------|
| UDP      | coap://hostname:port      |
| UDP/DTLS | coaps://hostname:port     |
| TCP      | coap+tcp://hostname:port  |
| TCP/TLS  | coaps+tcp://hostname:port |

The optional **noverify** parameter is used only when connecting over TCP/TLS. It overrides
the default behavior and disables the verification of the server's certificate during TLS
handshake.

Upon succesful connection to the server, a prompt is showing in the console and takes some
commands to act on the LWM2M client. Type **help** for more information:

~~~shell
> help
help    Type 'help [COMMAND]' for more details.
change  Change the value of a resource.
read    Read the value of a resource.
quit    Quit the client.
~~~

TLS Certificate management
--------------------------

When connecting to a TCP/TLS enabled LWM2M server, server certificate verification is done
by default. If you want to disable certificate verification, add the **noverify** parameter
at the end of the **akc_client** invoking command.

Certificate verification is done against trusted certificates that must be stored under a
specific keystore directory, set by default to **/usr/local/ssl/certs**. This directory can
be overriden by setting the **SSL_CERT_DIR** environment variable. To prepare the keystore 
directory, copy the certificates to consider as trusted to the directory and launch the following
command:

~~~shell
$ openssl rehash < certs dir >
~~~

Note: Replace **< certs dir >** above by the actual path you chose for the keystore directory,
or **/usr/local/ssl/certs** if you left the default value.

The **rehash** command will only work if you have OpenSSL 1.1.0 or above installed on your machine.
Otherwise you can use the one built along with the SDK as follows:

**Mac OS X**
~~~shell
$ export DYLD_LIBRARY_PATH=<workdir>/artikcloud-lwm2m-c/external/openssl
$ <workdir>/artikcloud-lwm2m-c/external/openssl/apps/openssl rehash < certs dir >
~~~

**Linux**
~~~shell
$ export LD_LIBRARY_PATH=<workdir>/artikcloud-lwm2m-c/external/openssl
$ <workdir>/artikcloud-lwm2m-c/external/openssl/apps/openssl rehash < certs dir >
~~~

Artik Cloud intermediate certificates
-------------------------------------

When using TCP/TLS connection to Artik Cloud LWM2M server, you need to have proper intermediate
certificates in the keystore in order for the server certificate verification to pass. These
certificates can be downloaded in PEM format from the following links:

VeriSign Class 3 Public Primary Certification Authority - G5: [pca3-g5ss.crt](http://www.tbs-internet.com/verisign/pca3-g5ss.crt)

Symantec Class 3 ECC 256 bit SSL CA - G2: [rc.crt](http://symantec.tbs-certificats.com/rc.crt)

Download and copy these files under **/usr/local/ssl/certs/** (or *SSL_CERT_DIR*), then run the *rehash* procedure as explained above.

LWM2M library client API
------------------------

The client library can be linked by any application that wants to take advantage of
the LWM2M client features implemented in wakaama. The application just has to link to
libwakaama-client.(so|dylib) and include "lwm2mclient.h".

The API exposed by the library is detailed here: [Client API](README-client-api.md)

More about ARTIK Cloud
----------------------

If you are not familiar with ARTIK Cloud, we have extensive documentation at https://developer.artik.cloud/documentation

The full ARTIK Cloud API specification can be found at https://developer.artik.cloud/documentation/api-reference/

Check out advanced sample applications at https://developer.artik.cloud/documentation/samples/

To create and manage your services and devices on ARTIK Cloud, create an account at https://developer.artik.cloud

Also see the ARTIK Cloud blog for tutorials, updates, and more: http://artik.io/blog/cloud

License and Copyright
---------------------

Licensed under the Eclipse Public License v1.0. See [LICENSE](http://www.eclipse.org/legal/epl-v10.html).

Copyright (c) 2016 Samsung Electronics Co., Ltd.



