ARTIK CLOUD (AKC) API

Source Layout
-------------
    -+- core                   (the LWM2M engine)
     |    |
     |    +- lwm2m_object        (M2M objects are here)
     +- examples
          |
          +- akc_client            (akc example)


Examples Compiling
--------
ack_clinet explame work for client with Leshan.
The following recipes assume you are on a unix like platform and you have cmake and make installed.

### akc_client example
 * Create a build directory and change to that.
 * ``cmake
 * ``make``
 * ``./ack_client``

The ack_client  have DTLS enable option.
So, Look at examples/client/README.md for an example of how
to include tinydtls.

### ack_client API
 * akc_start : starting client
 * akc_stop : stoping client

