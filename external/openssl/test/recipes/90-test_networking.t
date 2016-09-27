#!/usr/bin/perl
# Written by Richard Levitte for the OpenSSL project.
# ====================================================================
# Copyright (c) 2015-2016 The OpenSSL Project.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
#
# 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For written permission, please contact
#    openssl-core@openssl.org.
#
# 5. Products derived from this software may not be called "OpenSSL"
#    nor may "OpenSSL" appear in their names without prior written
#    permission of the OpenSSL Project.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
#
# THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================
#
# This product includes cryptographic software written by Eric Young
# (eay@cryptsoft.com).  This product includes software written by Tim
# Hudson (tjh@cryptsoft.com).

use strict;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;

my $test_name = "test_networking";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS|MSWin32)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

$ENV{OPENSSL_ia32cap} = '~0x200000200000000';

my $proxy = TLSProxy::Proxy->new(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 2;

#Test 1: Try IPv4
$proxy->clear();
$proxy->serverflags("-4");
$proxy->clientflags("-4");
$proxy->server_addr("127.0.0.1");
$proxy->proxy_addr("127.0.0.1");
ok(check_connection(), "Trying IPv4");

 SKIP: {
     skip "No IPv6 support", 1 unless $proxy->supports_IPv6();

     #Test 2: Try IPv6
     $proxy->clear();
     $proxy->serverflags("-6");
     $proxy->clientflags("-6");
     $proxy->server_addr("[::1]");
     $proxy->proxy_addr("[::1]");
     ok(check_connection(), "Trying IPv6");
}

sub check_connection
{
    eval { $proxy->start(); };

    if ($@ ne "") {
	print STDERR "Proxy connection failed: $@\n";
	return 0;
    }

    1;
}
