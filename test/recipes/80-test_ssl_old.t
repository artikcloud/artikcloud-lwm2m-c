#! /usr/bin/perl

use strict;
use warnings;

use POSIX;
use File::Spec;
use File::Copy;
use OpenSSL::Test qw/:DEFAULT with bldtop_file srctop_file cmdstr/;
use OpenSSL::Test::Utils;

setup("test_ssl");

$ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");

my ($no_rsa, $no_dsa, $no_dh, $no_ec, $no_srp, $no_psk,
    $no_ssl3, $no_tls1, $no_tls1_1, $no_tls1_2,
    $no_dtls, $no_dtls1, $no_dtls1_2, $no_ct) =
    anydisabled qw/rsa dsa dh ec srp psk
                   ssl3 tls1 tls1_1 tls1_2
                   dtls dtls1 dtls1_2 ct/;
my $no_anytls = alldisabled(available_protocols("tls"));
my $no_anydtls = alldisabled(available_protocols("dtls"));

plan skip_all => "No SSL/TLS/DTLS protocol is support by this OpenSSL build"
    if $no_anytls && $no_anydtls;

my $digest = "-sha1";
my @reqcmd = ("openssl", "req");
my @x509cmd = ("openssl", "x509", $digest);
my @verifycmd = ("openssl", "verify");
my $dummycnf = srctop_file("apps", "openssl.cnf");

my $CAkey = "keyCA.ss";
my $CAcert="certCA.ss";
my $CAserial="certCA.srl";
my $CAreq="reqCA.ss";
my $CAconf=srctop_file("test","CAss.cnf");
my $CAreq2="req2CA.ss";	# temp

my $Uconf=srctop_file("test","Uss.cnf");
my $Ukey="keyU.ss";
my $Ureq="reqU.ss";
my $Ucert="certU.ss";

my $Dkey="keyD.ss";
my $Dreq="reqD.ss";
my $Dcert="certD.ss";

my $Ekey="keyE.ss";
my $Ereq="reqE.ss";
my $Ecert="certE.ss";

my $P1conf=srctop_file("test","P1ss.cnf");
my $P1key="keyP1.ss";
my $P1req="reqP1.ss";
my $P1cert="certP1.ss";
my $P1intermediate="tmp_intP1.ss";

my $P2conf=srctop_file("test","P2ss.cnf");
my $P2key="keyP2.ss";
my $P2req="reqP2.ss";
my $P2cert="certP2.ss";
my $P2intermediate="tmp_intP2.ss";

my $server_sess="server.ss";
my $client_sess="client.ss";

# ssltest_old.c is deprecated in favour of the new framework in ssl_test.c
# If you're adding tests here, you probably want to convert them to the
# new format in ssl_test.c and add recipes to 80-test_ssl_new.t instead.
plan tests =>
    1				# For testss
    + 1				# For ssltest_old -test_cipherlist
    + 14			# For the first testssl
    + 16			# For the first testsslproxy
    + 16			# For the second testsslproxy
    ;

subtest 'test_ss' => sub {
    if (testss()) {
	open OUT, ">", "intP1.ss";
	copy($CAcert, \*OUT); copy($Ucert, \*OUT);
	close OUT;

	open OUT, ">", "intP2.ss";
	copy($CAcert, \*OUT); copy($Ucert, \*OUT); copy($P1cert, \*OUT);
	close OUT;
    }
};

my $check = ok(run(test(["ssltest_old","-test_cipherlist"])), "running ssltest_old");

  SKIP: {
      skip "ssltest_old ended with error, skipping the rest", 3
	  if !$check;

      note('test_ssl -- key U');
      testssl("keyU.ss", $Ucert, $CAcert);

      note('test_ssl -- key P1');
      testsslproxy("keyP1.ss", "certP1.ss", "intP1.ss", "AB");

      note('test_ssl -- key P2');
      testsslproxy("keyP2.ss", "certP2.ss", "intP2.ss", "BC");
    }

# -----------
# subtest functions
sub testss {
    open RND, ">>", ".rnd";
    print RND "string to make the random number generator think it has entropy";
    close RND;

    my @req_dsa = ("-newkey",
                   "dsa:".srctop_file("apps", "dsa1024.pem"));
    my @req_new;
    if ($no_rsa) {
	@req_new = @req_dsa;
    } else {
	@req_new = ("-new");
    }

    plan tests => 17;

  SKIP: {
      skip 'failure', 16 unless
	  ok(run(app([@reqcmd, "-config", $CAconf,
		      "-out", $CAreq, "-keyout", $CAkey,
		      @req_new])),
	     'make cert request');

      skip 'failure', 15 unless
	  ok(run(app([@x509cmd, "-CAcreateserial", "-in", $CAreq, "-days", "30",
		      "-req", "-out", $CAcert, "-signkey", $CAkey,
		      "-extfile", $CAconf, "-extensions", "v3_ca"],
		     stdout => "err.ss")),
	     'convert request into self-signed cert');

      skip 'failure', 14 unless
	  ok(run(app([@x509cmd, "-in", $CAcert,
		      "-x509toreq", "-signkey", $CAkey, "-out", $CAreq2],
		     stdout => "err.ss")),
	     'convert cert into a cert request');

      skip 'failure', 13 unless
	  ok(run(app([@reqcmd, "-config", $dummycnf,
		      "-verify", "-in", $CAreq, "-noout"])),
	     'verify request 1');


      skip 'failure', 12 unless
	  ok(run(app([@reqcmd, "-config", $dummycnf,
		      "-verify", "-in", $CAreq2, "-noout"])),
	     'verify request 2');

      skip 'failure', 11 unless
	  ok(run(app([@verifycmd, "-CAfile", $CAcert, $CAcert])),
	     'verify signature');

      skip 'failure', 10 unless
	  ok(run(app([@reqcmd, "-config", $Uconf,
		      "-out", $Ureq, "-keyout", $Ukey, @req_new],
		     stdout => "err.ss")),
	     'make a user cert request');

      skip 'failure', 9 unless
	  ok(run(app([@x509cmd, "-CAcreateserial", "-in", $Ureq, "-days", "30",
		      "-req", "-out", $Ucert,
		      "-CA", $CAcert, "-CAkey", $CAkey, "-CAserial", $CAserial,
		      "-extfile", $Uconf, "-extensions", "v3_ee"],
		     stdout => "err.ss"))
	     && run(app([@verifycmd, "-CAfile", $CAcert, $Ucert])),
	     'sign user cert request');

      skip 'failure', 8 unless
	  ok(run(app([@x509cmd,
		      "-subject", "-issuer", "-startdate", "-enddate",
		      "-noout", "-in", $Ucert])),
	     'Certificate details');

      skip 'failure', 7 unless
          subtest 'DSA certificate creation' => sub {
              plan skip_all => "skipping DSA certificate creation"
                  if $no_dsa;

              plan tests => 4;

            SKIP: {
                $ENV{CN2} = "DSA Certificate";
                skip 'failure', 3 unless
                    ok(run(app([@reqcmd, "-config", $Uconf,
                                "-out", $Dreq, "-keyout", $Dkey,
                                @req_dsa],
                               stdout => "err.ss")),
                       "make a DSA user cert request");
                skip 'failure', 2 unless
                    ok(run(app([@x509cmd, "-CAcreateserial",
                                "-in", $Dreq,
                                "-days", "30",
                                "-req",
                                "-out", $Dcert,
                                "-CA", $CAcert, "-CAkey", $CAkey,
                                "-CAserial", $CAserial,
                                "-extfile", $Uconf,
                                "-extensions", "v3_ee_dsa"],
                               stdout => "err.ss")),
                       "sign DSA user cert request");
                skip 'failure', 1 unless
                    ok(run(app([@verifycmd, "-CAfile", $CAcert, $Dcert])),
                       "verify DSA user cert");
                skip 'failure', 0 unless
                    ok(run(app([@x509cmd,
                                "-subject", "-issuer",
                                "-startdate", "-enddate", "-noout",
                                "-in", $Dcert])),
                       "DSA Certificate details");
              }
      };

      skip 'failure', 6 unless
          subtest 'ECDSA/ECDH certificate creation' => sub {
              plan skip_all => "skipping ECDSA/ECDH certificate creation"
                  if $no_ec;

              plan tests => 5;

            SKIP: {
                $ENV{CN2} = "ECDSA Certificate";
                skip 'failure', 4 unless
                    ok(run(app(["openssl", "ecparam", "-name", "P-256",
                                "-out", "ecp.ss"])),
                       "make EC parameters");
                skip 'failure', 3 unless
                    ok(run(app([@reqcmd, "-config", $Uconf,
                                "-out", $Ereq, "-keyout", $Ekey,
                                "-newkey", "ec:ecp.ss"],
                               stdout => "err.ss")),
                       "make a ECDSA/ECDH user cert request");
                skip 'failure', 2 unless
                    ok(run(app([@x509cmd, "-CAcreateserial",
                                "-in", $Ereq,
                                "-days", "30",
                                "-req",
                                "-out", $Ecert,
                                "-CA", $CAcert, "-CAkey", $CAkey,
                                "-CAserial", $CAserial,
                                "-extfile", $Uconf,
                                "-extensions", "v3_ee_ec"],
                               stdout => "err.ss")),
                       "sign ECDSA/ECDH user cert request");
                skip 'failure', 1 unless
                    ok(run(app([@verifycmd, "-CAfile", $CAcert, $Ecert])),
                       "verify ECDSA/ECDH user cert");
                skip 'failure', 0 unless
                    ok(run(app([@x509cmd,
                                "-subject", "-issuer",
                                "-startdate", "-enddate", "-noout",
                                "-in", $Ecert])),
                       "ECDSA Certificate details");
              }
      };

      skip 'failure', 5 unless
	  ok(run(app([@reqcmd, "-config", $P1conf,
		      "-out", $P1req, "-keyout", $P1key, @req_new],
		     stdout => "err.ss")),
	     'make a proxy cert request');


      skip 'failure', 4 unless
	  ok(run(app([@x509cmd, "-CAcreateserial", "-in", $P1req, "-days", "30",
		      "-req", "-out", $P1cert,
		      "-CA", $Ucert, "-CAkey", $Ukey,
		      "-extfile", $P1conf, "-extensions", "v3_proxy"],
		     stdout => "err.ss")),
	     'sign proxy with user cert');

      copy($Ucert, $P1intermediate);
      run(app([@verifycmd, "-CAfile", $CAcert,
	       "-untrusted", $P1intermediate, $P1cert]));
      ok(run(app([@x509cmd,
		  "-subject", "-issuer", "-startdate", "-enddate",
		  "-noout", "-in", $P1cert])),
	 'Certificate details');

      skip 'failure', 2 unless
	  ok(run(app([@reqcmd, "-config", $P2conf,
		      "-out", $P2req, "-keyout", $P2key,
		      @req_new],
		     stdout => "err.ss")),
	     'make another proxy cert request');


      skip 'failure', 1 unless
	  ok(run(app([@x509cmd, "-CAcreateserial", "-in", $P2req, "-days", "30",
		      "-req", "-out", $P2cert,
		      "-CA", $P1cert, "-CAkey", $P1key,
		      "-extfile", $P2conf, "-extensions", "v3_proxy"],
		     stdout => "err.ss")),
	     'sign second proxy cert request with the first proxy cert');


      open OUT, ">", $P2intermediate;
      copy($Ucert, \*OUT); copy($P1cert, \*OUT);
      close OUT;
      run(app([@verifycmd, "-CAfile", $CAcert,
	       "-untrusted", $P2intermediate, $P2cert]));
      ok(run(app([@x509cmd,
		  "-subject", "-issuer", "-startdate", "-enddate",
		  "-noout", "-in", $P2cert])),
	 'Certificate details');
    }
}

sub testssl {
    my $key = shift || bldtop_file("apps","server.pem");
    my $cert = shift || bldtop_file("apps","server.pem");
    my $CAtmp = shift;
    my @CA = $CAtmp ? ("-CAfile", $CAtmp) : ("-CApath", bldtop_dir("certs"));
    my @extra = @_;

    my @ssltest = ("ssltest_old",
		   "-s_key", $key, "-s_cert", $cert,
		   "-c_key", $key, "-c_cert", $cert);

    my $serverinfo = srctop_file("test","serverinfo.pem");

    my $dsa_cert = 0;
    if (grep /DSA Public Key/, run(app(["openssl", "x509", "-in", $cert,
					"-text", "-noout"]), capture => 1)) {
	$dsa_cert = 1;
    }


    # plan tests => 11;

    subtest 'standard SSL tests' => sub {
	######################################################################
	plan tests => 29;

      SKIP: {
	  skip "SSLv3 is not supported by this OpenSSL build", 4
	      if disabled("ssl3");

	  ok(run(test([@ssltest, "-ssl3", @extra])),
	     'test sslv3');
	  ok(run(test([@ssltest, "-ssl3", "-server_auth", @CA, @extra])),
	     'test sslv3 with server authentication');
	  ok(run(test([@ssltest, "-ssl3", "-client_auth", @CA, @extra])),
	     'test sslv3 with client authentication');
	  ok(run(test([@ssltest, "-ssl3", "-server_auth", "-client_auth", @CA, @extra])),
	     'test sslv3 with both server and client authentication');
	}

      SKIP: {
	  skip "Neither SSLv3 nor any TLS version are supported by this OpenSSL build", 4
	      if $no_anytls;

	  ok(run(test([@ssltest, @extra])),
	     'test sslv2/sslv3');
	  ok(run(test([@ssltest, "-server_auth", @CA, @extra])),
	     'test sslv2/sslv3 with server authentication');
	  ok(run(test([@ssltest, "-client_auth", @CA, @extra])),
	     'test sslv2/sslv3 with client authentication');
	  ok(run(test([@ssltest, "-server_auth", "-client_auth", @CA, @extra])),
	     'test sslv2/sslv3 with both server and client authentication');
	}

      SKIP: {
	  skip "SSLv3 is not supported by this OpenSSL build", 4
	      if disabled("ssl3");

	  ok(run(test([@ssltest, "-bio_pair", "-ssl3", @extra])),
	     'test sslv3 via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-ssl3", "-server_auth", @CA, @extra])),
	     'test sslv3 with server authentication via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-ssl3", "-client_auth", @CA, @extra])),
	     'test sslv3 with client authentication via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-ssl3", "-server_auth", "-client_auth", @CA, @extra])),
	     'test sslv3 with both server and client authentication via BIO pair');
	}

      SKIP: {
	  skip "Neither SSLv3 nor any TLS version are supported by this OpenSSL build", 1
	      if $no_anytls;

	  ok(run(test([@ssltest, "-bio_pair", @extra])),
	     'test sslv2/sslv3 via BIO pair');
	}

      SKIP: {
	  skip "DTLSv1 is not supported by this OpenSSL build", 4
	      if disabled("dtls1");

	  ok(run(test([@ssltest, "-dtls1", @extra])),
	     'test dtlsv1');
	  ok(run(test([@ssltest, "-dtls1", "-server_auth", @CA, @extra])),
	   'test dtlsv1 with server authentication');
	  ok(run(test([@ssltest, "-dtls1", "-client_auth", @CA, @extra])),
	     'test dtlsv1 with client authentication');
	  ok(run(test([@ssltest, "-dtls1", "-server_auth", "-client_auth", @CA, @extra])),
	     'test dtlsv1 with both server and client authentication');
	}

      SKIP: {
	  skip "DTLSv1.2 is not supported by this OpenSSL build", 4
	      if disabled("dtls1_2");

	  ok(run(test([@ssltest, "-dtls12", @extra])),
	     'test dtlsv1.2');
	  ok(run(test([@ssltest, "-dtls12", "-server_auth", @CA, @extra])),
	     'test dtlsv1.2 with server authentication');
	  ok(run(test([@ssltest, "-dtls12", "-client_auth", @CA, @extra])),
	     'test dtlsv1.2 with client authentication');
	  ok(run(test([@ssltest, "-dtls12", "-server_auth", "-client_auth", @CA, @extra])),
	     'test dtlsv1.2 with both server and client authentication');
	}

      SKIP: {
	  skip "Neither SSLv3 nor any TLS version are supported by this OpenSSL build", 8
	      if $no_anytls;

	SKIP: {
	    skip "skipping test of sslv2/sslv3 w/o (EC)DHE test", 1 if $dsa_cert;

	    ok(run(test([@ssltest, "-bio_pair", "-no_dhe", "-no_ecdhe", @extra])),
	       'test sslv2/sslv3 w/o (EC)DHE via BIO pair');
	  }

	  ok(run(test([@ssltest, "-bio_pair", "-dhe1024dsa", "-v", @extra])),
	     'test sslv2/sslv3 with 1024bit DHE via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-server_auth", @CA, @extra])),
	     'test sslv2/sslv3 with server authentication');
	  ok(run(test([@ssltest, "-bio_pair", "-client_auth", @CA, @extra])),
	     'test sslv2/sslv3 with client authentication via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-server_auth", "-client_auth", @CA, @extra])),
	     'test sslv2/sslv3 with both client and server authentication via BIO pair');
	  ok(run(test([@ssltest, "-bio_pair", "-server_auth", "-client_auth", "-app_verify", @CA, @extra])),
	     'test sslv2/sslv3 with both client and server authentication via BIO pair and app verify');

        SKIP: {
            skip "No IPv4 available on this machine", 1
                unless !disabled("sock") && have_IPv4();
            ok(run(test([@ssltest, "-ipv4", @extra])),
               'test TLS via IPv4');
          }

        SKIP: {
            skip "No IPv6 available on this machine", 1
                unless !disabled("sock") && have_IPv6();
            ok(run(test([@ssltest, "-ipv6", @extra])),
               'test TLS via IPv6');
          }
        }
    };

    subtest "Testing ciphersuites" => sub {

        my @exkeys = ();
        my $ciphers = "-EXP:-PSK:-SRP:-kDH:-kECDHe";

        if ($no_dh) {
            note "skipping DHE tests\n";
            $ciphers .= ":-kDHE";
        }
        if ($no_dsa) {
            note "skipping DSA tests\n";
            $ciphers .= ":-aDSA";
        } else {
            push @exkeys, "-s_cert", "certD.ss", "-s_key", "keyD.ss";
        }

        if ($no_ec) {
            note "skipping EC tests\n";
            $ciphers .= ":!aECDSA:!kECDH";
        } else {
            push @exkeys, "-s_cert", "certE.ss", "-s_key", "keyE.ss";
        }

	my @protocols = ();
	# FIXME: I feel unsure about the following line, is that really just TLSv1.2, or is it all of the SSLv3/TLS protocols?
        push(@protocols, "TLSv1.2") unless $no_tls1_2;
        push(@protocols, "SSLv3") unless $no_ssl3;
	my $protocolciphersuitcount = 0;
	my %ciphersuites =
	    map { my @c =
		      map { split(/:/, $_) }
		      run(app(["openssl", "ciphers", "${_}:$ciphers"]),
                          capture => 1);
		  map { s/\R//; } @c;  # chomp @c;
		  $protocolciphersuitcount += scalar @c;
		  $_ => [ @c ] } @protocols;

        plan skip_all => "None of the ciphersuites to test are available in this OpenSSL build"
            if $protocolciphersuitcount + scalar(@protocols) == 0;

        # The count of protocols is because in addition to the ciphersuits
        # we got above, we're running a weak DH test for each protocol
	plan tests => $protocolciphersuitcount + scalar(@protocols);

	foreach my $protocol (@protocols) {
	    note "Testing ciphersuites for $protocol";
	    foreach my $cipher (@{$ciphersuites{$protocol}}) {
		ok(run(test([@ssltest, @exkeys, "-cipher", $cipher,
			     $protocol eq "SSLv3" ? ("-ssl3") : ()])),
		   "Testing $cipher");
	    }
            is(run(test([@ssltest,
                         "-s_cipher", "EDH",
                         "-c_cipher", 'EDH:@SECLEVEL=1',
                         "-dhe512",
                         $protocol eq "SSLv3" ? ("-ssl3") : ()])), 0,
               "testing connection with weak DH, expecting failure");
	}
    };

    subtest 'RSA/(EC)DHE/PSK tests' => sub {
	######################################################################

	plan tests => 5;

      SKIP: {
	  skip "TLSv1.0 is not supported by this OpenSSL build", 5
	      if $no_tls1;

	SKIP: {
	    skip "skipping anonymous DH tests", 1
	      if ($no_dh);

	    ok(run(test([@ssltest, "-v", "-bio_pair", "-tls1", "-cipher", "ADH", "-dhe1024dsa", "-num", "10", "-f", "-time", @extra])),
	       'test tlsv1 with 1024bit anonymous DH, multiple handshakes');
	  }

	SKIP: {
	    skip "skipping RSA tests", 2
		if $no_rsa;

	    ok(run(test(["ssltest_old", "-v", "-bio_pair", "-tls1", "-s_cert", srctop_file("apps","server2.pem"), "-no_dhe", "-no_ecdhe", "-num", "10", "-f", "-time", @extra])),
	       'test tlsv1 with 1024bit RSA, no (EC)DHE, multiple handshakes');

	    skip "skipping RSA+DHE tests", 1
		if $no_dh;

	    ok(run(test(["ssltest_old", "-v", "-bio_pair", "-tls1", "-s_cert", srctop_file("apps","server2.pem"), "-dhe1024dsa", "-num", "10", "-f", "-time", @extra])),
	       'test tlsv1 with 1024bit RSA, 1024bit DHE, multiple handshakes');
	  }

	SKIP: {
	    skip "skipping PSK tests", 2
	        if ($no_psk);

	    ok(run(test([@ssltest, "-tls1", "-cipher", "PSK", "-psk", "abc123", @extra])),
	       'test tls1 with PSK');

	    ok(run(test([@ssltest, "-bio_pair", "-tls1", "-cipher", "PSK", "-psk", "abc123", @extra])),
	       'test tls1 with PSK via BIO pair');
	  }
	}

    };

    subtest 'Next Protocol Negotiation Tests' => sub {
	######################################################################

	plan tests => 7;

      SKIP: {
	  skip "TLSv1.0 is not supported by this OpenSSL build", 7
	      if $no_tls1;
	  skip "Next Protocol Negotiation is not supported by this OpenSSL build", 7
	      if disabled("nextprotoneg");

	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_client"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_server"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_server_reject"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_client", "-npn_server_reject"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_client", "-npn_server"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_client", "-npn_server", "-num", "2"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-npn_client", "-npn_server", "-num", "2", "-reuse"])));
	}
    };

    subtest 'Custom Extension tests' => sub {
	######################################################################

	plan tests => 1;

      SKIP: {
	  skip "TLSv1.0 is not supported by this OpenSSL build", 1
	      if $no_tls1;

	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-custom_ext"])),
	     'test tls1 with custom extensions');
	}
    };

    subtest 'Serverinfo tests' => sub {
	######################################################################

	plan tests => 5;

      SKIP: {
	  skip "TLSv1.0 is not supported by this OpenSSL build", 5
	      if $no_tls1;

	  note('echo test tls1 with serverinfo');
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-serverinfo_file", $serverinfo])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-serverinfo_file", $serverinfo, "-serverinfo_sct"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-serverinfo_file", $serverinfo, "-serverinfo_tack"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-serverinfo_file", $serverinfo, "-serverinfo_sct", "-serverinfo_tack"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-custom_ext", "-serverinfo_file", $serverinfo, "-serverinfo_sct", "-serverinfo_tack"])));
	}
    };

    subtest 'SNI tests' => sub {

	plan tests => 7;

      SKIP: {
	  skip "TLSv1.x is not supported by this OpenSSL build", 7
	      if $no_tls1 && $no_tls1_1 && $no_tls1_2;

	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-sn_server1", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "foo", "-sn_server1", "foo", "-sn_expect1"])));
	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "foo", "-sn_server1", "bar", "-sn_expect1"])));
	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "foo", "-sn_server1", "foo", "-sn_server2", "bar", "-sn_expect1"])));
	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "bar", "-sn_server1", "foo", "-sn_server2", "bar", "-sn_expect2"])));
	  # Negative test - make sure it doesn't crash, and doesn't switch contexts
	  ok(run(test([@ssltest, "-bio_pair", "-sn_client", "foobar", "-sn_server1", "foo", "-sn_server2", "bar", "-sn_expect1"])));
	}
    };

    subtest 'ALPN tests' => sub {
	######################################################################

	plan tests => 13;

      SKIP: {
	  skip "TLSv1.0 is not supported by this OpenSSL build", 13
	      if $no_tls1;

	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_server", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "foo", "-alpn_server", "foo", "-alpn_expected", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "foo,bar", "-alpn_server", "foo", "-alpn_expected", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "bar,foo", "-alpn_server", "foo", "-alpn_expected", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "bar,foo", "-alpn_server", "foo,bar", "-alpn_expected", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "bar,foo", "-alpn_server", "bar,foo", "-alpn_expected", "bar"])));
	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "foo,bar", "-alpn_server", "bar,foo", "-alpn_expected", "bar"])));

	  is(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "foo", "-alpn_server", "bar"])), 0,
             "Testing ALPN with protocol mismatch, expecting failure");
	  is(run(test([@ssltest, "-bio_pair", "-tls1", "-alpn_client", "baz", "-alpn_server", "bar,foo"])), 0,
             "Testing ALPN with protocol mismatch, expecting failure");

	  # ALPN + SNI
	  ok(run(test([@ssltest, "-bio_pair",
		       "-alpn_client", "foo,bar", "-sn_client", "alice",
		       "-alpn_server1", "foo,123", "-sn_server1", "alice",
		       "-alpn_server2", "bar,456", "-sn_server2", "bob",
		       "-alpn_expected", "foo"])));
	  ok(run(test([@ssltest, "-bio_pair",
		       "-alpn_client", "foo,bar", "-sn_client", "bob",
		       "-alpn_server1", "foo,123", "-sn_server1", "alice",
		       "-alpn_server2", "bar,456", "-sn_server2", "bob",
		       "-alpn_expected", "bar"])));
	  ok(run(test([@ssltest, "-bio_pair",
		       "-alpn_client", "foo,bar", "-sn_client", "bob",
		       "-alpn_server2", "bar,456", "-sn_server2", "bob",
		       "-alpn_expected", "bar"])));
	}
    };

    subtest 'SRP tests' => sub {

	plan tests => 4;

      SKIP: {
	  skip "skipping SRP tests", 4
	      if $no_srp;

	  ok(run(test([@ssltest, "-tls1", "-cipher", "SRP", "-srpuser", "test", "-srppass", "abc123"])),
	     'test tls1 with SRP');

	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-cipher", "SRP", "-srpuser", "test", "-srppass", "abc123"])),
	     'test tls1 with SRP via BIO pair');

	  ok(run(test([@ssltest, "-tls1", "-cipher", "aSRP", "-srpuser", "test", "-srppass", "abc123"])),
	     'test tls1 with SRP auth');

	  ok(run(test([@ssltest, "-bio_pair", "-tls1", "-cipher", "aSRP", "-srpuser", "test", "-srppass", "abc123"])),
	     'test tls1 with SRP auth via BIO pair');
	}
    };

    subtest 'Multi-buffer tests' => sub {
	######################################################################

	plan tests => 2;

      SKIP: {
	  skip "Neither SSLv3 nor any TLS version are supported by this OpenSSL build", 2
	      if $no_anytls;

	  skip "skipping multi-buffer tests", 2
	      if @extra || (POSIX::uname())[4] ne "x86_64";

	  ok(run(test([@ssltest, "-cipher", "AES128-SHA",    "-bytes", "8m"])));

	  # We happen to know that AES128-SHA256 is TLSv1.2 only... for now.
	  skip "TLSv1.2 is not supported by this OpenSSL configuration", 1
	      if $no_tls1_2;

	  ok(run(test([@ssltest, "-cipher", "AES128-SHA256", "-bytes", "8m"])));
	}
    };

    subtest 'DTLS Version min/max tests' => sub {
        my @protos;
        push(@protos, "dtls1") unless ($no_dtls1 || $no_dtls);
        push(@protos, "dtls1.2") unless ($no_dtls1_2 || $no_dtls);
        my @minprotos = (undef, @protos);
        my @maxprotos = (@protos, undef);
        my @shdprotos = (@protos, $protos[$#protos]);
        my $n = ((@protos+2) * (@protos+3))/2 - 2;
        my $ntests = $n * $n;
	plan tests => $ntests;
      SKIP: {
        skip "DTLS disabled", 1 if $ntests == 1;

        my $should;
        for (my $smin = 0; $smin < @minprotos; ++$smin) {
        for (my $smax = $smin ? $smin - 1 : 0; $smax < @maxprotos; ++$smax) {
        for (my $cmin = 0; $cmin < @minprotos; ++$cmin) {
        for (my $cmax = $cmin ? $cmin - 1 : 0; $cmax < @maxprotos; ++$cmax) {
            if ($cmax < $smin-1) {
                $should = "fail-server";
            } elsif ($smax < $cmin-1) {
                $should = "fail-client";
            } elsif ($cmax > $smax) {
                $should = $shdprotos[$smax];
            } else {
                $should = $shdprotos[$cmax];
            }

            my @args = (@ssltest, "-dtls");
            push(@args, "-should_negotiate", $should);
            push(@args, "-server_min_proto", $minprotos[$smin])
                if (defined($minprotos[$smin]));
            push(@args, "-server_max_proto", $maxprotos[$smax])
                if (defined($maxprotos[$smax]));
            push(@args, "-client_min_proto", $minprotos[$cmin])
                if (defined($minprotos[$cmin]));
            push(@args, "-client_max_proto", $maxprotos[$cmax])
                if (defined($maxprotos[$cmax]));
            my $ok = run(test[@args]);
            if (! $ok) {
                print STDERR "\nsmin=$smin, smax=$smax, cmin=$cmin, cmax=$cmax\n";
                print STDERR "\nFailed: @args\n";
            }
            ok($ok);
        }}}}}
    };

    subtest 'TLS session reuse' => sub {
        plan tests => 12;

        SKIP: {
            skip "TLS1.1 or TLS1.2 disabled", 12 if $no_tls1_1 || $no_tls1_2;
            ok(run(test([@ssltest, "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
            ok(run(test([@ssltest, "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "tls1.2"])));
            ok(run(test([@ssltest, "-server_max_proto", "tls1.1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "tls1.1"])));

            ok(run(test([@ssltest, "-server_max_proto", "tls1.1", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
            ok(run(test([@ssltest, "-server_max_proto", "tls1.1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "tls1.1"])));
            ok(run(test([@ssltest, "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "tls1.2"])));

            ok(run(test([@ssltest, "-no_ticket", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
            ok(run(test([@ssltest, "-no_ticket", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "tls1.2"])));
            ok(run(test([@ssltest, "-no_ticket", "-server_max_proto", "tls1.1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "tls1.1"])));

            ok(run(test([@ssltest, "-no_ticket", "-server_max_proto", "tls1.1", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
            ok(run(test([@ssltest, "-no_ticket", "-server_max_proto", "tls1.1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "tls1.1"])));
            ok(run(test([@ssltest, "-no_ticket", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "tls1.2"])));
        }
    };

    subtest 'DTLS session reuse' => sub {
        plan tests => 12;
      SKIP: {
        skip "DTLS disabled", 12 if $no_dtls;

        ok(run(test([@ssltest, "-dtls", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
        ok(run(test([@ssltest, "-dtls", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "dtls1.2"])));
        ok(run(test([@ssltest, "-dtls", "-server_max_proto", "dtls1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "dtls1"])));

        ok(run(test([@ssltest, "-dtls", "-server_max_proto", "dtls1", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
        ok(run(test([@ssltest, "-dtls", "-server_max_proto", "dtls1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "dtls1"])));
        ok(run(test([@ssltest, "-dtls", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "dtls1.2"])));

        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "dtls1.2"])));
        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_max_proto", "dtls1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "dtls1"])));

        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_max_proto", "dtls1", "-server_sess_out", $server_sess, "-client_sess_out", $client_sess])));
        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_max_proto", "dtls1", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "1", "-should_negotiate", "dtls1"])));
        ok(run(test([@ssltest, "-dtls", "-no_ticket", "-server_sess_in", $server_sess, "-client_sess_in", $client_sess, "-should_reuse", "0", "-should_negotiate", "dtls1.2"])));
	}
    };

    subtest 'Certificate Transparency tests' => sub {
	######################################################################

	plan tests => 3;

      SKIP: {
        skip "Certificate Transparency is not supported by this OpenSSL build", 3
            if $no_ct;
        skip "TLSv1.0 is not supported by this OpenSSL build", 3
            if $no_tls1;

        $ENV{CTLOG_FILE} = srctop_file("test", "ct", "log_list.conf");
        my @ca = qw(-CAfile certCA.ss);
        ok(run(test([@ssltest, @ca, "-bio_pair", "-tls1", "-noct"])));
        # No SCTs provided, so this should fail.
        ok(run(test([@ssltest, @ca, "-bio_pair", "-tls1", "-ct",
                     "-should_negotiate", "fail-client"])));
        # No SCTs provided, unverified chains still succeed.
        ok(run(test([@ssltest, "-bio_pair", "-tls1", "-ct"])));
        }
    };
}

sub testsslproxy {
    my $key = shift || srctop_file("apps","server.pem");
    my $cert = shift || srctop_file("apps","server.pem");
    my $CAtmp = shift;
    my @CA = $CAtmp ? ("-CAfile", $CAtmp) : ("-CApath", bldtop_dir("certs"));
    my @extra = @_;

    my @ssltest = ("ssltest_old",
		   "-s_key", $key, "-s_cert", $cert,
		   "-c_key", $key, "-c_cert", $cert);

    # plan tests => 16;

    note('Testing a lot of proxy conditions.');

    # We happen to know that certP1.ss has policy letters "AB" and
    # certP2.ss has policy letters "BC".  However, because certP2.ss
    # has certP1.ss as issuer, when it's used, both their policy
    # letters get combined into just "B".
    # The policy letter(s) then get filtered with the given auth letter
    # in the table below, and the result gets tested with the given
    # condition.  For details, read ssltest_old.c
    #
    # certfilename => [ [ auth, cond, expected result ] ... ]
    my %expected = ( "certP1.ss" => [ [ [ 'A',  'A'      ], 1 ],
                                      [ [ 'A',  'B'      ], 0 ],
                                      [ [ 'A',  'C'      ], 0 ],
                                      [ [ 'A',  'A|B&!C' ], 1 ],
                                      [ [ 'B',  'A'      ], 0 ],
                                      [ [ 'B',  'B'      ], 1 ],
                                      [ [ 'B',  'C'      ], 0 ],
                                      [ [ 'B',  'A|B&!C' ], 1 ],
                                      [ [ 'C',  'A'      ], 0 ],
                                      [ [ 'C',  'B'      ], 0 ],
                                      [ [ 'C',  'C'      ], 0 ],
                                      [ [ 'C',  'A|B&!C' ], 0 ],
                                      [ [ 'BC', 'A'      ], 0 ],
                                      [ [ 'BC', 'B'      ], 1 ],
                                      [ [ 'BC', 'C'      ], 0 ],
                                      [ [ 'BC', 'A|B&!C' ], 1 ] ],
                     "certP2.ss" => [ [ [ 'A',  'A'      ], 0 ],
                                      [ [ 'A',  'B'      ], 0 ],
                                      [ [ 'A',  'C'      ], 0 ],
                                      [ [ 'A',  'A|B&!C' ], 0 ],
                                      [ [ 'B',  'A'      ], 0 ],
                                      [ [ 'B',  'B'      ], 1 ],
                                      [ [ 'B',  'C'      ], 0 ],
                                      [ [ 'B',  'A|B&!C' ], 1 ],
                                      [ [ 'C',  'A'      ], 0 ],
                                      [ [ 'C',  'B'      ], 0 ],
                                      [ [ 'C',  'C'      ], 0 ],
                                      [ [ 'C',  'A|B&!C' ], 0 ],
                                      [ [ 'BC', 'A'      ], 0 ],
                                      [ [ 'BC', 'B'      ], 1 ],
                                      [ [ 'BC', 'C'      ], 0 ],
                                      [ [ 'BC', 'A|B&!C' ], 1 ] ] );

  SKIP: {
      skip "Neither SSLv3 nor any TLS version are supported by this OpenSSL build", scalar(@{$expected{$cert}})
	  if $no_anytls;

      foreach (@{$expected{$cert}}) {
	  my $auth = $_->[0]->[0];
	  my $cond = $_->[0]->[1];
	  my $res  = $_->[1];
	  is(run(test([@ssltest, "-server_auth", @CA,
		       "-proxy", "-proxy_auth", $auth,
		       "-proxy_cond", $cond])), $res,
	     "test tlsv1, server auth, proxy auth $auth and cond $cond (expect "
	     .($res ? "success" : "failure").")");
      }
    }
}
