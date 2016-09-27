#! /usr/bin/perl

use strict;
use warnings;

use File::Basename;
use File::Compare qw/compare_text/;

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file/;
use OpenSSL::Test::Utils qw/disabled alldisabled available_protocols/;

setup("test_ssl_new");

$ENV{TEST_CERTS_DIR} = srctop_dir("test", "certs");

my @conf_srcs =  glob(srctop_file("test", "ssl-tests", "*.conf"));
my @conf_files = map {basename($_)} @conf_srcs;

# 02-protocol-version.conf test results depend on the configuration of enabled
# protocols. We only verify generated sources in the default configuration.
my $is_default = (disabled("ssl3") && !disabled("tls1") &&
                  !disabled("tls1_1") && !disabled("tls1_2"));

my %conf_dependent_tests = ("02-protocol-version.conf" => 1);

foreach my $conf (@conf_files) {
    subtest "Test configuration $conf" => sub {
        test_conf($conf,
                  $conf_dependent_tests{$conf} || $^O eq "VMS" ?  0 : 1);
    }
}

# We hard-code the number of tests to double-check that the globbing above
# finds all files as expected.
plan tests => 2;  # = scalar @conf_files

sub test_conf {
    plan tests => 3;

    my ($conf, $check_source) = @_;

    my $conf_file = srctop_file("test", "ssl-tests", $conf);
    my $tmp_file = "${conf}.$$.tmp";
    my $run_test = 1;

  SKIP: {
      # "Test" 1. Generate the source.
      my $input_file = $conf_file . ".in";

      skip 'failure', 2 unless
        ok(run(perltest(["generate_ssl_tests.pl", $input_file],
                        interpreter_args => [ "-I", srctop_dir("test", "testlib")],
                        stdout => $tmp_file)),
           "Getting output from generate_ssl_tests.pl.");

    SKIP: {
        # Test 2. Compare against existing output in test/ssl_tests.conf.
        skip "Skipping generated source test for $conf", 1
          if !$check_source;

        $run_test = is(cmp_text($tmp_file, $conf_file), 0,
                       "Comparing generated sources.");
      }

      # Test 3. Run the test.
      my $no_tls = alldisabled(available_protocols("tls"));
      skip "No TLS tests available; skipping tests", 1 if $no_tls;
      skip "Stale sources; skipping tests", 1 if !$run_test;

      ok(run(test(["ssl_test", $tmp_file])), "running ssl_test $conf");
    }

    unlink glob $tmp_file;
}

sub cmp_text {
    return compare_text(@_, sub {
        $_[0] =~ s/\R//g;
        $_[1] =~ s/\R//g;
        return $_[0] ne $_[1];
    });
}
