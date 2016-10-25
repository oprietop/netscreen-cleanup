#!/usr/bin/perl
# Get the policy usage from a screenos firewall to do some cleaning

use strict;
use warnings;
use Net::Telnet;

$0 =~ s/.*\///g;
print "Usage: $0 <host/s>\n" and exit 1 unless @ARGV;

my @warnings  = ();
my @criticals = ();
my $user      = 'user';
my $pass      = 'pass';

foreach my $host (@ARGV) {
    # Establish a telnet connection.
    my $telnet = new Net::Telnet ( Timeout => 300
                                 , Errmode => 'return'
                                 , Prompt  => '/.*\(\w\)->/i'
                                 );
    my $count = 0;
    my $attempts = 3;
    print "# Connecting to '$host' via telnet.";
    while ($count != $attempts) {
        $count++;
        print " $count/$attempts...";
        print " OK\n" and last if $telnet->open($host);
    }
    if ($count == $attempts) {
        print " NOK!\n# Can't connect to '$host' after $count attempts.\n";
        push (@criticals, "[$host] Can't connect to '$host' after $count attempts.");
        next;
    }

    # Authenticate with our user/pass pair.
    print "# Authenticating with user/pass...";
    $telnet->login($user, $pass);
    my $prompt = $telnet->last_prompt;
    $prompt =~ tr/\015//d;
    my $lastline = $telnet->lastline;
    chomp $lastline;
    if ($prompt) {
        print " OK\n";
    } else {
        print " NOK! Unable to get prompt. The last line was: '$lastline'\n";
        push (@criticals, "[$host] Unable to get prompt. The last line was: '$lastline'");
        next;
    }

    my %hash = ();
    my $result = join('', $telnet->cmd('get policy'));
    while ( $result =~ /^\s+(\d+)/smg) {
        my $id = $1;
        my $id_info = join('', $telnet->cmd("get policy id $id"));
        if (my ($octets) = $id_info =~ /total octets (\d+),/) {
            $hash{$id} = $octets;
        }
    }

    my $sysver = join('', $telnet->cmd('get system'));
    my ($uptime) = $sysver =~ /Up (\d+ hours)/;

    print "\n# Rule Id -> Octets\n";
    map { print "$_ -> $hash{$_}\n"  } sort { $hash{$b} <=> $hash{$a} } keys(%hash);

    print "\n# Unused Rules since boot, $uptime ago.\n";
    map { print "unset policy id $_\n" unless $hash{$_} } sort { $hash{$b} <=> $hash{$a} } keys(%hash);
}


