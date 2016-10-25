#!/usr/bin/perl
# Print unused objects on a screenos configuration

use strict;
use Data::Dumper;

local(*DB, $/);
open (DB, '<', $ARGV[0]) or die "No puedo abir $ARGV[0]";
my $slurp = <DB>;

sub trim {
    my $var = shift;
    $var =~ s/^\s+|\s+$//g;
    return $var;
}

print "# INFO:\n\n";

my $acount = 0;
my %address = ();
while ( $slurp =~ /set address "([^"]+)" "([^"]+)" ([^\n\r]+)/sg ) {
    my ($zone, $name, $args) = ($1, $2, $3);
    $address{$zone}{$name}{comment} = $1  if $args =~ /"([^"]+)"/;
    $address{$zone}{$name}{ipmask}  = "$1/$2" if $args =~ /([\d\.]+) ([\d\.]+)/;
    $address{$zone}{$name}{args} = $args;
    $acount++;
}
print "# Addresses: $acount\n";

my $agcount = 0;
my %address_group = ();
while ( $slurp =~ /set group address "([^"]+)" "([^"]+)"(?: add "([^"]+)"|([\s\n\r]+))/sg ) {
    if (defined $3) {
        $address_group{$1}{$2}{addresses}{$3}++;
        $address{$1}{$3}{id}{$2}++;
    } else {
        $address_group{$1}{$2}{count};
        $agcount++;
    }
}
print "# Address Groups: $agcount\n";

my $scount = 0;
my %services = ();
while ( $slurp =~ /set service "([^"]+)" ([^\n\r]+)/sg ) {
    $services{$1}{count}++;
    $scount++;
}
print "# Services: $scount\n";

my $sgcount = 0;
my %services_group = ();
while ( $slurp =~ /set group service "([^"]+)"(?: add "([^"]+)"|([\s\n\r]+))/sg ) {
    if (defined $2) {
        $services_group{$1}{services}{$2}++;
        $services{$2}{id}{$1}++
    } else {
        $services_group{$1}{count};
        $sgcount++;
    }
}
print "# Service Groups: $sgcount\n";

my $pcount = 0;
my %policies = ();
while ( $slurp =~ /set policy id (\d+) (?:|name "[^"]+" )from "([^"]+)" to "([^"]+)"  "([^"]+)" "([^"]+)" "([^"]+)"(.+?)set policy id \d+(.+?)exit/sg ) {
    my ($id, $args, $rest) = ($1, $7, $8);
    $policies{$id} = { FROM    => $2
                     , TO      => $3
                     , SRC     => [$4]
                     , DST     => [$5]
                     , SRV     => [$6]
                     , ARGS    => trim($args)
                     , COUNT   => ++$pcount
                     , DISABLE => 0
                     , PERMIT  => 0
                     , COUNT   => 0
                     , DENY    => 0
                     , LOG     => 0
                     , NAT     => 0
                     };
    $policies{$id}{DISABLE} = 1  if $rest =~ /disable/;
    $policies{$id}{PERMIT}  = 1  if $args =~ /permit/;
    $policies{$id}{DENY}    = 1  if $args =~ /deny/;
    $policies{$id}{LOG}     = 1  if $args =~ /log/;
    $policies{$id}{NAT}     = $1 if $args =~ /(nat src dip-id \d+)/;
    push (@{$policies{$id}{SRC}}, $1) while $rest =~ /set src-address "(.+?)"/sg;
    push (@{$policies{$id}{DST}}, $1) while $rest =~ /set dst-address "(.+?)"/sg;
    push (@{$policies{$id}{SRV}}, $1) while $rest =~ /set service "(.+?)"/sg;
    map{ $address_group{$policies{$id}{FROM}}{$_} ? $address_group{$policies{$id}{FROM}}{$_}{id}{$id}++ : $address{$policies{$id}{FROM}}{$_}{id}{$id}++ } @{ $policies{$id}{SRC} };
    map{ $address_group{$policies{$id}{TO}}{$_}   ? $address_group{$policies{$id}{TO}}{$_}{id}{$id}++   : $address{$policies{$id}{TO}}{$_}{id}{$id}++ }   @{ $policies{$id}{DST} };
    map{ $services_group{$_}                      ? $services_group{$_}{id}{$id}++                      : $services{$_}{id}{$id}++ }                      @{ $policies{$id}{SRV} };
}
print "# Policies: $pcount\n";

print "\n# Duplicated Addresses (Must be cleaned manually)\n\n";
my $daddress = 0;
my %duplicated_addresses = ();
foreach my $zone (sort keys %address) {
    foreach my $our_adr (sort keys %{ $address{$zone} }) {
        my $our_ipmask = $address{$zone}{$our_adr}{ipmask} or next;
        foreach my $cur_adr (sort keys %{ $address{$zone} }) {
            next if $our_adr eq $cur_adr;
            my $cur_ipmask = $address{$zone}{$cur_adr}{ipmask};
            if ($our_ipmask eq $cur_ipmask) {
                $duplicated_addresses{$zone}{$cur_ipmask}{$cur_adr}++;
            }
        }
    }
}
print Dumper \%duplicated_addresses;

print "\n# Empty Service Groups\n\n";
foreach my $key (keys %services_group) {
    print "unset group service \"$key\"\n" unless $services_group{$key}{services};
}

print "\n# Empty Address Groups\n\n";
foreach my $zone (sort keys %address_group) {
    foreach my $key (sort keys %{ $address_group{$zone} }) {
        print "unset group address \"$zone\" \"$key\"\n" unless $address_group{$zone}{$key}{addresses};
    }
}

print "\n# Unused Address Groups\n\n";
foreach my $zone (sort keys %address_group) {
    foreach my $key (sort keys %{ $address_group{$zone} }) {
        print "unset group address \"$zone\" \"$key\"\n" unless $address_group{$zone}{$key}{id};
    }
}

print "\n# Unused Addresses\n\n";
foreach my $zone (sort keys %address) {
    foreach my $key (sort keys %{ $address{$zone} }) {
        print "unset address \"$zone\" \"$key\"\n" unless defined $address{$zone}{$key}{id};
    }
}

print "\n# Unused Service Groups\n\n";
foreach my $group (sort keys %services_group) {
    foreach my $service (sort keys %{ $services_group{$group} }) {
        print "unset group service \"$group\"\n" unless $services_group{$group}{id};
    }
}

print "\n# Unused Services\n\n";
foreach my $key (sort keys %services) {
    print "unset service \"$key\"\n" unless $services{$key}{id};
}

print "\n# Disabled Policies\n\n";
foreach my $id (sort keys %policies) {
    print "unset policy id $id\n" if $policies{$id}{DISABLE};
}
