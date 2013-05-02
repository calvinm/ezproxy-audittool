#!/usr/bin/perl

#
# Copyright 2012 - Calvin Mah - Simon Fraser University
#

use strict;

use vars qw($JOINED $DATA_IPS $DATA_USERS $GEOFILE);

$JOINED = '/opt/ezproxy/audit/joined.txt';
$DATA_IPS = '/opt/ezproxy/scripts/audit_ips.dat';
$DATA_USERS = '/opt/ezproxy/scripts/audit_users.dat';
$GEOFILE = '/opt/ezproxy/GeoLiteCity.dat';

use Geo::IP;
use File::Spec;
use Storable;

# for debug
# use Data::Dumper;

&main;

sub main {
	my ($line, %ips, %ids);
	my ($record, $country_code, $city);
	
	my $gi = Geo::IP->open($GEOFILE, GEOIP_STANDARD);

	open(JOINFILE, "$JOINED") || die ("can't open $JOINED for reading: $!\n");
	while ($line = <JOINFILE>) {
		my (@vals);
		my ($date, $event, $ip, $user, $session, $other);
		
		chop($line);
		($date, $event, $ip, $user, $session, $other) = split(/\t/, $line);
		# print "$date, $event, $ip, $user, $session, $other\n";
		$user =~ tr/A-Z/a-z/;
		
		if ($event =~ m#^Login.Success|^Login.Denied#) {
			$record = $gi->record_by_addr($ip);
			if (defined ($record)) {
				$country_code = $record->country_code;
				$city = $record->city;
			} else {
				$country_code = '??';
				$city = '??';
			}

			${ips{$ip}}{'country_code'} = $country_code;
			${ips{$ip}}{'city'} = $city;
			if ($event =~ m#^Login.Success#) {
				${ips{$ip}}{'success'}++;
				${ips{$ip}}{'success_ids'}{$user}++;
				${ids{$user}}{'success'}++;
				${ids{$user}}{'success_ips'}{$ip}++;
				${ids{$user}}{'success_country'}{$country_code}++;
				
			} elsif ($event =~ m#^Login.Denied#) {
				${ips{$ip}}{'fail'}++;
				${ips{$ip}}{'fail_ids'}{$user}++;
				${ids{$user}}{'fail'}++;
				${ids{$user}}{'fail_ips'}{$ip}++;
				${ids{$user}}{'fail_country'}{$country_code}++;
			}
		}
	}
	
	foreach my $user (keys %ids) {
		my ($count, $hashref);
		$hashref = $ids{$user}{'success_country'};
		# foreach my $country (keys %$hashref) { $count++; }
		$count = keys(%$hashref);
		$ids{$user}{'success_country_unique'} = $count;
		
		$hashref = $ids{$user}{'success_ips'};
		# foreach my $ipaddr (keys %$hashref) { $count++; }
		$count = keys(%$hashref);
		$ids{$user}{'success_ip_unique'} = $count;
		
		$hashref = $ids{$user}{'fail_country'};
		# foreach my $country (keys %$hashref) { $count++; }
		$count = keys(%$hashref);
		$ids{$user}{'fail_country_unique'} = $count;
		
		$hashref = $ids{$user}{'fail_ips'};
		# foreach my $ipaddr (keys %$hashref) { $count++; }
		$count = keys(%$hashref);
		$ids{$user}{'fail_ip_unique'} = $count;	
	}
	
	
	foreach my $addr (keys %ips) {
		my ($count, $hashref);
		
		$hashref = $ips{$addr}{'success_ids'};
		$count = keys(%$hashref);
		$ips{$addr}{'success_user_unique'} = $count;
		
		$hashref = $ips{$addr}{'fail_ids'};
		$count = keys(%$hashref);
		$ips{$addr}{'fail_user_unique'} = $count;

	}
	# debug
	#
	# print Dumper(\%ips);
	# print Dumper(\%ids);
	
	store(\%ips, $DATA_IPS);
	store(\%ids, $DATA_USERS);
}
