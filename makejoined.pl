#!/usr/bin/perl

#
# Copyright 2012 - Calvin Mah - Simon Fraser University
#

use vars qw($JOINED $AUDITDIR);

$JOINED = '/opt/ezproxy/audit/joined.txt';
$AUDIT_DIR = '/opt/ezproxy/audit/';



use strict;

my ($year, $month, $day);
my ($filename);
my $line;
my (%failed_ip);
my (%success_ip);
my (@blacklist);
my (%flagged_user);
my (%user_country, %countries);
my ($current_year, @current_date);

@current_date = localtime(time);
$current_year = $current_date[5];
$current_year += 1900;

system("/bin/rm -f " . $JOINED);

foreach $year (2007..$current_year) {
	foreach $month (1..12) {
		foreach $day (1..31) {
			if (length($month) < 2) {
				$month = '0' . $month;
			}
			if (length($day) < 2) {
				$day = '0' . $day;
			}
			# print $year . $month . $day . "\n";
			if (-e "$AUDIT_DIR$year$month$day.txt") {
				system("cat $AUDIT_DIR$year$month$day.txt >> $JOINED");
			}
		}
	}
}
system("chgrp apache " . $AUDIT_DIR . "*.txt");
system("chmod g+r " . $AUDIT_DIR . "*.txt");
