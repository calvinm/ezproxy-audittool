#!/usr/bin/perl

#
# Copyright 2012 - Calvin Mah - Simon Fraser University
#

use strict;

use vars qw(@IP_FILTER @HOSTILE_IPS @BADUSERS $JOINED 
			$AUDIT_DIR $BADUSER_FILE $HOSTILEIP_FILE $CSS $DATA_IPS $DATA_USERS
			$IPS $IDS $GEOFILE);

use CGI qw(:all);
use Date::Calc qw(:all);
use Geo::IP;
use Storable;


@IP_FILTER = qw(192.168.1.1);
$JOINED = '/opt/ezproxy/audit/joined.txt';
$AUDIT_DIR = '/opt/ezproxy/audit/';
$BADUSER_FILE = '/opt/ezproxy/scripts/badusers.txt';
$HOSTILEIP_FILE = '/opt/ezproxy/scripts/hostileip.txt';
$DATA_IPS = '/opt/ezproxy/scripts/audit_ips.dat';
$DATA_USERS = '/opt/ezproxy/scripts/audit_users.dat';
$GEOFILE = '/opt/ezproxy/GeoLiteCity.dat';

$CSS=<<END;
a, body, font, p, td, blockquote, h1, h2 {
font-family: Verdana, Arial, Helvetica, sans-serif;
font-size: 10pt;
}
.small {
font-family: Verdana, Arial, Helvetica, sans-serif;
font-size: 8pt;
}
.success {
color: green;
}
.failure {
color: red;
}
.nomargin {
margin-top: 0;
margin-bottom: 0;
margin-left: 0;
margin-right: 0;
}
.double, dd {
margin-bottom: 10pt}
tt {
font-size: 10pt;
font-family: monospace;
}
b {
font-weight: bold;
}
font.small {
font-size: 8pt;
}
h1, p.heading {
font-weight: bold;
font-size: 16pt;
text-align: center;
margin-top: 6px;
}
h2, p.subheading {
font-weight: bold;
}
a:active, a:link, a:visited {
text-decoration: none;
color: #0033CC;
background-color: transparent;
}
a:hover {
text-decoration: underline;
}
a.small:active, a.small:link, a.small:visited {
font-size: 8pt;
}
table.tdpad td {
	padding: 1px 0.5em;
}
td {
	padding: 1px 0.5em;
}
td.warnred {
	background-color: #FFB3B3; color: black;
}
td.warnblue {
	background-color: #A8E9FF; color: black;
}
END

sub main {

	&readfiles;
	print header;
	print start_html(-title=>'ezproxy audit',-style=>{-code=>$CSS});
	print a({-href=>CGI::url()}, 'ezproxy audit');
	print ' | ' . a({-href=>CGI::url() . '?ipreport=1'}, 'IP report');
	print ' | ' . a({-href=>CGI::url() . '?userreport=1'}, 'user report') . p();
	if (grep {remote_addr() eq $_} @IP_FILTER) {
		if (param('auditdate')) {
			&auditdate;
		}
		elsif (param('grepjoined')) {
			&grepjoined;
		}
		elsif (param('ipreport')) {
			&ipreport;
		}
		elsif (param('userreport')) {
			&userreport;
		}
		else {
			&auditlist;
		}
	}
	print end_html;
}

&main;

sub auditdate {
	my ($file, $line, @parts, @toaudit, @vals);
	my ($row, $rows);
	
	my $gi = Geo::IP->open($GEOFILE, GEOIP_STANDARD);	

	$file = $AUDIT_DIR . param('auditdate') . '.txt';
	if (-e "$file") {
		print h3($file);
		open(FILE, $file) || die "can't open file $file for reading: $!\n";
		while($line = <FILE>) {
			chop($line);
			@parts = split(/\t/, $line);
			if ($parts[1] =~ m#^Login.Success|^Login.Denied#) { push(@toaudit,$line); }
		}
		foreach $line (sort by_ip @toaudit) {
			@vals = split(/\t/, $line);
			$rows .= &print_row(\@vals);
		}
		print table({-class=>'tdpad',-border=>'1',cellspacing=>"0", cellpadding=>"0"}, $rows);
	} else {
		print "$file does not exist\n";
	}
}

sub grepjoined {
	my ($tofind) = param('grepjoined');

	my ($row, $rows);
	my (@lines, $line, @vals);
	my $find_normal = $tofind;
	
	$find_normal =~ tr/A-Z/a-z/;

	my $gi = Geo::IP->open($GEOFILE, GEOIP_STANDARD);	
	
	@lines = `grep -Pi $tofind $JOINED`;
	
	foreach my $line (@lines) {
		chop($line);
		@vals = split(/\t/, $line);

		my $check_ip = $vals[2];
		my $check_user = $vals[3];

		$check_ip =~ tr/A-Z/a-z/;
		$check_user =~ tr/A-Z/a-z/;
		
		if (($find_normal eq $check_ip) || ($find_normal eq $check_user)) {
			if ($vals[1] =~ m#^Login.Success|^Login.Denied#) {
				@vals = split(/\t/, $line);
				$rows .= &print_row(\@vals);
			}
		}
	}
	print h3($tofind);
	print table({-class=>'tdpad',-border=>'1',cellspacing=>"0", cellpadding=>"0"}, $rows);
}

sub print_row {
# 
# 0 Date/Time
# 1 Event
# 2 IP
# 3 Username
# 4 Session
# 5 Other
# 

	my ($vals) = @_;
	
	my ($warn);
	my ($truser);
	
	my $gi = Geo::IP->open($GEOFILE, GEOIP_STANDARD);
	my ($record, $location, $row);

	$record = $gi->record_by_addr($$vals[2]);
	if (defined ($record)) {
		if ($record->country_code =~ m#CN|IR#) {
			$location = b(font({-color=>'red'}, $location = $record->country_code . ' ' . $record->city));
		}
		else {
			$location = $record->country_code . ' ' . $record->city;
		}
	}
	else {
		$location = '??';
	}
	$row =  td({-nowrap=>1}, $$vals[0]);
	$row .= td({-nowrap=>1}, $$vals[1]);
	if (grep {$$vals[2] eq $_ } @HOSTILE_IPS) {
		$row .= td({-class=>'warnred'}, a({-href=>CGI::url() . "?grepjoined=" . $$vals[2]}, $$vals[2]));
	}
	else {
		$row .= td(a({-href=>CGI::url() . "?grepjoined=" . $$vals[2]}, $$vals[2]));
	}
	my ($uniq_id_s, $uniq_id_f);
	$uniq_id_s = $$IPS{$$vals[2]}{'success_user_unique'};
	$uniq_id_f = $$IPS{$$vals[2]}{'fail_user_unique'};
	
	$row .= td({-nowrap=>1},"s: $uniq_id_s  f: $uniq_id_f");
	
	$row .=	td({-nowrap=>1}, $location);
	if (grep {$$vals[3] eq $_ } @BADUSERS) {

		$row .= td({-class=>'warnblue'}, a({-href=>CGI::url() . "?grepjoined=" . $$vals[3]},$$vals[3]));
	}
	else {
		$row .= td(a({-href=>CGI::url() . "?grepjoined=" . $$vals[3]},$$vals[3]));
	}
	my ($user_countries, $user_ips, $user_s, $user_f, $user_ip_f);
	
	$truser = $$vals[3];
	$truser =~ tr/A-Z/a-z/;
	
	$user_countries = $$IDS{$truser}{'success_country_unique'};
	if ($user_countries > 5) { $user_countries = b(' ' . $user_countries . ' '); }
	$user_ips = $$IDS{$truser}{'success_ip_unique'};
	$user_s = $$IDS{$truser}{'success'};
	$user_f =  $$IDS{$truser}{'fail'};
	$user_ip_f = $$IDS{$truser}{'fail_ip_unique'};
	
	$row .= td({-nowrap=>1},"c: $user_countries ip: $user_ips s: $user_s f: $user_f ip_f: $user_ip_f");
	$row .= td({-nowrap=>1}, $$vals[4]);
	$row .= td({-nowrap=>1}, $$vals[5]);


	$row = Tr({-valign=>'top'}, $row) . "\n";

	return($row);
}

sub auditlist {
	my ($file);
	my ($days);

	$days = 0;

	while ($days > -720) {
		my ($year, $month, $day, $dow, $dayofweek);
		
		($year, $month, $day) = Add_Delta_Days(Today,$days);
		$dow = Day_of_Week($year, $month, $day);
		$dayofweek = Day_of_Week_to_Text($dow);
		
		if (length($month) < 2) {
			$month = '0' . $month;
		}
		if (length($day) < 2) {
			$day = '0' . $day;
		}

		print a({-href=>CGI::url() . "?auditdate=$year$month$day"}, "$year - $month - $day - $dayofweek");
		if ($dow == 7) {
			print "<hr>";
		}
		else {
			print "<br>";
		}
		$days--;
	}
}

sub readfiles {

	open(FILE, $BADUSER_FILE) || die ("can't open bad user file $BADUSER_FILE: $!\n");
	
	my $user;
	
	while ($user = <FILE>) {
		chop($user);
		push(@BADUSERS, $user);
	}
	close(FILE);

	open(FILE, $HOSTILEIP_FILE) || die ("can't open hostile IP file $HOSTILEIP_FILE: $!\n");
	
	my $ip;
	
	while ($ip = <FILE>) {
		chop($ip);
		push(@HOSTILE_IPS, $ip);
	}
	close(FILE);
	$IDS = eval { retrieve($DATA_USERS) } || die ("can't open datafile $DATA_USERS: $!\n");
	$IPS = eval { retrieve($DATA_IPS) } || die ("can't open datafile $DATA_IPS: $!\n");
}

sub ipreport {
	my ($row, $rows);

	$row = th('IP Addr') . th('Location') . th('IDs Fail') . th('IDs Success');
	$rows .= Tr({-valign=>'top'}, $row);

	foreach my $addr (sort {$$IPS{$b}{'fail_user_unique'} <=> $$IPS{$a}{'fail_user_unique'}} keys %$IPS) {
		if ($$IPS{$addr}{'fail_user_unique'} > 5) {
			$row = td( a({-href=>CGI::url() . "?grepjoined=" . $addr}, $addr) );
			$row .= td( $$IPS{$addr}{'country_code'} . ' ' . $$IPS{$addr}{'city'} );
			$row .= td( $$IPS{$addr}{'fail_user_unique'} );
			$row .= td( $$IPS{$addr}{'success_user_unique'} );
			$rows .= Tr({-valign=>'top'}, $row) . "\n";
		}
		
		
	}
	print table({-class=>'tdpad',-border=>'1',cellspacing=>"0", cellpadding=>"0"}, $rows);
}

sub userreport {
	my ($row, $rows);
	$row = th('ID') . th('# Country Success') . th('Uniq IP Fail');
	$rows .= Tr({-valign=>'top'}, $row);

	foreach my $user (sort {$$IDS{$b}{'fail_ip_unique'} <=> $$IDS{$a}{'fail_ip_unique'}} keys %$IDS) {
		if (($$IDS{$user}{'fail_ip_unique'} > 5) && ($user !~ m#^29345#)) {
			$row = td( a({-href=>CGI::url() . "?grepjoined=" . $user}, $user) );
			$row .= td( $$IDS{$user}{'success_country_unique'} );
			$row .= td( $$IDS{$user}{'fail_ip_unique'} );
			$rows .= Tr({-valign=>'top'}, $row) . "\n";

		}
	}
	print table({-class=>'tdpad',-border=>'1',cellspacing=>"0", cellpadding=>"0"}, $rows);

}

sub by_ip
{
	my (@aa) = split("\t", $a);
	my (@bb) = split("\t", $b);
	
        # Split the two ip addresses up into octets
        my ($a1, $a2, $a3, $a4) = split /\./, $aa[2];
        my ($b1, $b2, $b3, $b4) = split /\./, $bb[2];

        # Check to see if the first octets are the same
        if ($a1 == $b1) {
                # If the first octets are the same, check
                # the second octets
                if ($a2 == $b2)
                {
                        # Ditto for the third octets
                        if ($a3 == $b3)
                        {
                                # If the first 3 octets
                                # of each address are 
                                # the same, return the
                                # comparison of the last
                                # octet
                                $a4 =~ s/^([0-9]+)/$1/;
                                $b4 =~ s/^([0-9]+)/$1/;

                                return $a4 <=> $b4;
                        } else {
                                # 3rd octets were different
                                # so return their comparison
                                return $a3 <=> $b3;
                        }
                } else {
            # 2nd octets were different so
                        # return their comparison
                        return $a2 <=> $b2;
                }
        } else {
                # Best case: The first octets were
                # different so we can return their
                # comparison immediately
                return $a1 <=> $b1;
        }
}
