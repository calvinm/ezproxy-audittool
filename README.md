ezproxy-audittool
=================

Tool to audit ezproxy logs to easily identify compromised IDs &amp; abuse of use.

Copyright 2013 - Calvin Mah - Simon Fraser University


File Manifest:
================================
- makejoined.pl
- makeaudit.pl
- audit.pl (copy to apache cgi-bin)


Required perl modules:
================================
- CGI
- Date::Calc
- Geo::IP
- Storable
- File::Spec


Installation:
================================
You will need to install the required perl modules.  Using CPAN would be the easiest.

The audit tools make extensive use of IP address to geolocation data.  This data is free (free since the resol
ution is coarse, but good enough for this purpose)

Required location data from www.maxmind.com.  File download at:

http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz

Copy the un-compressed file to location specified by $GEOFILE in makeaudit.pl & audit.pl


Copy the audit.pl file into your apache cgi-bin directory and take the necessary steps to make it accessible t
o your browser.  (you'll want to edit IP_FILTER to
add your IP address)

Each of the 3 files points to locations where other files are found.  (Sorry this is rough, but I didn't inten
d to ever need to share these scripts)



Ezproxy config.txt setting:
================================
In order to get useful audit information from the ezproxy logs,
make sure these 2 lines are in your ezproxy file.  Audit most gives you login success and login fail messages.
AuditPurge 720 lets you keep 720 days of logs.  A deep history is useful for detecting abuse/intrusion.


- Audit Most
- AuditPurge 720

