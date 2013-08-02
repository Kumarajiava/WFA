#! c:\perl\bin\perl.exe
#---------------------------------------------------------
# kt.pl
# Retrieves LastWrite time from Registry keys
#
# usage: keytime.pl <full key path>
# ex:    keytime.pl HKEY_LOCAL_MACHINE\Software\Microsoft
#
#
# Copyright 2005-2007 H. Carvey keydet89@yahoo.com
#---------------------------------------------------------
use strict;
use Win32::TieRegistry(Delimiter=>"/");

my $server = Win32::NodeName;
my $regkey = shift || die "You must enter a Registry key.\n";
$regkey =~ s/\\/\//g;
$regkey = "//$server/".$regkey;
# Registry key to check
my $remote;
eval {
	$remote = $Registry->Open($regkey, {Access=>0x20019}) ||
		die "Could not open $regkey: $^E\n";
};
die "Error occurred: $@\n" if ($@);
	
# Get key info
#my %info = $remote->Information;
my %info;
die "Key has no Information.\n" unless (%info = $remote->Information);


# The FILETIME structure can be broken down and saved to be
# used at a later date for conversions, etc.
my $lw = getTime(unpack("VV",$info{"LastWrite"}));
print "LastWrite = ".localtime($lw)."\n";

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (QWORD) to Unix time, to be passed
# to gmtime() or localtime()
#-------------------------------------------------------------
sub getTime() {
	my $lo = shift;
	my $hi = shift;
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}