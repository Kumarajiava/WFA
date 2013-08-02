#! c:\perl\bin\perl.exe
#------------------------------------------------------
# pref.pl
# Perl script to parse the contents of prefetch files
#
# usage: pref.pl
#
# copyright 2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;

my $dir = $ENV{'SystemRoot'}."\\Prefetch\\";
opendir(DIR,$dir) || die "Could not open $dir: $!\n";
my @files = readdir(DIR);
close(DIR);
print "File,last access,last mod,creation\n";
foreach my $file (@files) {
	next if ($file =~ m/\.$/ || $file =~ m/\.\.$/);
	
	my ($access,$mod,$creation) = (stat($dir.$file))[8,9,10];
	my ($runcount,$runtime) = getMetaData($dir.$file);
	print $file.",".localtime($access).",".localtime($mod).",".localtime($creation).
		",".$runcount.",".localtime($runtime)."\n";	
}

#---------------------------------------------------------
# getMetaData()
# get metadata from .pf files
#---------------------------------------------------------
sub getMetaData {
	my $file = $_[0];
	my $data;
	my ($runcount,$runtime);
	
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	binmode(FH);
	seek(FH,0x78,0);
	read(FH,$data,8);
	my @tvals = unpack("VV",$data);
	$runtime = getTime($tvals[0],$tvals[1]);
	
	seek(FH,0x90,0);
	read(FH,$data,4);
	$runcount = unpack("V",$data);
	
	close(FH);
	return ($runcount,$runtime);
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
# Thanks goes to Andreas Schuster for the below code, which he
# included in his ptfinder.pl
#---------------------------------------------------------
sub getTime {
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