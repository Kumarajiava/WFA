#! c:\perl\bin\perl.exe
#---------------------------------------------------------
# srvchk.pl
# Parses through the CurrentControlSet/Services key on a system,
# and returns all of the Service subkeys, sorted in order of their
# key's LastWrite times.  In addition to retrieving the Service name,
# the ImagePath value (if available) is also returned.
#
# usage: [perl] srvchk.pl [> srvchk.log] 
#
# Copyright 2006-2007 H. Carvey keydet89@yahoo.com
#---------------------------------------------------------
use strict;
use Win32::TieRegistry(Delimiter=>"/");

my %svckeys = ();

my $regkey = "System/CurrentControlSet/Services";
my $hklm;
my $svc;
eval {
	$hklm = $Registry->Open("LMachine", {Access=>0x20019}) ||
		die "Could not open HKLM: $^E\n";
	$svc = $hklm->Open($regkey,{Access=>0x20019}) || 
		die "Could not open $regkey: $^E\n";
};
die "Error occurred: $@\n" if ($@);

my %info = $svc->Information;
print "$regkey LastWrite = ".localtime(getTime(unpack("VV",$info{"LastWrite"})))."\n";

my @subkeys = $svc->SubKeyNames;
foreach my $s (@subkeys) {
	my $skey = $svc->Open($s,{Access=>0x20019});
	my %info = $skey->Information;
	my $g = getTime(unpack("VV",$info{"LastWrite"}));
	
	my @vals = $skey->ValueNames();
	my $image = "ImagePath";
	my $n = "";
	$n = ":".$skey->GetValue($image) if (grep(/$image/i,@vals));
	
	push(@{$svckeys{$g}},$s.$n); 
}

foreach my $t (reverse sort {$a <=> $b} keys %svckeys) {
	print "[".localtime($t)."]\n";
	foreach my $n (@{$svckeys{$t}}) {
		print "\t$n\n";
	}
}

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