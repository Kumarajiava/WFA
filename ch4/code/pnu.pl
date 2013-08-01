#! c:\perl\bin\perl.exe
#-------------------------------------------------------------
# parse NTUSER.DAT file, and list the contents of one of the
# UserAssist\GUID\Count keys, sorted by most recent time
# 
# Usage: C:\perl>pnu.pl <filename>
#
# copyright 2006-2007 H. Carvey
#-------------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);

# Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";

my $ntuser = shift || die "You must enter a filename.\n";
die "$ntuser not found.\n" unless (-e $ntuser);

my $reg = Parse::Win32Registry->new($ntuser);
my $root_key = $reg->get_root_key;

#print "Root key: $root_key\n";

my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\'.
                '{75048700-EF1F-11D0-9888-006097DEACF9}\\Count';

my $count = $root_key->get_subkey($key_path);
print "LastWrite time = ".gmtime($count->get_timestamp())." (UTC)\n";
my %ua = ();
foreach my $value ($count->get_list_of_values) {
	my $value_name = $value->get_name;
	my $data = $value->get_data;
	my @vals = unpack("x8VV",$data);
	if (length($data) == 16 && $vals[1] != 0) {
		my $time_value = getTime($vals[0],$vals[1]);
		$value_name =~ tr/N-ZA-Mn-za-m/A-Za-z/;
		push(@{$ua{$time_value}},$value_name);
	}
}

foreach my $t (reverse sort {$a <=> $b} keys %ua) {
	print gmtime($t)." (UTC)\n";
	foreach my $item (@{$ua{$t}}) {
		print "\t$item\n";
	}
}

#-------------------------------------------------------------
# getTime()
# Translate FILETIME object (2 DWORDS) to Unix time, to be passed
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