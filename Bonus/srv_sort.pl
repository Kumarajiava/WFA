#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# srv_sort.pl
# Perl script to retrieve Service key info raw Registry/System file,
# sorting the output based on LastWrite time; automatically determines
# which of the available ControlSets is marked "current"
#
# Usage:
# C:\Perl>srv_sort.pl <path_to_System_file> [> srv_sort.txt]
#
# This script is intended to be used against System files extracted from 
# from an image, either from the system32\config directory, or from system 
# restore points.
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);

#Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";

my $sys = shift || die "You must enter a filename.\n";
die "$sys not found.\n" unless (-e $sys);
my %svckeys = ();
my $reg = Parse::Win32Registry->new($sys);
my $root_key = $reg->get_root_key || die "Could not get root key: $!\n";

# Determine which ControlSet is current
my $sel = $root_key->get_subkey("Select");
my $curr = $sel->get_value("Current")->get_data();

# Access the ControlSet
my $cs = $root_key->get_subkey("ControlSet00".$curr."\\Services");
my @subkeys = $cs->get_list_of_subkeys();
foreach my $s (@subkeys) {
	my $name  = $s->get_name();
	my $ts    = $s->get_timestamp();
	my $image = "";
	if (my @vals = $s->get_list_of_values()) {
		foreach my $v (@vals) {
			if ($v->get_name() eq "ImagePath") {
				$image = " -> ".$v->get_data("ImagePath");
			}
		}
	}
	$name .= $image;
	push(@{$svckeys{$ts}},$name); 
}

foreach my $t (reverse sort {$a <=> $b} keys %svckeys) {
	print "[".localtime($t)."]\n";
	foreach my $n (@{$svckeys{$t}}) {
		print "\t$n\n";
	}
}