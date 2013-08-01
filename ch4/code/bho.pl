#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# BHO.pl
# Perl script to retrieve listing of installed BHOs from a local
# system
#
# Usage:
# C:\Perl>bho.pl [> bholist.txt]
#
# Note: If compiled via Perl2Exe with the '-tiny' switch, this script
#       can be used with the FRU/FSP
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Win32::TieRegistry(Delimiter=>"/");

my $server = Win32::NodeName();
my $err;
my %bhos;
my $remote;

# Get Browser Helper Objects
if ($remote = $Registry->{"//$server/LMachine"}) {
	my $ie_bho = "SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/Browser Helper Objects";
	if (my $bho = $remote->{$ie_bho}) {
		my @keys = $bho->SubKeyNames();
		foreach (@keys) { 
			$bhos{$_} = 1;
		}
	}
	else {
		$err = Win32::FormatMessage Win32::GetLastError();
		print "Error connecting to $ie_bho: $err\n";
	}
}
else {
	$err = Win32::FormatMessage Win32::GetLastError();
	print "Error connecting to Registry: $err\n";
}
undef $remote;

# Find out what each BHO is...
if ($remote = $Registry->{"//$server/Classes/CLSID/"}) {
	foreach my $key (sort keys %bhos) {
		if (my $conn = $remote->{$key}) {
			my $class = $conn->GetValue("");
			print "Class : $class\n";
			my $module = $conn->{"InprocServer32"}->GetValue("");
			print "Module: $module\n";
			print "\n";
		}
		else {
			$err = Win32::FormatMessage Win32::GetLastError();
			print "Error connecting to $key: $err\n";
		}
	}
}
else {
	$err = Win32::FormatMessage Win32::GetLastError();
	print "Error connecting to Registry: $err\n";
}