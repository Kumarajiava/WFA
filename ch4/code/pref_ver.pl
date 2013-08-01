#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# pref_ver.pl
# Perl script to parse the contents of the XP layout.ini file, locate
# executables (.exe, .dll, .sys) and locate those files and then 
# extract any file version information
#
# Usage:
# C:\Perl>pref_ver.pl [> bholist.txt]
#
# Note: If compiled via Perl2Exe with the '-tiny' switch, this script
#       can be used with the FRU/FSP
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Win32::File::VersionInfo;

my $layout = $ENV{'SystemRoot'}."\\Prefetch\\layout.ini";
my %files = ();

if (-e $layout) {
	open(FH,$layout) || die "Could not open $layout: $! \n";
	while(<FH>) {
		chomp;
		my $str = $_;
    $str =~ tr/\0//d;
    $str =~ s/\x0D$//;
		if ($str =~ m/(\.exe|\.dll|\.sys)$/i) {
			$files{$str} = 1;
		}
	}
	close(FH);
}
else {
	print $layout." not found.\n";
	exit 1;
}


foreach my $file (keys %files) {
	if (-e $file) {
		my $ver ;
		print $file."\n";
		if (my $ver = GetFileVersionInfo ($file)) {
			print "File Version    : ".$ver->{FileVersion}."\n";
			print "Product Version : ".$ver->{ProductVersion}."\n";
			print "OS              : ".$ver->{OS}."\n";
			print "Type            : ".$ver->{Type}."\n";
			if (my $lang = (keys %{$ver->{Lang}})[0]) {
				print "CompanyName     : ".$ver->{Lang}{$lang}{CompanyName}, "\n";
				print "FileDescription : ".$ver->{Lang}{$lang}{FileDescription}, "\n";
				print "FileVersion     : ".$ver->{Lang}{$lang}{FileVersion}, "\n";
				print "InternalName    : ".$ver->{Lang}{$lang}{InternalName}, "\n";
				print "Copyright       : ".$ver->{Lang}{$lang}{Copyright}, "\n";
				print "Trademarks      : ".$ver->{Lang}{$lang}{Trademarks}, "\n";
				print "OrigFileName    : ".$ver->{Lang}{$lang}{OriginalFilename}, "\n";
				print "ProductName     : ".$ver->{Lang}{$lang}{ProductName}, "\n";
				print "ProductVersion  : ".$ver->{Lang}{$lang}{ProductVersion}, "\n";
				print "PrivateBuild    : ".$ver->{Lang}{$lang}{PrivateBuild}, "\n";
				print "SpecialBuild    : ".$ver->{Lang}{$lang}{SpecialBuild}, "\n";
			}
		}
		print "\n";
	}  
	else {
		print "$file not found.\n";
	}
}
  