#! c:\perl\bin\perl.exe
#------------------------------------------------------
# poladt.pl
# Parse the raw Security file and display the audit policy
# for the system (2000, XP, 2003) 
#
# Usage: poladt.pl <filename> [ > output_file]
#
# NT: http://support.microsoft.com/kb/246120
# 2K: http://www.jsifaq.com/SF/Tips/Tip.aspx?id=5231
# http://loguk.blogspot.com/2004/09/bit-of-windows-internals-recently.html
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Parse::Win32Registry qw(:REG_);

my %win2kevents = (0 => "System Events",
              1 => "Logon Events",
              2 => "Object Access",
              3 => "Privilege Use",
              4 => "Process Tracking",
              5 => "Policy Change",
              6 => "Account Management",
              7 => "Directory Service Access",
              8 => "Account Logon Events");
              
my %ntevents = (0 => "Restart, Shutdown, Sys",
                1 => "Logon/Logoff",
                2 => "File/Object Access",
                3 => "Use of User Rights",
                4 => "Process Tracking",
                5 => "Sec Policy Mgmt",
                6 => "User/Grp Mgmt");              
              
my %audit = (0 => "None",
             1 => "Succ",
             2 => "Fail",
             3 => "Both");

my %policy = ();

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

my $reg = Parse::Win32Registry->new($file);
my $root = $reg->get_root_key;

my $pol = $root->get_subkey("Policy\\PolAdtEv");
my $ts = $pol->get_timestamp();
print "LastWrite: ".gmtime($ts)." (UTC)\n";

my $val = $pol->get_value("");
#print "\t".$val->print_summary()."\n";

my $adt = $val->get_data();
my $len = length($adt);

my $enabled = unpack("C",substr($adt,0,1));
if ($enabled) {
	print "Auditing was enabled.\n"; 
	my @evts = unpack("V*",substr($adt,4,$len-4));
	my $tot = $evts[scalar(@evts) - 1];
	print "There are $tot audit categories.\n";
  print "\n";
  
  if ($tot == 9) {
		foreach my $n (0..(scalar(@evts) - 2)) {
			my $adtev = $audit{$evts[$n]};
			$policy{$win2kevents{$n}} = $adtev;
		}
	}
	elsif ($tot == 7) {
		foreach my $n (0..(scalar(@evts) - 2)) {
			my $adtev = $audit{$evts[$n]};
			$policy{$ntevents{$n}} = $adtev;
		}
	}
	else {
		print "Unknown audit configuration.\n";	
	}
	
	foreach my $k (keys %policy) {
		printf "%-25s %-4s\n",$k,$policy{$k};
	}
}
else {
	print "Auditing was not enabled.\n";
}