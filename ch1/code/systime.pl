# c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# systime.pl - Perl script to demonstrate how to obtain the system 
#              time in UTC/GMT and local time formats, via the 
#	             Windows API
#
# Usage: C:\perl>systime.pl 
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
# To install the Win32::API::Prototype module:
# ppm install http://www.roth.net/perl/packages/win32-api-prototype.ppd
use Win32::API::Prototype;

my @month = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
my @day   = qw/Sun Mon Tue Wed Thu Fri Sat/;

ApiLink('kernel32.dll',
        'VOID GetSystemTime(LPSYSTEMTIME lpSystemTime)')
    || die "Cannot locate GetSystemTime()";

ApiLink('kernel32.dll',
        'VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)')
		|| die "Cannot locate GetLocalTime()";

# Get the system time
# Ref: http://msdn.microsoft.com/library/default.asp?url=
#           /library/en-us/sysinfo/base/getsystemtime.asp
my $lpSystemTime = pack("S8", 0); 
GetSystemTime($lpSystemTime);
my $str = sys_STR($lpSystemTime);

GetLocalTime($lpSystemTime);
my $local = sys_STR($lpSystemTime);

print "System Time  : $str\n";
print "Local Time   : $local\n";

# Convert returned SystemTime into a string
sub sys_STR {
	my $lpSystemTime = $_[0];
	my @time = unpack("S8", $lpSystemTime);
  $time[5] = "0".$time[5] if ($time[5] =~ m/^\d$/);
  $time[6] = "0".$time[6] if ($time[6] =~ m/^\d$/);            
  my $timestr = $day[$time[2]]." ".$month[$time[1]-1]." ".$time[3].
        " ".$time[4].":".$time[5].":".$time[6]." ".$time[0];
  return "$timestr";
}
