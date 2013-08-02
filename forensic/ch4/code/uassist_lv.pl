#! c:\perl\bin\perl.exe
#---------------------------------------------------------
# uassist.pl
# Parse UserAssist keys, and translate from ROT-13 encryption
#---------------------------------------------------------
#use strict;
use Win32::TieRegistry(Delimiter=>"/");

my @month = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
my @day = qw/Sun Mon Tue Wed Thu Fri Sat/;

#---------------------------------------------------------------
# _main
# 
#---------------------------------------------------------------
\getKeyValues();

#---------------------------------------------------------------
# Get key values
# 
#---------------------------------------------------------------
sub getKeyValues {
	my $reg;
	my $userassist = "SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/UserAssist";
	
	my $subkey1 = "{5E6AB780-7743-11CF-A12B-00AA004AE837}/Count";
	my $subkey2 = "{75048700-EF1F-11D0-9888-006097DEACF9}/Count";
	
	if ($reg = $Registry->Open("CUser",{Access=>KEY_READ})) {
	
		if (my $ua = $reg->Open($userassist,{Access=>KEY_READ})) {
			if (my $key1 = $ua->Open($subkey1,{Access=>KEY_READ})) {
			
				my @valuenames = $key1->ValueNames();
				print "[$subkey1  -  $lastwrite]\n";
				foreach my $value (@valuenames) {
					my $vData = $key1->GetValue($value);
					$value =~ tr/N-ZA-Mn-za-m/A-Za-z/;
					print $value."\n";
				}
			}
			else {
				print "Error accessing $subkey1: $! \n";
			}
			print "\n";
			if (my $key2 = $ua->Open($subkey2,{Access=>KEY_READ})) {
							
				my @valuenames = $key2->ValueNames();
				print "[$subkey2  -  $lastwrite]\n";
				foreach my $value (@valuenames) {
					my (@data,$lastrun, $runcount);
					my $vData = $key2->GetValue($value);
					$value =~ tr/N-ZA-Mn-za-m/A-Za-z/;
					if (length($vData) == 16) {
						@data = unpack("V*",$vData);
						($data[1] > 5) ? ($runcount = $data[1] - 5) : ($runcount = $data[1]);
						$lastrun = getTime($data[2],$data[3]);
						print $value."\n";
						if ($lastrun == 0) {
							next;
						}
						else {
							print "\t".localtime($lastrun)." -- ($runcount)\n";
						}
					}
					else {
						print $value."\n";
					}
					print "\n";
				}
			} 
			else {
				print "Error accessing $subkey2: $! \n";
			}
		}
		else {
			die "Error connecting to $userassist key: $!\n";
		}
		
	}
	else {
		die "Error connecting to HKEY_CURRENT_USER hive: $! \n";
	}
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
# Thanks goes to Andreas Schuster for the below code, which he
# included in his ptfinder.pl
#---------------------------------------------------------
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