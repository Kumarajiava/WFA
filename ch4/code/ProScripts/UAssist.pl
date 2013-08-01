#! c:\Perl\bin\perl.exe
#-------------------------------------------------------------
# UAssist.pl, version 0.11                                  
# Extract data from the UserAssist keys within the Registry
# of a ProDiscover project.  To use, insure that you have populated
# the Registry view.
#
# Copyright 2007 H. Carvey, keydet89@yahoo.com
#-------------------------------------------------------------
use ProScript;

PSDisplayText("UserAssist.pl v.0.11, 20060522");
PSDisplayText("ProScript to parse the UserAssist keys within each user's Registry file");
PSDisplayText("decrypt the values, and display the data as a GMT time, where applicable.");
PSDisplayText("Also, values with time-stamped data are sorted by time, in reverse order, so");
PSDisplayText("that timelining the user activity is done more readily.");
PSDisplayText("\n");
my @sids = ();
$numRegs = PSGetNumRegistries();

if ($numRegs == 0) {
	PSDisplayText("No registries to process");
	return;
}

$regName = PSGetRegistryAt(0);
PSRefreshRegistry($regName);
#-------------------------------------------------------------
my $hiveName = "HKEY_Users";
my $rHandle = PSOpenRegistry($regName, $hiveName);
my @sids = ();

if ($rHandle == 0) {
	PSDisplayText("Unable to locate registry key");
	return;
}
else {
	PSDisplayText("Registry opened succesfully.");
}
#Successfully opened the key. Now, enumerate the key.
while (1) {
	$RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
	last if ($RegKeyInfo->{nType} == -1);
	push(@sids,$RegKeyInfo->{strRegName}) if (length($RegKeyInfo->{strRegName}) > 20);
}
PSCloseHandle($rHandle);
PSDisplayText("Registry handle closed.");

# Now that we have the SIDs, let's enumerate through the keys
my @guids  = ("{5E6AB780-7743-11CF-A12B-00AA004AE837}\\Count",
	            "{75048700-EF1F-11D0-9888-006097DEACF9}\\Count");
	            
my $key_path = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\";


foreach my $sid (@sids) {
	
# use %sorter as a hash-of-arrays data structure for maintaining a sorted list of 
# times 
	my %sorter = ();

	foreach my $g (@guids) {
		my $key = $hiveName."\\".$sid.$key_path.$g;
		PSDisplayText("Key : $key");
		my $rHandle = PSOpenRegistry($regName,$key);
		while (1) {
    	$RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
    	last if ($RegKeyInfo->{nType} == -1);
    	next if ($RegKeyInfo->{strRegName} eq "(Default)");
    	my $value = $RegKeyInfo->{strRegName};
    	$value =~ tr/N-ZA-Mn-za-m/A-Za-z/;
#	   	PSDisplayText("\t".$value);
    	
    	my $data = $RegKeyInfo->{strValueData};
    	my $l    = length($data);
    	if ($l == 16) {
 	  		my @vals = unpack("V4",substr($data,0,16));
    		my $gtime = _getTimeDate($vals[3],$vals[2]);
    		if ($gtime > 0) {
    			PSDisplayText("\t".$value." --> ".gmtime($gtime));

# The following code adds the ROT-13 (decrypted) entry to an array in the hash-of-arrays
# data structure     			
    			if ($g eq "{75048700-EF1F-11D0-9888-006097DEACF9}\\Count") {
    				push(@{$sorter{$gtime}},$value);
    			}
    		}
    		else {
    			PSDisplayText("\t".$value);
    		}
    	}
		}
		PSCloseHandle($rHandle);
	}
	PSDisplayText("\n");
# Display the time-based entries in reverse order, listing the entries that
# were accessed at that date/time beneath the time 
	PSDisplayText("Time-sorted Entries");
	foreach my $item (reverse sort {$a <=> $b} keys %sorter) {
		PSDisplayText(" --> ".gmtime($item));
		foreach my $pdl (@{$sorter{$item}}) {
			PSDisplayText("\t --> $pdl");
		}
	}
	PSDisplayText("\n");
}

#----------------------------------------------------------------
# _getTimeDate()
# Input : 2 DWORDs, each containing half of the LastWrite time
# Output: readable GMT time string
#----------------------------------------------------------------
sub _getTimeDate {
# Borrowed from Andreas Schuster's ptfinder code
	my $Hi = shift;
	my $Lo = shift;
	my $t;
	if (($Lo == 0) and ($Hi == 0)) {
		$t = 0;
	} 
	else {
		$Lo -= 0xd53e8000;
		$Hi -= 0x019db1de;
		$t = int($Hi*429.4967296 + $Lo/1e7);
	}
	$t = 0 if ($t < 0);
	return $t;
}