#! c:\perl\bin\perl.exe
#-------------------------------------------------------------
# Prefetch.pl, version 0.1_20061026
# ProScript to parse the Prefetch directory for .pf files, and 
# then parse the files for run count and last run time.                         
#
# Copyright 2007 H. Carvey, keydet89@yahoo.com
#-------------------------------------------------------------
use ProScript;
PSDisplayText("Prefetch.pl v. 0.1_20061026");
PSDisplayText("ProScript to parse through the Prefetch directory on Windows XP");
PSDisplayText("systems and return the filename, time last accessed, and the run-count");
PSDisplayText(" -> Requires ProDiscover v. 4.85 or higher");
#-------------------------------------------------------------
# Get the SystemRoot value
my %sysinfo = ();
$numRegs = PSGetNumRegistries();

if ($numRegs == 0) {
	PSDisplayText("No registries to process");
	return;
}

$regName = PSGetRegistryAt(0);
PSRefreshRegistry($regName);
my $keyName = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion";
my $rHandle = PSOpenRegistry($regName, $keyName);

if ($rHandle == 0) {
	PSDisplayText("Unable to locate registry key");
	return;
}
else {
#	PSDisplayText("Registry opened succesfully.");
}
# Access the key in order to get the SystemRoot value
while (1) {
	$RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
  last if ($RegKeyInfo->{nType} == -1);
  next if ($RegKeyInfo->{nType} == PS_TYPE_KEY);
  my $value = $RegKeyInfo->{strRegName};
  my $data  = $RegKeyInfo->{strValueData};  
  $sysinfo{$value} = $data;
}
PSCloseHandle($rHandle);
#-------------------------------------------------------------
# Now we have a %sysinfo hash, and all we really want is the 
# "SystemRoot" value

my $sysroot = $sysinfo{"SystemRoot"};
$sysroot = $sysroot."\\" unless ($sysroot =~ m/\\$/);
# Note: Make sure that the first letter (ie, the drive letter) of the 
# SystemRoot path is capitalized; this is an issue with ProDiscover
$sysroot = ucfirst($sysroot);

my $objectName = PSGetObjectName(0);
my $path       = $objectName."\\".$sysroot."Prefetch";

my $pHandle = PSOpenDir($path,0);
if ($pHandle == NULL) {
	PSDisplayText("$path not opened.");
}

my $tag = 1;
while ($tag) {
	my $file = &ProScript::PSReadDirectory($pHandle);
	$tag = 0 if ($file == NULL || $file->{strName} eq "");
	my $pf = "pf";
	next if ($file->{bIsDirectory});
	next unless ($file->{strName} =~ m/$pf$/);
	my $filepath = $path."\\".$file->{strName};
	my ($t_val,$run);
	if (my $oFile = PSOpen($filepath)) {		
		if (PSSeek($oFile,0x78,0,PS_FILE_BEGIN)) {
			my $buffer = PSReadRaw($oFile,8);
			my @vals = unpack("VV",$buffer);
			$t_val = getTime($vals[0],$vals[1]);
		}
		else {
			PSDisplayText("File seek to first offset failed.");
		}
# Get the Run count		
		if (PSSeek($oFile,0x90,0,PS_FILE_BEGIN)) {
			my $buffer = &ProScript::PSReadRaw($oFile,4);
			PSCloseHandle($oFile);
			$run = unpack("V",$buffer);
		}
		else {
			PSDisplayText("File seek to second offset failed.");
		}
		
		PSDisplayText($file->{strName}."  ".gmtime($t_val)." (UTC)  ".$run);
		
	}
	else {
		PSDisplayText("File could not be opened.");
	}	
}
PSCloseHandle($pHandle);

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