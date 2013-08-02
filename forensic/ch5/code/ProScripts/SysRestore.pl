#! c:\perl\bin\perl.exe
#-------------------------------------------------------------
# SysRestore.pl, version 0.1
# ProScript to parse the System Restore subdirectories for rp.log files, and 
# then parse the files for description and creation time info                         
#
# Copyright 2007 H. Carvey, keydet89@yahoo.com
#-------------------------------------------------------------
use ProScript;
PSDisplayText("SysRestore.pl v. 0.1");
PSDisplayText("ProScript to parse through the System Restore subdirectories on Windows XP");
PSDisplayText("systems and return the descriptions and creation times from the rp\.log files.");
PSDisplayText("\n");
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

while (1) {
	$RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
  last if ($RegKeyInfo->{nType} == -1);
  next if ($RegKeyInfo->{nType} == PS_TYPE_KEY);
  my $value = $RegKeyInfo->{strRegName};
  my $data  = $RegKeyInfo->{strValueData};
#  PSDisplayText($value." --> ".$data);
  $sysinfo{$value} = $data;
}
PSCloseHandle($rHandle);
#-------------------------------------------------------------
# Now we have a %sysinfo hash, and all we really want is the 
# "SystemRoot" value

my $sysroot = $sysinfo{"SystemRoot"};
my $drive   = (split(/:/,$sysinfo{"SystemRoot"},2))[0];
# $drive should now just be a drive letter 

my $objectName = PSGetObjectName(0);
my $path       = $objectName."\\".$drive.":\\System Volume Information";

#---------------------------------------------------------
# First, we need to get the name of the _restore directory
#---------------------------------------------------------
my $pHandle = PSOpenDir($path,0);
if ($pHandle == NULL) {
	PSDisplayText("$path not opened.");
}
my $rest = "_restore";
my $restoredir;
my $tag = 1;
while ($tag) {
	my $file = &ProScript::PSReadDirectory($pHandle);
	$tag = 0 if ($file == NULL || $file->{strName} eq "");
	$restoredir = $file->{strName} if ($file->{bIsDirectory} && $file->{strName} =~ m/^$rest/i);
#	PSDisplayText("Name : $file->{strName}");
}
PSCloseHandle($pHandle);

$path = $path."\\".$restoredir."\\";

#---------------------------------------------------------
# Now, we need to get the list of subdirectories
#---------------------------------------------------------
my @rpdirs = ();
my $rpdir = "RP";

my $pHandle = PSOpenDir($path,0);
if ($pHandle == NULL) {
	PSDisplayText("$path not opened.");
}
my $tag = 1;
while ($tag) {
	my $file = &ProScript::PSReadDirectory($pHandle);
	$tag = 0 if ($file == NULL || $file->{strName} eq "");
	push(@rpdirs,$file->{strName}) if ($file->{bIsDirectory} && $file->{strName} =~ m/^$rpdir/);
#	PSDisplayText("Name : $file->{strName}");
}
PSCloseHandle($pHandle);

foreach my $rp (@rpdirs) {
	$rp_path = $path.$rp."\\rp\.log";
	my $descr = getRpDescr($rp_path);
	my $creation = getCreationTime($rp_path);
	PSDisplayText($rp."   ".$creation." (UTC)   ".$descr);
}


#---------------------------------------------------------
# getCreationTime()
# Read the rp.log file to get the description and creation
# date
#---------------------------------------------------------
sub getCreationTime {
	my $path = shift;
	my $t_val = 0;
	if (my $oFile = PSOpen($path)) {
		if (PSSeek($oFile,0x210,0,PS_FILE_BEGIN)) {
			my $buffer = PSReadRaw($oFile,8);
			PSCloseHandle($oFile);
			my @vals = unpack("VV",$buffer);
			$t_val = getTime($vals[0],$vals[1]);
		}
		else {
			PSDisplayText("File seek to first offset failed.");
		}
	}
	else {
		PSDisplayText("File could not be opened.");
	}	
	return gmtime($t_val);
}

#---------------------------------------------------------
# getRpDescr()
# Read the rp.log file to get the description and creation
# date
#---------------------------------------------------------
sub getRpDescr {
	my $path = shift;
	my $buffer;
	my $tag = 1;
	my $offset = 0x10;
	my @strs;
	my $str;
	my $oFile;
	if ($oFile = PSOpen($path)) {
		while ($tag) {
			PSSeek($oFile,$offset,0,PS_FILE_BEGIN);
			$buffer = PSReadRaw($oFile,2);
			if (unpack("v",$buffer) == 0) {
				$tag = 0;
				
			}
			else {
				push(@strs,$buffer);
			}
			$offset += 2;
		}
		
	}
	else {
		PSDisplayText("File could not be opened.");
	}	
	PSClose($oFile);
	my $str = join('',@strs);
	$str =~ s/\00//g;
	return $str;
}

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