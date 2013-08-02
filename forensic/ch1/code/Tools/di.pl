#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# di.pl - Disk ID tool
# This script is intended to assist investigators in identifying disks
#   attached to systems.  It can be used by an investigator to document
#   a disk following acquisition, providing information for use in 
#   acquisition worksheets and chain-of-custody documentation.
#
#   This tool may also be run remotely against managed system, by passing
#   the necessary arguments at the command line.
# 
# Usage: di.pl 
#        di.pl <system> <username> <password>
#
# copyright 2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);

my $server = shift || Win32::NodeName();
my $user   = shift || "";
my $pwd    = shift || "";

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($server,'root\cimv2',$user,$pwd) 
	|| die "Error connecting to $server: ".Win32::OLE->LastError()."\n";

my %capab =  (0 =>	"Unknown",
							1 =>	"Other",
							2 =>	"Sequential Access",
							3 =>	"Random Access",		
							4 =>	"Supports Writing",
							5 =>	"Encryption",
							6 =>	"Compression",
							7 =>	"Supports Removable Media",
							8 =>	"Manual Cleaning",
							9 =>	"Automatic Cleaning",
							10 =>	"SMART Notification",
							11 => "Supports Dual Sided Media",
							12 =>	"Ejection Prior to Drive Dismount Not Required");
my %disk = ();
foreach my $drive (in $serverObj->InstancesOf("Win32_DiskDrive")) {
	$disk{$drive->{Index}}{DeviceID}      = $drive->{DeviceID};
	$disk{$drive->{Index}}{Manufacturer}  = $drive->{Manufacturer};
	$disk{$drive->{Index}}{Model}         = $drive->{Model};
	$disk{$drive->{Index}}{InterfaceType} = $drive->{InterfaceType};
	$disk{$drive->{Index}}{MediaType}     = $drive->{MediaType};
	$disk{$drive->{Index}}{Partitions}    = $drive->{Partitions};
# The drive signature is a DWORD value written to offset 0x1b8 (440) in the MFT
# when the drive is formatted.  This value can be used to identify a specific HDD,
# either internal/fixed or USB/external, by corresponding the signature to the
# values found in the MountedDevices key of the Registry
	$disk{$drive->{Index}}{Signature}     = $drive->{Signature};
	$disk{$drive->{Index}}{Size}          = $drive->{Size};
	$disk{$drive->{Index}}{Capabilities}  = $drive->{Capabilities};
}

my %diskpart = ();
foreach my $part (in $serverObj->InstancesOf("Win32_DiskPartition")) {
	$diskpart{$part->{DiskIndex}.":".$part->{Index}}{DeviceID} = $part->{DeviceID};
	$diskpart{$part->{DiskIndex}.":".$part->{Index}}{Bootable} = 1 if ($part->{Bootable});
	$diskpart{$part->{DiskIndex}.":".$part->{Index}}{BootPartition} = 1 if ($part->{BootPartition});
	$diskpart{$part->{DiskIndex}.":".$part->{Index}}{PrimaryPartition} = 1 if ($part->{PrimaryPartition});
	$diskpart{$part->{DiskIndex}.":".$part->{Index}}{Type} = $part->{Type};
}

foreach my $dd (sort keys %disk) {
	print  "DeviceID  : ".$disk{$dd}{DeviceID}."\n";
	print  "Model     : ".$disk{$dd}{Model}."\n";
	print  "Interface : ".$disk{$dd}{InterfaceType}."\n";
	print  "Media     : ".$disk{$dd}{MediaType}."\n";
	print  "Capabilities : \n";
	foreach my $c (in $disk{$dd}{Capabilities}) {
		print  "\t".$capab{$c}."\n";
	}
	my $sig = $disk{$dd}{Signature};
	$sig = "<None>" if ($sig == 0x0);
	printf "Signature : 0x%x\n",$sig;
	
	print "\n";
	print $disk{$dd}{DeviceID}." Partition Info : \n";
	my $part = $disk{$dd}{Partitions};
	foreach my $p (0..($part - 1)) {
		my $partition = $dd.":".$p;
		print "\t".$diskpart{$partition}{DeviceID}."\n";
		print "\t".$diskpart{$partition}{Type}."\n";
		print "\t\tBootable\n" if ($diskpart{$partition}{Bootable});
		print "\t\tBoot Partition\n" if ($diskpart{$partition}{BootPartition});
		print "\t\tPrimary Partition\n" if ($diskpart{$partition}{PrimaryPartition});
		print "\n";
	}
}