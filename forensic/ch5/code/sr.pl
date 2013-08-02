#! c:\perl\bin\perl.exe
#------------------------------------------------------
# sr.pl
# Use WMI to get Restore point settings from XP (local or remote)
#
# Usage: sr.pl
#
# http://msdn.microsoft.com/library/default.asp?url=/library/
#        en-us/sr/sr/system_restore_wmi_classes.asp
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Win32::OLE qw(in);

my $server = shift || Win32::NodeName();
my $user   = shift || "";
my $pwd    = shift || "";

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;

my $serverObj = $locatorObj->ConnectServer($server,'root\cimv2',$user,$pwd) 
	|| die "Error connecting to ".$server.": ".Win32::OLE->LastError()."\n";
# Check to see if you're working with XP
my $name;
foreach my $rp (in $serverObj->InstancesOf("Win32_OperatingSystem")) {
	$name = (split(/\|/,$rp->{Name}))[0];
}
my $xp = "XP";
if (! grep(/$xp/,$name)) {
	die "$name is not XP\n";
}
undef $serverObj;
my $serverObj = $locatorObj->ConnectServer($server,'root\default',$user,$pwd) 
	|| die "Error connecting to ".$server.": ".Win32::OLE->LastError()."\n";

print "Restore Point settings for ".Win32::NodeName()."\n";
print "-" x 25,"\n";
foreach my $rp (in $serverObj->InstancesOf("SystemRestoreConfig")) {
	print "RPGlobalInterval  = ".$rp->{RPGlobalInterval}."\n";
	print "RPLifeInterval    = ".$rp->{RPLifeInterval}."\n";
	print "RPSessionInterval = ".$rp->{RPSessionInterval}."\n";
	print "DiskPercent       = ".$rp->{DiskPercent}."\n";
}
print "\n";
my $datetime = Win32::OLE->new("WbemScripting.SWbemDateTime") || die "Could not create datetime object\n";
print "Restore points\n";
printf "%-2s %-20s %-40s\n","RP","Creation Date","Description";
printf "%-2s %-20s %-40s\n","-" x 2, "-" x 15, "-" x 12;
foreach my $rp (in $serverObj->InstancesOf("SystemRestore")) {
	$datetime->{Value} = $rp->{CreationTime};
	printf $rp->{SequenceNumber}." %02d:%02d:%02d %02d/%02d/%04d  ".$rp->{Description}."\n",
		$datetime->{Hours}, $datetime->{Minutes}, $datetime->{Seconds},$datetime->{Month}, 
		$datetime->{Day}, $datetime->{Year};
}