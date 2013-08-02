#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# f_svc.pl - Perl script to retrieve service information
#           Allows for checking of remote hosts
#
# Usage: C:\perl>svc.pl 
#        C:\perl>svc.pl <host> <username> <password>
#
# Copyright 2006 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);
use Win32::OLE::Variant;

my $server = shift || Win32::NodeName();
my $admin = shift || "";
my $passwd = shift || "";

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($server,'root\cimv2',$admin,$passwd) 
	|| die "Error connecting to $server: ".Win32::OLE->LastError()."\n";

foreach my $svc (in $serverObj->InstancesOf("Win32_Service")) {
	print $svc->{Name}.";".$svc->{DisplayName}.";".$svc->{StartName}.";".$svc->{Description}.
		";".$svc->{ProcessID}.";".$svc->{PathName}.";".$svc->{StartMode}.";".
		$svc->{State}.";".$svc->{Status}.";".$svc->{ServiceType}.";".
		$svc->{TagID}."\n";
}
