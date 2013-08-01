#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# svc.pl - Perl script to retrieve service information
#           Allows for checking of remote hosts
#
# Usage: C:\perl>svc.pl 
#        C:\perl>svc.pl <host> <username> <password>
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
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
	print "Name    : ".$svc->{Name}."\n";
	print "Display : ".$svc->{DisplayName}."\n";
	print "Start   : ".$svc->{StartName}."\n";
	print "Desc    : ".$svc->{Description}."\n";
	print "PID     : ".$svc->{ProcessID}."\n";
	print "Path    : ".$svc->{PathName}."\n";
	print "Mode    : ".$svc->{StartMode}."\n";
	print "State   : ".$svc->{State}."\n";
	print "Status  : ".$svc->{Status}."\n";
	print "Type    : ".$svc->{ServiceType}."\n";
	print "TagID   : ".$svc->{TagID}."\n";
	print "\n";
}
