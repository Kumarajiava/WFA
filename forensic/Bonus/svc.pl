#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# svc.pl - Perl script to retrieve service information
#           Allows for checking of remote hosts
#
# This version of svc.pl is similar to the one found in chapter 1, however,
# it prints out its output in CSV format:
# PID,Name,DisplayName,Pathname,State,StartMode,ServiceType,Descr String (or not)
#
# Usage: C:\perl>svc.pl 
#        C:\perl>svc.pl <host> <username> <password>
#
# Copyright 2006-2007 H. Carvey keydet89@yahoo.com
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
	my $tag;
# If the service has a description string, print "*"; else print "#"
	($svc->{Description} eq "") ? ($tag = "*") : ($tag = "#");
	print $svc->{ProcessID}.",".$svc->{Name}.",".$svc->{DisplayName}.",".$svc->{PathName}.
	      ",".$svc->{State}.",".$svc->{StartMode}.",".$svc->{ServiceType}.",".$tag."\n";
}
