#! c:\perl\bin\perl.exe -w
#--------------------------------------------------------------------
# procmon.pl - Perl script to monitor the creation of processes
#           
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);
use Win32::OLE::Variant;

my $server = Win32::NodeName();
my $user = Variant(VT_BYREF | VT_BSTR,"");
my $domain = Variant(VT_BYREF | VT_BSTR,"");

# First, let's get some information about the operating system
my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($server,'root\cimv2',"","") 
	|| die "Error connecting to \\root\\cimv2 namespace on $server: ".
 Win32::OLE->LastError()."\n";

# Now, set up event query and loop
my $evtQuery = "SELECT * FROM __instancecreationevent WITHIN 1 WHERE targetinstance ".
								"ISA 'Win32_Process'";
my $events = Win32::OLE->GetObject("WinMgmts:{impersonationLevel=impersonate,(security)}")->
             ExecNotificationQuery($evtQuery) || die "Error: ".Win32::OLE->LastError()."\n";
print "Monitoring for new process creation events...\n";
printf "%-5s %-15s %-30s\n","PID","USER","PROCESS";
printf "%-5s %-15s %-30s\n","-" x 4,"-" x 10,"-" x 15;

while (my $event = $events->NextEvent) {
#	my $name = $event->{targetinstance}->{Name};
	my $cmd = $event->{targetinstance}->{CommandLine};
	my $path = $event->{targetinstance}->{ExecutablePath};
	my $pid  = $event->{targetinstance}->{ProcessID};
	$event->{targetinstance}->GetOwner($user,$domain);
	printf "%-5s %-15s %-40s\n",$pid,$user,$path." (".$cmd.")";
} 

