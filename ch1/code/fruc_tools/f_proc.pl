#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# f_proc.pl - Perl script to retrieve process information
#           Allows for checking of remote hosts
#
# Usage: C:\perl>proc.pl 
#        C:\perl>proc.pl <host> <username> <password>
#
# Copyright 2006 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);
use Win32::OLE::Variant;

my $server = shift || Win32::NodeName();
my $admin = shift || "";
my $passwd = shift || "";

my $user = new Win32::OLE::Variant( VT_BYREF | VT_BSTR, "" );
my $domain = new Win32::OLE::Variant( VT_BYREF | VT_BSTR, "" );

my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($server,'root\cimv2',$admin,$passwd) 
	|| die "Error connecting to $server: ".Win32::OLE->LastError()."\n";

# Access the Win32_Process class
# http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wmisdk/wmi/win32_process.asp
my %processes;
foreach my $proc (in $serverObj->InstancesOf("Win32_Process")) {
	$processes{$proc->{ProcessID}}{'ParentPID'} = $proc->{ParentProcessID};
	$processes{$proc->{ProcessID}}{'Name'}       = $proc->{Name};
	$processes{$proc->{ProcessID}}{'CommandLine'} = $proc->{CommandLine};
	$processes{$proc->{ProcessID}}{'ExecutablePath'} = $proc->{ExecutablePath};
	$processes{$proc->{ProcessID}}{'CreationDate'} = $proc->{CreationDate};
	$processes{$proc->{ProcessID}}{'ThreadCount'} = $proc->{ThreadCount};
	$processes{$proc->{ProcessID}}{'Priority'} = $proc->{Priority};
	$processes{$proc->{ProcessID}}{'SessionId'} = $proc->{SessionId};
#	$processes{$proc->{ProcessID}}{'UserModeTime'} = $proc->{UserModeTime};
	my $result = $proc->GetOwner($user,$domain);
	if (0 == $result) {
		$processes{$proc->{ProcessID}}{'User'} = $domain."\\".$user;
	}
}
# Access the Win32_Service class
# http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wmisdk/wmi/win32_service.asp
my %services;
foreach my $svc (in $serverObj->InstancesOf("Win32_Service")) {
	$services{$svc->{Name}}{'PID'}  = $svc->{ProcessID};
	$services{$svc->{Name}}{'Path'} = $svc->{PathName};
	$services{$svc->{Name}}{'StartName'} = $svc->{StartName};
	$services{$svc->{Name}}{'DisplayName'} = $svc->{DisplayName};
	$services{$svc->{Name}}{'State'} = $svc->{State};
	$services{$svc->{Name}}{'ServiceType'} = $svc->{ServiceType};
	$services{$svc->{Name}}{'TagID'} = $svc->{TagID};
}

# PID,Name,User,ParentPID,CmdLine,Exe,Services
foreach (keys %processes) {
	my $parentname = $processes{$processes{$_}{'ParentPID'}}{'Name'};
	print $_.";".$processes{$_}{'Name'}.";".$processes{$_}{'User'}.";".
	$processes{$_}{'ParentPID'}." [".$parentname."];".$processes{$_}{'CommandLine'}.";". 
	$processes{$_}{'ExecutablePath'}.";";
	my @svcs = ();
	foreach my $n (keys %services) {
		push(@svcs,$n) if ($services{$n}{'PID'} == $_);
	}
	print (join(',',@svcs)) if (@svcs);
	print "\n";
}