#! c:\perl\bin\perl.exe
#------------------------------------------------------
# fw.pl
# Use WMI to get info about the Windows firewall, as well as
# information from the SecurityCenter
#
# Usage: fw.pl [-bsph] [-app] [-sec]
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use Win32::OLE qw(in);
use Getopt::Long;
my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(b s sec p app help|?|h));

# if -h, print syntax info and exit
if ($config{help}) {
	\_syntax();
	exit 1;
}

# some global hashes used throughout the code
my %proto = (6 => "TCP",
             17 => "UDP");

my %ipver = (0 => "IPv4",
             1 => "IPv6",
             2 => "Any");

my %type = (0 => "DomainProfile",
	          1 => "StandardProfile");
	          
print "[".localtime(time)."] Checking Windows Firewall on ".Win32::NodeName()."...\n"
  unless ($config{sec});

# Create necessary objects
my $fwmgr = Win32::OLE->new("HNetCfg.FwMgr") 
	|| die "Could not create firewall mgr obj: ".Win32::OLE::LastError()."\n";
my $fwprof = $fwmgr->LocalPolicy->{CurrentProfile};

if (! %config || $config{b}) {
# Profile type: 0 = Domain, 1 = Standard
	print "Current Profile = ".$type{$fwmgr->{CurrentProfileType}}."  ";

	if ($fwprof->{FirewallEnabled}) {
		print "(Enabled)\n";
	}
	else {
		print "(Disabled)\n";
		exit(1);
	}
	($fwprof->{ExceptionsNotAllowed}) ?(print "Exceptions not allowed\n"):(print "Exceptions allowed\n");
	($fwprof->{NotificationsDisabled})?(print "Notifications Disabled\n"):(print "Notifications not disabled\n");
	($fwprof->{RemoteAdminSettings}->{Enabled}) ? (print "Remote Admin Enabled\n") : (print "Remote Admin Disabled\n"); 
	print "\n";
}

if (! %config || $config{app}) {
	print "[Authorized Applications]\n";
	foreach my $app (in $fwprof->{AuthorizedApplications}) {
		if ($app->{Enabled} == 1) {
			print $app->{Name}." - ".$app->{ProcessImageFileName}."\n";
			print "IP Version = ".$ipver{$app->{IPVersion}}."; Remote Addrs = ".$app->{RemoteAddresses}."\n";
			print "\n";
		}
	}
}

if (! %config || $config{p}) {
	print "[Globablly Open Ports]\n";
	foreach my $port (in $fwprof->{GloballyOpenPorts}) {
		if ($port->{Enabled} == 1) {
			my $pp = $port->{Port}."/".$proto{$port->{Protocol}};
			printf "%-8s %-35s %-20s\n",$pp,$port->{Name},$port->{RemoteAddresses};
		}
	}
	print "\n";
}

if (! %config || $config{s}) {
	print "[Services]\n";
	foreach my $srv (in $fwprof->{Services}) {
		if ($srv->{Enabled}) {
			print $srv->{Name}." (".$srv->{RemoteAddresses}.")\n";
			foreach my $port (in $srv->{GloballyOpenPorts}) {
				if ($port->{Enabled} == 1) {
					my $pp = $port->{Port}."/".$proto{$port->{Protocol}};
					printf "  %-8s %-35s %-20s\n",$pp,$port->{Name},$port->{RemoteAddresses};
				}
			}
			print "\n";
		}
	}
}

# Check the SecurityCenter for additional, installed, WMI-managed FW and/or AV software
# Some AV products are not WMI-aware, and may need a patch installed 
if ($config{sec}) {
	my $server = Win32::NodeName();	
	print "[".localtime(time)."] Checking SecurityCenter on $server...\n";
	my $objWMIService = Win32::OLE->GetObject("winmgmts:\\\\$server\\root\\SecurityCenter") || die "WMI connection failed.\n";

# Alternative method
# my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
#	"Error creating locator object: ".Win32::OLE->LastError()."\n";
# $locatorObj->{Security_}->{impersonationlevel} = 3;
# my $objWMIService = $locatorObj->ConnectServer($server,'root\SecurityCenter',"","") 
#	|| die "Error connecting to $server: ".Win32::OLE->LastError()."\n";

	my $fwObj = $objWMIService->InstancesOf("FirewallProduct");
	if (scalar(in $fwObj) > 0) {
		foreach my $fw (in $fwObj) {
			print "Company  = ".$fw->{CompanyName}."\n";
			print "Name     = ".$fw->{DisplayName}."\n";
			print "Enabled  = ".$fw->{enabled}."\n";
			print "Version  = ".$fw->{versionNumber}."\n";
		}
	}
	else {
		print "There do not seem to be any non-MS, WMI-enabled FW products installed.\n";
	}

	my $avObj = $objWMIService->InstancesOf("AntiVirusProduct");
	if (scalar(in $avObj) > 0) {
		foreach my $av (in $avObj) {
			print "Company  = ".$av->{CompanyName}."\n";
			print "Name     = ".$av->{DisplayName}."\n";
			print "Version  = ".$av->{versionNumber}."\n";
			print "O/A Scan = ".$av->{onAccessScanningEnabled}."\n";
			print "UpToDate = ".$av->{productUptoDate}."\n";
		}
	}
	else {
		print "There do not seem to be any WMI-managed A/V products installed.\n";
	}
}

sub _syntax {
	print<< "EOT";
fw [-bsph] [-app]
Collect information about the Windows firewall (local system only) and
the SecurityCenter (additional WMI-managed FW and AV products)

  -b   ............Basic info about Windows firewall only
  -app ............Display authorized application info for the Windows 
                   firewall (enabled only)
  -s   ............Display service info for the Windows firewall (enabled only)
  -p   ............Display port info for Windows firewall (enabled only)
  -sec ............Display info from the SecurityCenter (other installed, WMI-
                   managed FW and/or AV) 
  -h   ............Help (print this information)
  
Ex: C:\\>fw -s <server> -u <username> -p <password>
  
copyright 2006-2007 H. Carvey
EOT
}