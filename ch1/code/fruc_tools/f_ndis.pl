#! c:\perl\bin\perl.exe
#--------------------------------------------------------------------
# f_ndis.pl - Perl script to determine settings of NIC;
#             Checks for promiscuous mode
#             Used with the FRUC tool
#
# Copyright 2006 H. Carvey keydet89@yahoo.com
#--------------------------------------------------------------------
use strict;
use Win32::OLE qw(in);

# OID_GEN_CURRENT_PACKET_FILTER values defined in ntddndis.h
# http://msdn.microsoft.com/library/default.asp?url=/library/en-us/
#        wceddk5/html/wce50lrfoidgencurrentpacketfilter.asp
my %filters = ("NDIS_PACKET_TYPE_DIRECTED" =>	0x00000001,
							 "NDIS_PACKET_TYPE_MULTICAST" => 0x00000002,
							 "NDIS_PACKET_TYPE_ALL_MULTICAST" =>	0x00000004,
							 "NDIS_PACKET_TYPE_BROADCAST" => 0x00000008,
							 "NDIS_PACKET_TYPE_SOURCE_ROUTING" =>	0x00000010,
							 "NDIS_PACKET_TYPE_PROMISCUOUS" =>	0x00000020,
							 "NDIS_PACKET_TYPE_SMT" =>	0x00000040,
							 "NDIS_PACKET_TYPE_ALL_LOCAL" =>	0x00000080,
							 "NDIS_PACKET_TYPE_GROUP" =>	0x00000100,
							 "NDIS_PACKET_TYPE_ALL_FUNCTIONAL" =>	0x00000200,
							 "NDIS_PACKET_TYPE_FUNCTIONAL" =>	0x00000400,
							 "NDIS_PACKET_TYPE_MAC_FRAME" =>	0x00000800);

my $server = Win32::NodeName();
my %nic = ();
my $locatorObj = Win32::OLE->new('WbemScripting.SWbemLocator') || die 
	"Error creating locator object: ".Win32::OLE->LastError()."\n";
$locatorObj->{Security_}->{impersonationlevel} = 3;
my $serverObj = $locatorObj->ConnectServer($server,'root\wmi',"","") 
	|| die "Error connecting to \\root\\wmi namespace on $server: ".
 Win32::OLE->LastError()."\n";

foreach my $ndis (in $serverObj->InstancesOf("MSNdis_CurrentPacketFilter")) {
	if ($ndis->{Active}) {
		my $wan = "WAN Miniport";
		next if ($ndis->{InstanceName} =~ m/^$wan/i);
		my $instance = (split(/-/,$ndis->{InstanceName}))[0];
		$instance =~ s/\s$//;
#		$nic{$instance} = 1;
		my @gpf = ();
		foreach my $f (keys %filters) {
			push(@gpf,$f) if ($ndis->{NdisCurrentPacketFilter} & $filters{$f});
		}
		$nic{$instance}{filter} = join(';',@gpf);
	}
}

foreach (keys %nic) {
	print "$_;$nic{$_}{filter}\n";
}
