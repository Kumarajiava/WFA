#! c:\perl\bin\perl.exe
#------------------------------------------------------
# lsevt.pl
# Perl script to parse the contents of a Windows EVT file
#   and display the event records
#
# usage: lsevt.pl <path to EVT file>
#
# NOTE: Requires the use of the File::ReadEvt module
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use File::ReadEvt;

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

my $evt = File::ReadEvt::new($file);
my %hdr = ();
if (%hdr = $evt->parseHeader()) {
# no need to do anything...	
}
else {
	print "Error : ".$evt->getError()."\n";
	die;
}

my $ofs = $evt->getFirstRecordOffset();

while ($ofs) {

	my %record = $evt->readEventRecord($ofs);
	print "Record Number : ".$record{rec_num}."\n";
 	print "Source        : ".$record{source}."\n";
 	print "Computer Name : ".$record{computername}."\n";
 	print "Event ID      : ".$record{evt_id}."\n";
	print "Event Type    : ".$record{evt_type}."\n";
	print "Time Generated: ".gmtime($record{time_gen})."\n";
	print "Time Written  : ".gmtime($record{time_wrt})."\n";
	print "SID           : ".$record{sid}."\n" if ($record{sid_len} > 0);
	print "Message Str   : ".$record{strings}."\n" if ($record{num_str} > 0);
	print "Message Data  : ".$record{data}."\n" if ($record{data_len} > 0);
	print "\n";

# length of record is $record{length}...skip forward that far
	$ofs = $evt->locateNextRecord($record{length});
#	printf "Current Offset = 0x%x\n",$evt->getCurrOfs();
}
$evt->close();

