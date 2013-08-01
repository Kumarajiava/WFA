#! c:\perl\bin\perl.exe
#---------------------------------------------------------------------
# Perl script to parse Windows Event Log (.evt) files in 
# raw, binary mode (ie, neither special modules nor the 
# MS API are used).
#
# This script parses through a .evt file in binary mode, and locates
# event records (based on available MS documentation).  The script prints
# out the information contained in the event record.
#
# Usage: C:\Perl>[perl] lsevt.pl <path_to_file> [> output_file]
# Minor modification of the output will allow you to print the output
# to STDOUT in an Excel-compatible format
#
# Input : Takes the path to a .evt file as an argument
# Output: Prints out event-specific info to STDOUT
#
# Author: H. Carvey (keydet89@yahoo.com)
# Copyright 2005 H. Carvey
#---------------------------------------------------------------------

use strict;
use Getopt::Long;

my %config = ();
Getopt::Long::Configure("prefix_pattern=(-|\/)");
GetOptions(\%config, qw(file|f=s csv|c help|?|h));

if ($config{help} || ! %config) {
	\_syntax();
	exit 1;
}

die "You must enter a filename.\n" unless ($config{file});

my $file = $config{file};
die "$file not found.\n" unless (-e $file);

my %type = (0x0001 => "EVENTLOG_ERROR_TYPE",
  	          0x0010 => "EVENTLOG_AUDIT_FAILURE",
    	        0x0008 => "EVENTLOG_AUDIT_SUCCESS",
      	      0x0004 => "EVENTLOG_INFORMATION_TYPE",
        	    0x0002 => "EVENTLOG_WARNING_TYPE");

# Can uncomment this line out to print out header information      	    
#&parseHeader($file);

# Set initial offset to zero; can modify this value if working with
# fragments of .evt files 
my $offset = getFirstRecordOffset($file);
my ($size,$n);
#print "\n";
#print "First event located at offset ".$offset."\n";

#---------------------------------------------------------------------
open(EXE,"< $file") || die "Could not open $file: $!\n";
binmode(EXE);
while (<EXE>) {
	$size = readEventRecord($offset);
# At this point we need to determine where the next record is...
	$offset += $size;
	$n = locateNextRecord($offset);
	$offset += $n;
}
close(EXE);

#---------------------------------------------------------------------
# gets the offset to the first event record in the file
#---------------------------------------------------------------------
sub getFirstRecordOffset {
	my $file = $_[0];
	my ($record,$tag);
	open(EXE,"< $file") || die "Could not open $file: $!\n";
	binmode(EXE);
	my $i = 0;
	my $num_reads;
	seek(EXE,48,0);
	foreach my $i (1..10000) {
		read(EXE,$record,4);
		my $tag = unpack("L",$record);
		if ($tag == 0x654c664c) {
#			printf "$i : 0x%x    <--\n",$tag;
			close(EXE);
			return ((($i - 2) * 4) + 48);
		}
		else {
#			printf "$i : 0x%x\n",$tag;
			seek(EXE,48 + ($i * 4),0);
		}
	}
	close(EXE);
}
#---------------------------------------------------------------------
# locates the next event record
#---------------------------------------------------------------------
sub locateNextRecord {
	my $c_offset = $_[0];
	my $record;
	
	seek(EXE,$c_offset,0);
	
	foreach my $i (1..10000) {
		read(EXE,$record,4);
		my $tag = unpack("L",$record);
		if ($tag == 0x654c664c) {
#			printf "$i : 0x%x    <--\n",$tag;
			return (($i - 2) * 4);
		}
		else {
#			printf "$i : 0x%x\n",$tag;
			seek(EXE,$c_offset + ($i * 4),0);
		}
	}
}
#---------------------------------------------------------------------
# Reads an event record; prints out specific info; returns record length
#---------------------------------------------------------------------
sub readEventRecord {
# This offset is the point within the .evt file where the record
# begins
	my $offset = $_[0];
	my ($record,%hdr);
	seek(EXE,$offset,0);
# EventLogRecord structure
# http://msdn.microsoft.com/library/en-us/debug/base/eventlogrecord_str.asp
	read(EXE,$record,56);

	($hdr{length},$hdr{magic},$hdr{rec_num},$hdr{time_gen},$hdr{time_wrt},
	 $hdr{evtid1},$hdr{evtid2},$hdr{evttype},$hdr{numstrings},$hdr{evtcat},$hdr{c_rec},
	 $hdr{stroffset},$hdr{sid_len}, $hdr{sid_offset},$hdr{data_len},$hdr{data_offset}) 
		= unpack("LLLLLSSSSSx2LLLLLL",$record);
	
	if ($hdr{magic} == 0x654c664c) {
		
		my $chars = ($offset + $hdr{stroffset}) - ($offset + 56);
		seek(EXE,$offset + 56,0);
		read(EXE,$record,$chars);
		my ($source,$computername) = split(/\00/,_uniToAscii($record),2);
		$computername = (split(/\00/,$computername,2))[0];
 		if ($hdr{sid_len} > 0) {
			seek(EXE,$offset + $hdr{sid_offset},0);
			read(EXE,$record,$hdr{sid_len});
			$hdr{sid} = _translateBinary($record);
		}
 	
 		if ($hdr{numstrings} > 0) {
			my @list = ();
			$hdr{strings} = "";
			seek(EXE,$offset +  $hdr{stroffset},0);
			exit 1 if ($hdr{stroffset} > $hdr{data_offset});
			read(EXE,$record,$hdr{data_offset} - $hdr{stroffset});
			@list = split(//,$record);
 			map{$hdr{strings} .= $list[$_] unless ($_%2)} (0..(length($record) - 1));
		}

		if ($hdr{data_len} > 0) {
			seek(EXE,$offset + $hdr{data_offset},0);
			read(EXE,$record,$hdr{data_len});
			$hdr{data} = _translateBinary($record);
		}
		if ($config{csv}) {
			print $hdr{rec_num}.";".$hdr{evtid1}.";".$source.";".$computername.";".$type{$hdr{evttype}}.";"
       .$hdr{evtcat}.";".gmtime($hdr{time_gen}).";".gmtime($hdr{time_wrt}).";".$hdr{sid}.";"
       .$hdr{strings}.";".$hdr{data}."\n";
		}
		else { 	
 			print "Record Number : ".$hdr{rec_num}."\n";
 			print "Source        : ".$source."\n";
 			print "Computer Name : ".$computername."\n";
 			print "Event ID      : ".$hdr{evtid1}."\n";
			print "Event Type    : ".$type{$hdr{evttype}}."\n";
			print "Event Category: ".$hdr{evtcat}."\n";
			print "Time Generated: ".gmtime($hdr{time_gen})."\n";
			print "Time Written  : ".gmtime($hdr{time_wrt})."\n";
			print "SID           : ".$hdr{sid}."\n" if ($hdr{sid_len} > 0);
			print "Message Str   : ".$hdr{strings}."\n" if ($hdr{numstrings} > 0);
			print "Message Data  : ".$hdr{data}."\n" if ($hdr{data_len} > 0);
			print "\n";
		}

		return $hdr{length};
	}
	else {
		exit 1;
		
	}
}
#---------------------------------------------------------------------
# Parses header information from a .evt file
#---------------------------------------------------------------------
sub parseHeader {
	my $file = $_[0];
	my ($record,$tag);
	open(EXE,"< $file") || die "Could not open $file: $!\n";
	binmode(EXE);
	seek(EXE,0,0);
 	read(EXE,$record,48);
	my ($f_size,$magic,$filler1,$filler2,$oldestoffset,$nextoffset,
	    $nextID,$oldestID,$maxsize,$filler4,$retention,$l_size)   
			= unpack("LLLLLLLLLLLL",$record);
	print "Magic number located.\n" if ($magic == 0x654c664c);
	print "**ERROR: Header sizes not equal!!\n" unless ($f_size == $l_size);
	print "\n";
	print "Next record ID          -> $nextID\n";
	print "Oldest record ID        -> $oldestID\n";
	print "Total number of records -> ".($nextID - $oldestID)."\n";
	print "\n";
	print "Location where event ID ".$nextID." will be written.\n";
	printf "Next ID Offset -> 0x%x (".$nextoffset.")\n",$nextoffset;
	print "Location where event ID ".$oldestID." was written.\n";
	printf "Last Offset  -> 0x%x (".$oldestoffset.")\n",$oldestoffset;
	close(EXE);
}

#---------------------------------------------------------------------
# Translate binary into a string of hex pairs
#---------------------------------------------------------------------
sub _translateBinary {
	my $str = unpack("H*",$_[0]);
	my $len = length($str);
	my @nstr = split(//,$str,$len);
	my @list;
	foreach (0..($len/2)) {
		push(@list,$nstr[$_*2].$nstr[($_*2)+1]);
	}
	return join(' ',@list);
}
#----------------------------------------------------------------
# _uniToAscii()
# Input : Unicode string
# Output: ASCII string
# Removes every other \00 from Unicode strings, returns ASCII string
#----------------------------------------------------------------
sub _uniToAscii {
	my $str = $_[0];
	my $len = length($str);
	my $newlen = $len - 1;
	my @str2;
	my @str1 = split(//,$str,$len);
	foreach my $i (0..($len - 1)) {
		if ($i % 2) {
# In a Unicode string, the odd-numbered elements of the list will be \00
# so just drop them			
		}
		else {
			push(@str2,$str1[$i]);
		}
	}
	return join('',@str2);
}

#----------------------------------------------------------------
# _syntax()
#----------------------------------------------------------------
sub _syntax {

	print<< "EOT";
Lsevt  [-h] [-c] [-f file]
Parse Event log files in binary format.

  -f file......path to .evt file 
  -c ..........use .csv style output
  -h.............Help (print this information)
  
Ex: C:\\>lsevt -c -f c:\\windows\\system32\\config\\AppEvent.evt
  
copyright 2006-2007 H. Carvey
EOT
}