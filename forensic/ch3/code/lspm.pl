#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------
# lspm.pl - dump the memory pages used by a process from a 
#           Windows 2000 phys. memory/RAM dump,
#             
# Version 0.4
#
# Usage: lspm.pl <filename> <offset>
#        Determine the offset of the the process you're interested in by 
#        running lsproc.pl first
#
# copyright 2007 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------------
use strict;
# Usage info
print "lspm - list Windows 2000 process memory (v.0.4 - 20060524)\n";
print "Ex: lspm dfrws-mem1\.dmp 0x0414dd60\n";
print "\n";

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);
my $offset = hex(shift) || die "You must enter a process offset.\n";
my $data;
my $error;

open(FH,"<",$file) || die "Could not open $file : $!\n";
binmode(FH);
seek(FH,$offset,0);
read(FH,$data,4);
my $hdr = unpack("V",$data);
if ($hdr == 0x001b0003) {
	seek(FH,$offset,0);
	my $bytes = read(FH,$data,0x290);
	if (0x290 == $bytes) {
		if (my %proc = isProcess($data)) {
			printf "Name : ".$proc{name}." -> 0x%08x\n",$proc{directorytablebase};
			my @pages = getMemoryPages($proc{directorytablebase});
			print "There are ".scalar(@pages)." pages (".(scalar(@pages) * 4096)." bytes) to process.\n";	
			$proc{name} =~ s/\.exe$//;
			my $outfile = $proc{name}."\.dmp";
			open(OUT,">",$outfile) || die "Could not open $outfile: $!\n";
					
			print "Dumping process memory to $outfile...\n";
			
			foreach my $page (@pages) {
				seek(FH,$page,0);
				read(FH,$data,4096);
				print OUT $data;
			}
			close(OUT);
			
			print "Done.\n";
			
		}
	}
}

close(FH);


#---------------------------------------------------------
# isProcess()
# check to see if we have a valid process (Win2K SP4)
# Input : 652 bytes starting at the offset
# Output: Hash containing EPROCESS block info, undef if not a valid 
#         EPROCESS block
# NOTE  : All that's needed for this utility is the DirectoryTableBase
#---------------------------------------------------------
sub isProcess {
	my $data = shift;
	my %proc = ();
	my $event1 = unpack("V",substr($data,0x13c,4));
	my $event2 = unpack("V",substr($data,0x164,4));
	
	if ($event1 == 0x40001 && $event2 == 0x40001) {
# Use this area to populate the EPROCESS structure		
		my $name = substr($data,0x1fc,16);
		$name =~ s/\00//g;
		$proc{name} = $name;
#		$proc{exitstatus} = unpack("V", substr($data,0x06c,4));
# Get Active Process Links for EPROCESS block
#		($proc{flink},$proc{blink})  = unpack("VV",substr($data,0x0a0,8));
#		my (@createTime) 	= unpack("VV", substr($data,0x088,8));
#		$proc{createtime} = getTime($createTime[0],$createTime[1]);
#		my (@exitTime) = unpack("VV", substr($data,0x090,8));
#		$proc{exittime} = getTime($exitTime[0],$exitTime[1]);
		
#		$proc{pObjTable} = unpack("V",substr($data,0x128,4));
#		$proc{pSectionHandle} = unpack("V",substr($data,0x1ac,4));
#		$proc{pSecBaseAddr} = unpack("V",substr($data,0x1b4,4));
		
#		$proc{pid} = unpack("V",substr($data,0x09c,4));
#	  $proc{ppid}	= unpack("V",substr($data,0x1c8,4));
#	  ($proc{subsysmin},$proc{subsysmaj}) = unpack("CC",substr($data,0x212,2));
		$proc{directorytablebase} = unpack("V",substr($data,0x018,4));
#	  $proc{peb} = unpack("V",substr($data,0x1b0,4));
#	  $proc{exitprocesscalled} = unpack("C",substr($data,0x1aa,1));
#	  $proc{pimagefilename} = unpack("V",substr($data,0x284,4));
	}
	else {
# Not an EPROCESS block
	}
	return %proc;
}

#---------------------------------------------------------
# getOffset()
# Get physical offset within dump, based on logical addresses
# Translates a logical address to a physical offset w/in the dump
#   file
# Input : two addresses (ex: PEB and DirectoryTableBase)
# Output: offset within file
#---------------------------------------------------------
sub getOffset {
	my $peb = shift;
	my $dtb = shift;
	my $record;
	my $pdi = $peb >> 22 & 0x3ff;
	my $pda = $dtb + ($pdi * 4);
	seek(FH,$pda,0);
	read(FH,$record,4);	
	my $pde = unpack("V",$record);
# Determine page size if needed
# $pde & 0x080; if 1, page is 4Mb; else, 4Kb
# Check to see if page is present
	if ($pde & 0x1) {
		my $pti = $peb >> 12 & 0x3ff;
		my $ptb = $pde >> 12;
		
		seek(FH,($ptb * 0x1000) + ($pti * 4),0);
		read(FH,$record,4);	
		my $pte = unpack("V",$record);
		if ($pte & 0x1) {
			my $pg_ofs = $peb & 0x0fff;
			return ((($pte >> 12) * 0x1000) + $pg_ofs);	
		}
		else {
			$error = "Page Table Entry not present.";
			return 0;
		}
	}
	else {
		$error = "Page Directory Entry not present.";
		return 0;
	}
}

#---------------------------------------------------------
# getMemoryPages()
# 
# Input : Page directory base address
# Output: List of page addresses
#---------------------------------------------------------
sub getMemoryPages {
	my $pdbaddr = shift;
	my @pages = ();
# read page directory
	seek(FH,$pdbaddr,0);
	my $bytes = read(FH,$data,0x1000);
	die "Could not read the page directory.\n" if ($bytes < 0x1000);
	my @pd = unpack("V1024", $data);
# loop over all page directory entries
	foreach my $pde (@pd) {
# skip pages that aren't present
		next unless ($pde & 0x01);
# determine page size
		if ($pde & 0x80) {
# process 4M page
			next if ($pde & 0x100);
# Calculate page base address
			my $pba = ($pde >> 22) * 0x400000;
		} else {
#		printf "0x%08x\n",$pde;
# not a 4M page, but a table of 4k pages
# Page Table Base Address
			my $ptba = ($pde >> 12) * 0x1000;	
# read the Page Table
			seek(FH,$ptba,0);
			my $bytes = read(FH,$data,0x1000);
			die "Could not read the Page Table.\n" if ($bytes < 0x1000);
			my @pt = unpack("V1024",$data);
# Look at each page table entry
			foreach my $pte (@pt) {
# skip non-present (paged/undefined) pages
				next if (($pte & 1) == 0);
# skip pages with global flag set
				next if (($pte & 0x100));
#			printf "\t0x%08x\n",$pte;
# calculate the page base address
				my $pba = ($pte >> 12) * 0x1000;
#			printf "\t\t0x%08x\n",$pba;
				push(@pages,$pba);
			}
		}
	}
	return @pages;
}				