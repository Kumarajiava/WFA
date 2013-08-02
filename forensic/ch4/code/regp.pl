#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------
# regp.pl 
# Parses raw Windows Registry files (ntuser.dat, system32\config\system,
# system32\config\software) from NT/2K/XP/2K3 systems.
#
# Author: H. Carvey keydet89@yahoo.com
#
# Thanks goes to Peter Nordahl for his ntpasswd utility, as the 
# source code for ntreg.h was extremely helpful in deciphering the
# binary structure of the Windows Registry.
# http://home.eunet.no/~pnordahl/ntpasswd/
#
# Copyright 2007 H. Carvey keydet89@yahoo.com
#-----------------------------------------------------------------
use strict;

#-----------------------------------------------------------------
# Usage info
#-----------------------------------------------------------------
print "Offline Registry File Parser, by Harlan Carvey\n";
print "Version 1\.1, 20060523\n";
print "\n";
#-----------------------------------------------------------------
# Global Variables
#-----------------------------------------------------------------
my $VERSION = '1.1';
my $ADJUST  = 0x1004;		# Global adjustment value (4096 + 4 bytes)
my $ERROR;							# Global value to capture application errors
my %regtypes = (0 => "REG_NONE",
	            	1 => "REG_SZ",
	            	2 => "REG_EXPAND_SZ",
	            	3 => "REG_BINARY",
	            	4 => "REG_DWORD",
	            	5 => "REG_DWORD_BIG_ENDIAN",
	            	6 => "REG_LINK",
	            	7 => "REG_MULTI_SZ",
	            	8 => "REG_RESOURCE_LIST",
	            	9 => "REG_FULL_RESOURCE_DESCRIPTOR",
	             10 => "REG_RESOURCE_REQUIREMENTS_LIST");
	             
# Special list for translating the UserAssist (ROT-13) key value names
my @ua = qw/{5E6AB780-7743-11CF-A12B-00AA004AE837}
            {75048700-EF1F-11D0-9888-006097DEACF9}/;
#-----------------------------------------------------------------
# Node IDS											Data Types
# nk = 0x6b6e										0 = REG_NONE
# vk = 0x6b76										1 = REG_SZ
# ri = 0x6972										2 = REG_EXPAND_SZ
# li = 0x696c										3 = REG_BINARY
# lf = 0x666c										4 = REG_DWORD
# lh = 0x686c										5 = REG_DWORD_BIG_ENDIAN
#	sk = 0x6b73 (ignored in 			6 = REG_LINK
#              this script)			7 = REG_MULTI_SZ
# 															8 = REG_RESOURCE_LIST
# 															9 = REG_FULL_RESOURCE_DESCRIPTOR
#															 10 = REG_RESOURCE_REQUIREMENTS_LIST
#-----------------------------------------------------------------

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);
open(REG,$file) || die "Could not open $file: $!\n";
binmode(REG);

my ($node,$offset) = locateRecord($ADJUST);
my $nt = _getNodeType($offset);
if ($nt == 0x6b6e) {
	\parseNkRecords("",$offset);
}
else {
	printf "Node not an nk node: 0x%x\n",$nt;
	die;
}
close(REG);
#-----------------------------------------------------------------
# locateRecord()
# Subroutine to locate the root nk node
#-----------------------------------------------------------------
sub locateRecord {
	my $offset = $_[0];
	my $record;
	seek(REG,$offset,0);
	while(1) {
		read(REG,$record,4);
		my ($tag,$id) = unpack("vv",$record);
		if ($tag == 0x6b6e && $id == 0x2c) {
#			print "nk record located.\n";
			return("nk",$offset);
		}
		$offset = $offset + 2;
		seek(REG,$offset,0);
	}
}

#-----------------------------------------------------------------
# parseNkRecords() 
# Input : Name of the key/subkey, offset to the nk record
# Output: None (prints to STDOUT)
#-----------------------------------------------------------------
sub parseNkRecords {
	my $name = $_[0];
	my $offset = $_[1];
	my %nk = readNkRecord($offset);
	print $name."\\".$nk{keyname}."\n"; 
	print "LastWrite time: ".gmtime(getTime($nk{time1},$nk{time2}))."\n";
	if ($nk{no_values} > 0) { 
		my @ofs_vallist = readValList(($nk{ofs_vallist} + $ADJUST),$nk{no_values});
		foreach my $i (0..(scalar(@ofs_vallist) - 1)) {
			my %vk = readVkRecord($ofs_vallist[$i] + $ADJUST);
			
# **Special section to handle translating the UserAssist value names
			if ($nk{keyname} eq "Count") {
				foreach my $u (@ua) {
					if (grep(/$u/,$name)) {
						$vk{valname} =~ tr/N-ZA-Mn-za-m/A-Za-z/;
					}
				}
			}			
# **End special UserAssist section
			
			print "\t--> ".$vk{valname}.";".$regtypes{$vk{val_type}}.";".$vk{data}."\n";
		}
		print "\n";
	}
	if ($nk{no_subkeys} > 0) {
		my $nt = _getNodeType($nk{ofs_lf} + $ADJUST);
		if ($nt == 0x666c || $nt == 0x686c) {
			my %lf = readLfList($nk{ofs_lf} + $ADJUST);
			foreach my $ofs_lf (keys %lf) {
				\parseNkRecords($name."\\".$nk{keyname},$ofs_lf + $ADJUST);
			}
		}
		elsif ($nt == 0x6972) {
			my @ri = readRiList($nk{ofs_lf} + $ADJUST);
			foreach (@ri) {
				\parseLiRecords($name."\\".$nk{keyname},$_ + $ADJUST);
			}
		}
		elsif ($nt == 0x696c) {
			\parseLiRecords($name."\\".$nk{keyname},$nk{ofs_lf} + $ADJUST);
		}
		else {
			printf "**Unrecognized node type : 0x%x\n",$nt;
		}
	}
}

#-----------------------------------------------------------------
# parseLiRecords()
# Input : Name of key/subkey, offset to li records
# Output: None (prints to STDOUT)
#-----------------------------------------------------------------
sub parseLiRecords {
	my $name   = $_[0];
	my $offset = $_[1];
	my @li_list = readRiList($offset);
	foreach my $ofs_nk (@li_list) {
		my $nt = _getNodeType($ofs_nk + $ADJUST);
		if ($nt == 0x6b6e) {
			\parseNkRecords($name,$ofs_nk + $ADJUST);
		}
		elsif ($nt == 0x696c) {
			\parseLiRecords($name,$ofs_nk + $ADJUST);
		}
		else {
			printf "**Unrecognized node type : 0x%x\n",$nt;
		}
	}
}

#-----------------------------------------------------------------
# readNkRecord()
# Input : Offset to an nk record
# Output: Hash containing the elements of the nk record/structure
# Note  : The basic nk structure is 76 bytes in length
#-----------------------------------------------------------------
sub readNkRecord {
	my $offset = $_[0];
	my $record;
	my %nk = ();
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,76);
	if ($bytes == 76) {
# Dump the items in the structure into a hash; not the 
# prettiest, but it works.
#		my (@recs)         = unpack("vvL3LLLLLLLLLL4Lvv",$record);
    my (@recs)         = unpack("vvV17vv",$record);
		$nk{id}            = $recs[0];
		$nk{type}          = $recs[1];
		$nk{time1}         = $recs[2];
		$nk{time2}         = $recs[3];
 		$nk{time3}         = $recs[4];
		$nk{no_subkeys}    = $recs[6];
		$nk{ofs_lf}        = $recs[8];
		$nk{no_values}     = $recs[10];
		$nk{ofs_vallist}   = $recs[11];
		$nk{ofs_sk}        = $recs[12];
		$nk{ofs_classname} = $recs[13];
		$nk{len_name}      = $recs[19];
		$nk{len_classname} = $recs[20];
# Get the name		
		seek(REG,$offset + 76,0);
		read(REG,$record,$nk{len_name});
		$nk{keyname}       = $record;
# At this point, the total number of bytes read is
# ($num_bytes + $nk_rec{len_name}); can return this and
# the hash for use in the rest of the program
		return %nk;
	}
	else {
		$ERROR = "readNkRecord bytes read error: ".$bytes;
		return;
	}
}

#-----------------------------------------------------------------
# readVkRecord()
# Input : Offset to a vk record
# Output: Hash containing the elements of the vk record/structure
# Note  : The basic vk structure is 20 bytes in length
#-----------------------------------------------------------------
sub readVkRecord {
	my $offset = $_[0];
	my $record;
	my %vk = ();
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,20);
	if ($bytes == 20) {
# Dump the items in the structure into a hash; not the 
# prettiest, but it works.
		my (@recs)    = unpack("vvVVVvv",$record);
		$vk{id}       = $recs[0];
		$vk{len_name} = $recs[1];
		$vk{len_data} = $recs[2];
		$vk{ofs_data} = $recs[3];
		$vk{val_type} = $recs[4];
		$vk{flag}     = $recs[5];
		
		if ($vk{len_name} == 0) {
			$vk{valname} = "Default";
		}
		else {
			seek(REG,$offset + 20,0);
			read(REG,$record,$vk{len_name});
			$vk{valname}  = $record;
		}

		if ($vk{len_data} & 0x80000000 || $vk{val_type} == 4) {
			$vk{data} = $vk{ofs_data};
			$vk{data} = "" if ($vk{val_type} == 7);
			$vk{data} = chr($vk{data}) if ($vk{val_type} == 1);
		}
		else {
			$vk{data} = _getValueData($vk{ofs_data} + $ADJUST,$vk{len_data});
			$vk{data} = _uniToAscii($vk{data}) if ($vk{val_type} == 1 ||
			                                       $vk{val_type} == 2 ||
			                                       $vk{val_type} == 7);
		}
		$vk{data} = _translateBinary($vk{data}) if ($vk{val_type} == 0 || 
																								$vk{val_type} == 3 ||
																 								$vk{val_type} == 8 ||
																 								$vk{val_type} == 10);
		
		return %vk;
	}
	else {
		$ERROR = "readVkRecord bytes read error: ".$bytes;
		return;
	}
}
#-----------------------------------------------------------------
# readValList()
# Input : Offset to the value list, number of values to read
# Output: List of offsets to vk records
#-----------------------------------------------------------------
sub readValList {
	my $offset = $_[0];
	my $num_vals = $_[1];
	my $record;
	my $bytes_to_read = $num_vals * 4;
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,$bytes_to_read);
	if ($bytes == $bytes_to_read) {
		my @ofs_val = unpack("V*",$record);
		if (scalar(@ofs_val) == $num_vals) {
			return @ofs_val;
		}
		else {
			$ERROR = "readValList bytes read error: ".$bytes;
			return;
		}
	}
}

#-----------------------------------------------------------------
# _getValueData()
# Input : Offset to value data, number of bytes to read
# Output: Perl scalar containing value data; needs to be managed/
#         munged in readVkRecord()
#-----------------------------------------------------------------
sub _getValueData {
	my $offset = $_[0];
	my $len    = $_[1];
	my $record;
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,$len);
	if ($bytes == $len) {
		return $record;
	}
	else {
		$ERROR = "_getValData error: $bytes of $len bytes read.";
		return;
	}
}

#-----------------------------------------------------------------
# readRiList()
# Input : Offset to an ri/li list
# Output: List of offsets to either (ri) a list of li nodes, or (li)
#         a list of nk records
#-----------------------------------------------------------------
sub readRiList {
	my $offset = $_[0];
	my $record;
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,4);
	my ($id,$num) = unpack("vv",$record);
	seek(REG,$offset + 4,0);
	$bytes = read(REG,$record,$num * 4);
	return unpack("L*",$record);
}

#-----------------------------------------------------------------
# readLfList()
# Input : Offset to an lf/lh list
# Output: Hash of offsets to nk records
# Reads in a list of offsets from an lf/lh list; returned hash keys
# are the offsets to the nk records, values are (NT/2K) the first 4
# characters of the nk node name, or (XP+) the base 37 "hash" of the
# nk node name
#-----------------------------------------------------------------
sub readLfList {
	my $offset = $_[0];
	my $record;
	my $num_bytes = 4;
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,$num_bytes);
	if ($bytes == $num_bytes) {
		my($id, $no_keys) = unpack("vv",$record);
		seek(REG,$offset + $num_bytes,0);
		$bytes = read(REG,$record,(2 * 4 * $no_keys));
		
		my $iterations = ($bytes/4);
		my $step = 1;
		my $temp;
		my %lf;
		
		foreach my $i (0..($iterations - 1)) {
			my $str = substr($record,$i*4,4);
			if ($step%2) {
				$temp = unpack("L",$str);
			}
			else {				
				$lf{$temp} = $str;
			}
			$step++;
		}
		return %lf;
	}
	else {
		$ERROR = "readLfList bytes read error: ".$bytes;
		return;
	}
}

#-----------------------------------------------------------------
#
#
#-----------------------------------------------------------------

#----------------------------------------------------------------
# _getNodeType()
# Input : Offset 
# Output: unpack()'d WORD (2 bytes) containing the node ID
#----------------------------------------------------------------
sub _getNodeType {
	my $offset = $_[0];
	my $record;
	seek(REG,$offset,0);
	my $bytes = read(REG,$record,2);
	if ($bytes == 2) {
		return unpack("S",$record);
	}
	else {
		$ERROR = "_getNodeType error - only $bytes read.";
		return;
	}
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
# _translateBinary()
# Input : Binary data
# Output: String of hex pairs
#----------------------------------------------------------------
sub _translateBinary {
	my $str = unpack("H*",$_[0]);
	my $len = length($str);
	my @nstr = split(//,$str,$len);
	my @list = ();
	foreach (0..($len/2)) {
		push(@list,$nstr[$_*2].$nstr[($_*2)+1]);
	}
	return join(' ',@list);
}

#---------------------------------------------------------
# getTime()
# Get Unix-style date/time from FILETIME object
# Input : 8 byte FILETIME object
# Output: Unix-style date/time
# Thanks goes to Andreas Schuster for the below code, which he
# included in his ptfinder.pl
#---------------------------------------------------------
sub getTime() {
	my $lo = shift;
	my $hi = shift;
	my $t;

	if ($lo == 0 && $hi == 0) {
		$t = 0;
	} else {
		$lo -= 0xd53e8000;
		$hi -= 0x019db1de;
		$t = int($hi*429.4967296 + $lo/1e7);
	};
	$t = 0 if ($t < 0);
	return $t;
}