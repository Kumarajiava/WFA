#! c:\perl\bin\perl.exe
#-----------------------------------------------------------------
# lspd.pl - parse process details from a Windows 2000 phys. memory/RAM dump,
#             
# Version 0.8b
#
# Usage: lspd.pl <filename> <offset>
#        Determine the offset of the the process you're interested in by 
#        running lsproc.pl first
#
# Changelog:
# 20060416 - updated getOffset() subroutine; added three bytes to be
#            retrieved from PEB (ie, InheritedAddressSpace, ReadImageFile-
#            ExecutionOptions, BeingDebugged); modified comparison for EPROCESS
#            block header (went from header to examining size and type values)
#
# copyright 2007 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------------
use strict;
print "lspd - list Windows 2000 process details (v.0.8b - 20060524)\n";
print "Ex: lspd <path_to_dump_file> <offset_from_lsproc>\n";
print "\n";
my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);
my $offset = hex(shift) || die "You must enter a process offset.\n";
my $data;
my $error;
my ($size,$type);

open(FH,"<",$file) || die "Could not open $file : $!\n";
binmode(FH);
seek(FH,$offset,0);
read(FH,$data,4);
#my $hdr = unpack("V",$data);
#if ($hdr == 0x001b0003) {
my ($type,$size) = unpack("CxCx",$data);
if ($size == 0x1b && $type == 0x03) {	
	seek(FH,$offset,0);
	my $bytes = read(FH,$data,0x290);
	if (0x290 == $bytes) {
		if (my %proc = isProcess($data)) {
			print "Process Name : ".$proc{name}."\n";
			print "PID          : ".$proc{pid}."\n";
			print "Parent PID   : ".$proc{ppid}."\n";
			printf "TFLINK       : 0x%08x\n",$proc{tflink};
			printf "TBLINK       : 0x%08x\n",$proc{tblink};
			printf "FLINK        : 0x%x\n",$proc{flink};
			printf "BLINK        : 0x%x\n",$proc{blink};
			print "SubSystem    : $proc{subsysmaj}\.$proc{subsysmin}\n";
			print "Exit Status  : ".$proc{exitstatus}."\n";
			print "Create Time  : ".gmtime($proc{createtime})."\n" unless ($proc{createtime} == 0);
			print "Exit Time    : ".gmtime($proc{exittime})."\n" unless ($proc{exittime} == 0);
			print "Exit Called  : ".$proc{exitprocesscalled}."\n";
			printf "DTB          : 0x%08x\n",$proc{directorytablebase};
			my $objtableofs = getOffset($proc{pObjTable},$proc{directorytablebase});
			printf "ObjTable     : 0x%08x (0x%08x)\n",$proc{pObjTable},$objtableofs;
			my $peb_ofs = getOffset($proc{peb},$proc{directorytablebase});
			printf "PEB          : 0x%08x (0x%08x)\n",$proc{peb},$peb_ofs;
			
# Get specific info from the PEB				
			if ($peb_ofs != 0x0) {
				my %peb_data = getPEBData($peb_ofs,$proc{directorytablebase});
				
				print "\n";
				print "\tInheritedAddressSpace         : ".$peb_data{inheritedaddrspace}."\n";
				print "\tReadImageFileExecutionOptions : ".$peb_data{readimgfileexecopts}."\n";
				print "\tBeingDebugged                 : ".$peb_data{beingdebugged}."\n";
				print "\n";
				
				print "\tCSDVersion                    : ".$peb_data{csdversion}."\n";
				print "\n";
				
				printf "\tMutant        = 0x%08x\n",$peb_data{mutant};
				my $imgbaseofs = getOffset($peb_data{img_base_addr},$proc{directorytablebase});
				printf "\tImg Base Addr = 0x%08x (0x%08x)\n",$peb_data{img_base_addr},$imgbaseofs;
				my $peb_ldr_ofs = getOffset($peb_data{peb_ldr},$proc{directorytablebase});
				printf "\tPEB_LDR_DATA  = 0x%08x (0x%08x)\n",$peb_data{peb_ldr},$peb_ldr_ofs;
				my $params_ofs = getOffset($peb_data{params},$proc{directorytablebase});
				printf "\tParams        = 0x%08x (0x%08x)\n",$peb_data{params},$params_ofs;
				print "\n";
				my $env_ofs;	
				if ($params_ofs != 0x0) {
					my %params = getParams($params_ofs,$proc{directorytablebase});
					if (%params) {
						print  "Current Directory Path = $params{currdirpath}\n";
						print  "DllPath                = $params{dllpath}\n";
						print  "ImagePathName          = $params{imagepath}\n";
						print  "Command Line           = $params{cmdline}\n";
						$env_ofs = getOffset($params{env},$proc{directorytablebase});
						printf "Environment Offset     = 0x%08x (0x%08x)\n",$params{env},$env_ofs;        
						print  "Window Title           = $params{windowtitle}\n";
						print  "Desktop Name           = $params{desktopname}\n";
					}
				}
# if the physical offset of the PEB_LDR_DATA is present, we'll see if we
# can't get the modules				
				if ($peb_ldr_ofs != 0x00) {
					print "\n";
					print "Modules:\n";
				
					my %mods = getModuleList($peb_data{peb_ldr},$proc{directorytablebase});
					foreach (sort {$a <=> $b} keys %mods) {
						print "\t".$mods{$_}{fulldllname}."\n";
					}
				}
				
				if ($imgbaseofs != 0x00) {
					\getImgBase($imgbaseofs);
				}
				
				if ($env_ofs != 0x00) {
					print "\n";	
					print "Environment:\n";
					\getProcEnv($env_ofs);
				}
				
				if ($objtableofs != 0x00) {	
					print "\n";	
					print "Object Table:\n";
					\getObjTable($objtableofs,$proc{directorytablebase});
				}
			}				
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
		$proc{exitstatus} = unpack("V", substr($data,0x06c,4));
# Get the thread links for the EPROCESS block
		($proc{tflink},$proc{tblink}) = unpack("VV",substr($data,0x050,8));		
		
# Get Active Process Links for EPROCESS block
		($proc{flink},$proc{blink})  = unpack("VV",substr($data,0x0a0,8));
		my (@createTime) 	= unpack("VV", substr($data,0x088,8));
		$proc{createtime} = getTime($createTime[0],$createTime[1]);
		my (@exitTime) = unpack("VV", substr($data,0x090,8));
		$proc{exittime} = getTime($exitTime[0],$exitTime[1]);
		
		$proc{pObjTable} = unpack("V",substr($data,0x128,4));
		$proc{pSectionHandle} = unpack("V",substr($data,0x1ac,4));
		$proc{pSecBaseAddr} = unpack("V",substr($data,0x1b4,4));
		
		$proc{pid} = unpack("V",substr($data,0x09c,4));
	  $proc{ppid}	= unpack("V",substr($data,0x1c8,4));
	  ($proc{subsysmin},$proc{subsysmaj}) = unpack("CC",substr($data,0x212,2));
		$proc{directorytablebase} = unpack("V",substr($data,0x018,4));
	  $proc{peb} = unpack("V",substr($data,0x1b0,4));
	  $proc{exitprocesscalled} = unpack("C",substr($data,0x1aa,1));
	  $proc{pimagefilename} = unpack("V",substr($data,0x284,4));
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
			return 0;
		}
	}
	else {
		return 0;
	}
}

#---------------------------------------------------------
# getPEBData()
# Input : physical offset to PEB
# Output: data from PEB (Note: Virtual addresses are not 
#         translated to physical offsets in this subroutine)
#---------------------------------------------------------
sub getPEBData() {
	my $ofs = shift;
	my $dtb = shift;
	my %peb = ();
	seek(FH,$ofs,0);
	my $record;
	read(FH,$record,20);
	($peb{inheritedaddrspace},$peb{readimgfileexecopts},$peb{beingdebugged},$peb{mutant},
		$peb{img_base_addr},$peb{peb_ldr},$peb{params}) = unpack("C3xV4",$record);
		
	seek(FH,$ofs + 0x1dc,0);
	read(FH,$record,8);
	$peb{csdversion} = getUnicodeString($record,$dtb);	
		
	return %peb;
}

#---------------------------------------------------------
# getprocParams()
# Read RTL_USER_PROCESS_PARAMETERS structure
# Input : Physical offset to the RTL_USER_PROCESS_PARAMETERS structure
# Output: hash populated by structure elements
#---------------------------------------------------------
sub getParams() {
	my $ofs = shift;
	my $dtb = shift;
	my %params = ();
	seek(FH,$ofs,0);
	my $data;
	read(FH,$data,8);
	my($maxlen,$len) = unpack("VV",$data);
#	printf "\t -> Offset = 0x%08x\n",$ofs;
#	print  "\t -> Length = $len\n";
# Now that we have the length of the structure, read the entire thing
	seek(FH,$ofs,0);
	my $bytes = read(FH,$data,$len);
	if ($bytes == $len) {
		$params{currdirpath} = getUnicodeString(substr($data,36,8),$dtb);
		$params{dllpath}     = getUnicodeString(substr($data,48,8),$dtb);
		$params{imagepath}   = getUnicodeString(substr($data,56,8),$dtb);
		$params{cmdline}     = getUnicodeString(substr($data,64,8),$dtb);
		$params{windowtitle} = getUnicodeString(substr($data,112,8),$dtb);
		$params{desktopname} = getUnicodeString(substr($data,120,8),$dtb);
	}
	else {
		
	}
	return %params;
}

#---------------------------------------------------------
# getUnicodeString()
# Input : 
# Output: 
#---------------------------------------------------------
sub getUnicodeString {
	my $uStr = shift;
	my $dtb = shift;
	my $record;
	my ($len,$maxlen,$ptr) = unpack("vvV",$uStr);
	my $ofs = getOffset($ptr,$dtb);
	return "" if ($ofs == 0x00);
	seek(FH,$ofs,0);
	my $bytes = read(FH,$record,$len);
	return _uniToAscii($record);
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

#---------------------------------------------------------
# getImgBase()
# Read 4K at image base offset (from PEB)
# Input : Physical offset to the image base addr
# Output: dump of memory
#---------------------------------------------------------
sub getImgBase {
	my $ofs = shift;
	my $data;
	seek(FH,$ofs,0);
	read(FH,$data,2);
	my $mz = unpack("v",$data);
	if ($mz == 0x00005a4d) {
		print "PE Header found at the image base addr.\n";
	}
}

#---------------------------------------------------------
# getProcEnv()
# Read 4K at Environment offset (ptr found in RTL_USER_PROCESS_PARAMETERS
#   structure)
# Input : Physical offset to the Environment
# Output: dump of memory
#---------------------------------------------------------
sub getProcEnv {
	my $ofs = shift;
	my $data;
	my $env;
	seek(FH,$ofs,0);
	my $bytes = read(FH,$data,4096);
	if (4096 == $bytes) {
		$env = _uniToAscii($data);
		$env =~ s/\00+$//;
		print $env."\n";
	}
}

#---------------------------------------------------------
# getModuleList()
# Get the module list from the PEB_LDR_DATA structure
# Input : Pointer to PEB_LDR_DATA structure 
# Output: Module list
# Note  : Read the modules from the InLoadOrderModuleList, which
#         is a doubly-linked list
#---------------------------------------------------------
sub getModuleList {
	my $ofs = shift;
	my $dtb = shift;
	my $data;
	my %modules = ();
	
	my $pld = getOffset($ofs,$dtb);
	seek(FH,$pld + 12,0);
	read(FH,$data,4);
	my $modlist = unpack("V",$data);
	my $modlistofs = getOffset($modlist,$dtb);
#	printf "Module List located at 0x%08x (0x%08x)\n",$modlist,$modlistofs;
	my $tag = 1;
	my $count = 1;
	my $next = $modlistofs;
	while ($tag) {
		seek(FH,$next,0);
		read(FH,$data,44);
		my $nextptr = unpack("V",substr($data,0,4));
		if ($nextptr == $modlist) {
			$tag = 0;
			next;
		}
		my $nextptrofs = getOffset($nextptr,$dtb);
		next if ($nextptrofs == 0x00);
		$next = $nextptrofs;
#		printf "Pointer to next module -> 0x%08x (0x%08x)\n",$nextptr,$nextptrofs;
		my ($baseaddr,$entrypt,$imgsz) = unpack("V3",substr($data,24,12));
		$modules{$count}{baseaddr}       = $baseaddr;
		$modules{$count}{entrypt}     = $entrypt;
		$modules{$count}{imagesz}     = $imgsz;
		$modules{$count}{fulldllname} = getUnicodeString(substr($data,36,8),$dtb);
		$count++;
	}
	return %modules;
}

#---------------------------------------------------------
# getObjTable()
# Input : physical offset to Object Table (from EPROCESS block)
# Output: Object table
#---------------------------------------------------------
sub getObjTable {
	my $ofs = shift;
	my $dtb = shift;
	my $data;
	seek(FH,$ofs + 4,0);
	read(FH,$data,4);
	my $handle_count = unpack("V",$data);
#	print "\tHandle Count = ".$handle_count."\n";
	seek(FH,$ofs + 0x10,0);
	read(FH,$data,4);
#	print "\tUnique PID   = ".unpack("V",$data)."\n";
	
	seek(FH,$ofs + 0x08,0);
	read(FH,$data,4);
	my $tbl = unpack("V",$data);
	my $tbl_ofs = getOffset($tbl,$dtb);
#	printf "\tHandle Tbl   = 0x%08x (0x%08x)\n",$tbl,$tbl_ofs;
	
	seek(FH,$tbl_ofs,0);
	read(FH,$data,4);
	my $tbl = unpack("V",$data);
	my $tbl_ofs = getOffset($tbl,$dtb);
#	printf "\t\t     => 0x%08x (0x%08x)\n",$tbl,$tbl_ofs;
	
	seek(FH,$tbl_ofs,0);
	read(FH,$data,4);
	my $tbl = unpack("V",$data);
	my $tbl_ofs = getOffset($tbl,$dtb);
#	printf "\t\t\t=> 0x%08x (0x%08x)\n",$tbl,$tbl_ofs;
#	print "\n";
# Get the 16th handle (be sure that the process has at least 16 handles)
	foreach my $o (0..($handle_count - 1)) {
#		print "Object ".($o + 1)."\n";
		my $new_addr = $tbl_ofs + (($o * 4)/4 * 8);
#		printf "New Address = 0x%08x\n",$new_addr;
		seek(FH,$new_addr,0);
		read(FH,$data,8);
		my ($a,$b) = unpack("VV",$data);
#		printf "\t0x%08x 0x%08x\n",$a,$b;
	
#		print "\n";
		$a = ($a + 0x80000000) & 0xfffffff4;
		my $obj_ofs = getOffset($a,$dtb);
#		printf "Object Header located at: 0x%08x (0x%08x)\n",$a,$obj_ofs;
	
		seek(FH,$obj_ofs,0);
		read(FH,$data,12);
		my ($ptrct,$handlect,$type) = unpack("V3",$data);
		my $type_ofs = getOffset($type,$dtb);
#		print  "Pointer Count  : ".$ptrct."\n";
#		print  "Handle Count   : ".$handlect."\n";
#		printf "Type           : 0x%08x (0x%08x)\n",$type,$type_ofs;
#		print "\n";
		if ($type_ofs == 0x00) {
			next;
		}
		else {
#			printf "Object Header at 0x%08x (0x%08x)\n",$a,$obj_ofs;		
			seek(FH,$type_ofs + 0x40,0);
			read(FH,$data,8);
			my $str = getUnicodeString($data,$dtb);
			print "Type : ".$str."\n";
# More information is necessary for other handle types		
			if ($str eq "File") {
				seek(FH,$obj_ofs + 0x18,0);
				read(FH,$data,4);
				my ($type,$size) = unpack("vv",$data);
#				print "\tType = $type\n";
#				print "\tSize = $size\n";
				seek(FH,$obj_ofs + 0x18 + 0x30,0);
				read(FH,$data,8);
				my $name = getUnicodeString($data,$dtb);
				print "\tName = $name\n";
				
			}
		}
	}
}