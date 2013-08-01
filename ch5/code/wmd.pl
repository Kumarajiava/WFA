#! c:\perl\bin\perl.exe
#----------------------------------------------------------
# WMD - Word Metadata Dumper version 1.0
# Dump metadata from Word documents, without using the MS API
#
# Usage: C:\Perl>[perl] wmd.pl <filename> [> output]
#
# Modules: Requires the use of OLE::Storage, Startup, and 
#          Unicode::Map; for Activestate Perl, these modules
#          can be easily installed using PPM
#
# Author: H. Carvey, keydet89@yahoo.com
# Copyright 2006, 2007 H. Carvey
#----------------------------------------------------------
use strict;
use OLE::Storage;
use OLE::PropertySet;
use Startup;

my $file = shift || die "You must enter a filename.\n";
die "$file not found.\n" unless (-e $file);

my %ids = (0x6a62 => "MS Word 97",
           0x626a => "Word 98 Mac",
           0xa5dc => "Word 6\.0/7\.0",
           0xa5ec => "Word 8\.0");
           
my %doc_bin = getBinaryData($file); 
print "-" x 20,"\n";
print "Statistics\n";
print "-" x 20,"\n";
print  "File    = $file\n";
print  "Size    = ".(stat($file))[7]." bytes\n";
printf "Magic   = 0x%x (".$ids{$doc_bin{wIdent}}.")\n",$doc_bin{wIdent};
print  "Version = $doc_bin{nFib}\n";
printf "LangID  = ".getLangID($doc_bin{langid})."\n";;
printf "LKey    = 0x%x\n",$doc_bin{lKey} if ($doc_bin{lKey});
print "\n";
print "Document is a template.\n" if ($doc_bin{fDot} & 0x0001);
print "Document is a glossary.\n" if ($doc_bin{fDot} & 0x0002);
print "Document is complex.\n"    if ($doc_bin{fDot} & 0x0004);
print "Document has picture(s).\n" if ($doc_bin{fDot} & 0x0008);
print "Document is encrypted.\n"  if ($doc_bin{fDot} & 0x0100);
print "Document is Far East encoded.\n" if ($doc_bin{fDot} & 0x8000);
print "\n";
($doc_bin{envr}) ? (print "Document was created on a Mac.\n") 
	: (print "Document was created on Windows.\n");
print "File was last saved on a Mac.\n" if ($doc_bin{fMac} & 0x01);  
print "\n";
printf "Magic Created : ".$ids{$doc_bin{wMagicCreat}}."\n";;
printf "Magic Revised : ".$ids{$doc_bin{wMagicRev}}."\n";;        	
print "\n";
my $var = OLE::Storage->NewVar();
my $startup = new Startup;
my $doc = OLE::Storage->open($startup,$var,$file);

my %names;
my @pps;
if ($doc->directory(0,\%names,"string")) {
	@pps = keys %names;
}
my @pps = $doc->dirhandles(0);
foreach my $pps (sort {$a <=> $b} @pps) {
	my $name = $doc->name($pps)->string();
	
	if ($doc->is_file($pps)) {
		if ($name eq "\05SummaryInformation") {
			if (my $prop = OLE::PropertySet->load($startup,$var,$pps,$doc)) {
				my ($title,$subject,$authress,$lastauth,$revnum,$appname,
				 $created,$lastsaved,$lastprinted) =
				 string {$prop->property(2,3,4,8,9,18,12,13,11)};
				 print "-" x 20,"\n";
				 print "Summary Information\n";
				 print "-" x 20,"\n";
				 print "Title        : $title\n";
				 print "Subject      : $subject\n";
				 print "Authress     : $authress\n";
				 print "LastAuth     : $lastauth\n";
				 print "RevNum       : $revnum\n";
				 print "AppName      : $appname\n";
				 print "Created      : $created\n";
				 print "Last Saved   : $lastsaved\n";
				 print "Last Printed : $lastprinted\n";
				 print "\n";
			}
		}
		elsif ($name eq "\05DocumentSummaryInformation") {
				if (my $prop = OLE::PropertySet->load($startup,$var,$pps,$doc)) {
					my $org = string {$prop->property(15)};
					print "-" x 20,"\n";
					print "Document Summary Information\n";
					print "-" x 20,"\n";
					print "Organization : $org\n";
					print "\n";
				}
		}
		elsif ($name eq "1Table") {
			if ($doc_bin{szRevLog} > 0) {
				my $buff;
				$doc->read($pps,\$buff,$doc_bin{ofsRevLog},$doc_bin{szRevLog});
				if (length($buff) == $doc_bin{szRevLog}) {
					my %revLog = getRevLogTable($buff);
					print "-" x 20,"\n";
					print "Last Author(s) Info\n";
					print "-" x 20,"\n";
					foreach my $i (sort {$a <=> $b} keys %revLog) {
						print "$i : ".$revLog{$i}{author}." : ".$revLog{$i}{path}."\n";
					}
					print "\n";
				}
			}
		}
	}
	elsif ($doc->is_directory($pps)) {

	}
	else {
				
	}		
}
     
#----------------------------------------------------
# getBinaryData()
# parse binary data from the file
# Input  : File name
# Output : Hash
#----------------------------------------------------
sub getBinaryData {
	my $file = $_[0];
	my $record;
	my %doc =();
	open(FH,"<",$file) || die "Could not open $file: $!\n";
	binmode(FH);
	seek(FH,0,0);
	read(FH,$record,4);
# should be 0xe011cfd0, beginning of GUID
	$doc{sig} = unpack("V",$record);

# Go to beginning of FIB
	seek(FH,512,0);
	read(FH,$record,18);
	($doc{wIdent},$doc{nFib},$doc{nProduct},$doc{langid},$doc{pnNext},
		$doc{fDot},$doc{nFibBack},$doc{lKey}) = unpack("v5V",$record);

	($doc{fDot} & 0x0200) ? ($doc{table} = "1Table") : ($doc{table} = "0Table");

	seek(FH,512 + 18,0);
	read(FH,$record,2);
	($doc{envr},$doc{fMac}) = unpack("C2",$record);

# get creator and revisor ID
#  0x6a62 is ID for Word
	seek(FH,512 + 34,0);
	read(FH,$record,4);
	($doc{wMagicCreat},$doc{wMagicRev}) = unpack("vv",$record);

	seek(FH,512 + 68,0);
	read(FH,$record,8);
	($doc{lProdCreat},$doc{lProdRev}) = unpack("VV",$record);

	seek(FH,512 + 722,0);
	read(FH,$record,8);
	($doc{ofsRevLog},$doc{szRevLog}) = unpack("VV",$record);

	close(FH);
  return %doc;
}

#----------------------------------------------------
# getRevLogTable()
# parse the STTBF containing the last (10) authors
# Input : Buffer containing STTBF
# Output: Hash of hashes
#----------------------------------------------------
sub getRevLogTable {
	my $buff = $_[0];
	my %revLog;
	my $num_str = unpack("v",substr($buff,2,2));
	my $cursor = 6;
	my ($size,$str);
	foreach my $i (1..($num_str/2)) {
		$size = unpack("v",substr($buff,$cursor,2));
		$cursor += 2;
		$str  = substr($buff,$cursor,$size*2);
		$str =~ s/\00//g;
		$revLog{$i}{author} = $str;
		$cursor += $size*2;
		
		$size = unpack("v",substr($buff,$cursor,2));
		$cursor += 2;
		$str  = substr($buff,$cursor,$size*2);
		$str =~ s/\00//g;
		$revLog{$i}{path} = $str;
		$cursor += $size*2;
	}
	return %revLog;
}

#----------------------------------------------------------
# getLangID()
# Input : Language ID (hex)
# Output: Language ID (readable)
#----------------------------------------------------------
sub getLangID {
	my $id = $_[0];	
	my %langID = (0x0400 => "None",
		 0x0401 => "Arabic",
		 0x0402 => "Bulgarian",
		 0x0403 => "Catalan",
		 0x0404 => "Traditional Chinese",
		 0x0804 => "Simplified Chinese",
		 0x0405 => "Czech",
		 0x0406 => "Danish",
		 0x0407 => "German",
		 0x0807 => "Swiss German",
		 0x0408 => "Greek",
		 0x0409 => "English (US)",
		 0x0809 => "British English",		
		 0x0c09 => "Australian English",
		 0x040a => "Castilian Spanish",
		 0x080a => "Mexican Spanish",
		 0x040b => "Finnish",
		 0x040c => "French",
		 0x080c => "Belgian French",
		 0x0c0c => "Canadian French",
		 0x100c => "Swiss French",
		 0x040d => "Hebrew",
		 0x040e => "Hungarian",
		 0x040f => "Icelandic",
		 0x0410 => "Italian",
		 0x0810 => "Swiss Italian",
		 0x0411 => "Japanese",
		 0x0412 => "Korean",
		 0x0413 => "Dutch",
		 0x0813 => "Belgian Dutch",
		 0x0414 => "Norwegian (Bokmal)",
		 0x0814 => "Norwegian (Nynorsk)",
		 0x0415 => "Polish",
		 0x0416 => "Brazilian Portuguese",
		 0x0816 => "Portuguese",
		 0x0417 => "Rhaeto-Romanic",	
		 0x0418 => "Romanian",
		 0x0419 => "Russian",
		 0x041a => "Croato-Serbian (Latin)",
		 0x081a => "Serbo-Croatian (Cyrillic)",
		 0x041b => "Slovak",
		 0x041c => "Albanian",
		 0x041d => "Swedish",
		 0x041e => "Thai",
		 0x041f => "Turkish",
		 0x0420 => "Urdu",
		 0x0421 => "Bahasa",
		 0x0422 => "Ukrainian",
		 0x0423 => "Byelorussian",
		 0x0424 => "Slovenian",
		 0x0425 => "Estonian",
		 0x0426 => "Latvian",
		 0x0427 => "Lithuanian",
		 0x0429 => "Farsi",
		 0x042D => "Basque",
		 0x042F => "Macedonian",
		 0x0436 => "Afrikaans",
		 0x043E => "Malaysian ");
	
	if (exists $langID{$id}) {
		return $langID{$id};
	}
	else {
		return "Unknown";
	}
}