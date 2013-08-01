#! c:\perl\bin\perl.exe
#----------------------------------------------------------
# oledmp.pl - OLE dumper, version 1.0
# Dump OLE info and some metadata from Word documents, without using the MS API
#
# Usage: C:\Perl>[perl] oledmp.pl <filename> [> output]
#
# Modules: Requires the use of File::MSWord
#
# Author: H. Carvey, keydet89@yahoo.com
# Copyright 2006, 2007 H. Carvey
#----------------------------------------------------------
use strict;
use File::MSWord;

my $file = shift || die "You must enter a filename.\n";
die "File not found.\n" unless (-e $file);

print "ListStreams\n";
my $doc = File::MSWord::new($file);
my %streams = $doc->listStreams();
map{print "Stream : ".$_."\n";}(keys %streams);
print "\n";

my %trash = $doc->readTrash();
printf "%-15s %-8s\n","Trash Bin","Size";
map{printf "%-15s %-8d\n",$_,$trash{$_}{size}}(keys %trash); 
print "\n";
print "Summary Information\n";
my %sum = $doc->getSummaryInfo();
map{printf "%-15s %-40s\n",$_ ,$sum{$_};}(keys %sum);
#map{print "$_ => $sum{$_}\n"}(keys %sum);
print "\n";

# Read last 10 authors info
my ($ofs,$size) = $doc->getSavedBy();
my $buff = $doc->readStreamTable($ofs,$size);
my %revlog = $doc->parseSTTBF($buff,"author","path");
foreach my $k (sort {$a <=> $b} keys %revlog) {
	printf "%-3s %-15s %-60s\n",$k,$revlog{$k}{author},$revlog{$k}{path};
}