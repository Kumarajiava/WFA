#! c:\perl\bin\perl.exe
#------------------------------------------------------
# pdfmeta.pl
# Attempt to extract metadata from PDF files
#
# Usage: pdfmeta.pl <filename>
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------
use strict;
use PDF::API2;

my $file = shift || die "You must enter a filename.\n";
if (-e $file) {
  my $pdf = PDF::API2->open($file);
  if ($pdf) {
  	my %info = $pdf->info();
  	foreach (sort keys %info) {
    	printf "%-15s %-20s\n", $_ ,$info{$_};
  	}
  }
}
else {
  die "$file not found.\n";
}
