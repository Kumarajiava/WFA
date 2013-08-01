#! d:\perl\bin\perl.exe
#------------------------------------------------------
# pdfdmp.pl
# Attempt to extract metadata from PDF files
#
# Usage: pdfdmp.pl <filename>
#
# copyright 2006-2007 H. Carvey keydet89@yahoo.com
#------------------------------------------------------

use strict;
use PDF;

my $file = shift || die "You must enter a filename\n";
if (-e $file) {
	my $pdf = PDF->new;
	$pdf = PDF->new($file);
	if ($pdf->IsaPDF()) {
		print "PDF Version    : ".$pdf->Version."\n";
		print "Title          : ".$pdf->GetInfo("Title")."\n";
		print "Subject        : ".$pdf->GetInfo("Subject")."\n";
		print "Author         : ".$pdf->GetInfo("Author")."\n";
		print "Creation Date  : ".$pdf->GetInfo("CreationDate")."\n";
		print "Creator        : ".$pdf->GetInfo("Creator")."\n";
		print "Converted With : ".$pdf->GetInfo("Producer")."\n";
		print "Last Mod       : ".$pdf->GetInfo("ModDate")."\n";
		print "Keywords       : ".$pdf->GetInfo("Keywords")."\n";
	}
	else {
		print $file." is not a PDF file.\n";
	}
}
else {
	print $file." not found.\n";
}

