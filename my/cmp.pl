#!/usr/bin/perl -w
use strict;
use IO::File;

my $source = IO::File->new("source2.txt","r") or die $!;
my @lines=<$source>;
undef $source;

my $opt = IO::File->new("opt.txt","r") or die $!;
my @lineo=<$opt>;
undef $opt;

my $fh = IO::File->new("exp.txt","w") or die $!;
select ($fh);
$|=1;
my $ao = 0;
my $bo = 0;
my $am = $#lines;
my $bm = $#lineo;
while ($ao > $am || $bo > $bm) {
	my $exp = $lineo[$bo] =~ m/(.*):([0-9]{11})/;
	my $liii = $2;
	if ($lines[$ao] lt $liii) {
		$ao++;
	}
	elsif($lines[$ao] eq $liii){
		$bo++;
		print $fh $exp;
	}
	elsif($lines[$ao] gt $liii) {
		$ao++;
	}
}

undef $fh;