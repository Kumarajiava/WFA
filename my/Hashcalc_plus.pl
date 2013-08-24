#!/usr/bin/perl -w 

use strict;
use Tk;
use Tk::DirTree;
use Tk::PathEntry;
use Cwd;
use File::Spec;
use File::Basename;
use Digest::MD5;
use Digest::SHA;
use IO::File;
use Win32::Clipboard;

my $mlgm = 5;
my @ph;
my $cwd0;
my $FFILE;
my $hashset = 5;
my $ext = "MD5.txt";
my $kingst = "MD5.txt\'s MD5";
my $main = MainWindow->new;
my $filedir ;
$filedir = $main->PathEntry(-width => 103,
					#-initialdir =>'pls input the dir',
					-textvariable =>\$filedir,					
					-autocomplete => 1,
					-pathcompletion => '<F5>',
					-dircolor => 'red',
					-selectcmd => sub {print $filedir;},
        )->pack;

my $butt_frame = $main->Frame()->pack();
$butt_frame->Button(-text => 'HASHCALC_MD5',
	-command => sub{do_fax(5, $filedir)},
)->pack(-side => "left");
$butt_frame->Button(-text => 'HASHCALC_SHA256',
	-command => sub{do_fax(256, $filedir)},
)->pack(-side => "left");
my $fire_frame = 0;
MainLoop;

sub do_fax {
	my ($hashsett, $filedir_val) = @_;
	undef $hashset;
	$hashset = $hashsett;
	if ($fire_frame) {
		$fire_frame->packForget;
	}	
	$fire_frame = $main->Frame()->pack(-side => "bottom");	
	if (-d $filedir_val){
		do_check($filedir_val);
		&hashcalc;
		do_pri(@ph);
		undef @ph;
	}else{
		my $FH=IO::File->new($filedir_val);
        binmode($FH);
		my $hash;
		if ($hashset == 5) {
			$hash=Digest::MD5->new->addfile(*$FH)->hexdigest;
		}else{
			$hash=Digest::SHA->new(256)->addfile(*$FH)->hexdigest;
		}		
        $FH->close;
		$fire_frame->Label(-text => $hash)->pack;
		my $CLIP = Win32::Clipboard();
		$CLIP->Set($hash);
	}
}

sub do_pri{
	my @items = @_;
	my $box = $fire_frame->Scrolled("Listbox",
				  -width => 99,
                  -scrollbars => 'osoe',
				  -relief => 'sunken',
                  )->pack(-side   =>'bottom',
                      -fill   => 'y',
                      -expand => 1,
                      -padx   => 2);
    foreach (@items) {
       $box->insert('end', $_);
    }
}

sub do_check{
	($cwd0)=@_;
	$cwd0=~s#\/#\\#g;
	chomp ($cwd0);
	if (chdir ($cwd0)){
		$mlgm = -1;
	}
}
sub hashcalc{
	my @files = glob q{*};
	$ext ="SHA256.txt" if $hashset == 256;
	$ext ="MD5.txt" if $hashset == 5;
	my $md5=$cwd0."\\".$ext;
	$FFILE = IO::File->new($ext,q{>} );
	select( $FFILE ); 
	$| = 1;
	my $gctime = localtime;
	my $timm;
	if ($hashset == 5) {
		$timm = "# MD5 checksums generated by Hashcalc_Plus \n# Generated $gctime\n\n";
	}else{
		$timm = "# SHA256 checksums generated by Hashcalc_Plus \n# Generated $gctime\n\n";
	}	
	print $FFILE $timm;
	$fire_frame->Label(-text => $timm)->pack;
	foreach my $file(@files)
	{
		my $path = File::Spec->catfile( $cwd0, $file );
		&filelist($path,$hashset);
	}
	$FFILE->close;
	my $cpfile;

	if (-e $md5) {
		my $FHH=IO::File->new($md5);
		binmode($FHH);
		if ($hashset == 5) {
			$cpfile = Digest::MD5->new->addfile(*$FHH)->hexdigest;
		}else{
			$cpfile = Digest::SHA->new(256)->addfile(*$FHH)->hexdigest;			
		}
		$FHH->close;
	}
	$kingst = "SHA256.txt\'s SHA256" if $hashset== 256; 
	$fire_frame->Label(-text => "$kingst:\n$cpfile\n it's Clipboard now\n")->pack;
	my $CLIP = Win32::Clipboard();
	$CLIP->Set($cpfile);
	$fire_frame->Label(-text => "+++++++++++++++end!+++++++++++++++\n")->pack;
}

sub filelist{
	my ($path,$hashset) = shift @_;
	my $file_name = basename $path;
	if(-d $file_name)
	{		
		chdir $path or die "can't chdir $path:$!";
		my $cwd = getcwd;
		my @files = glob q{*};
		my $count = 0;
		foreach my $file(@files)
		{
			$count++;
			my $path = File::Spec->catfile( $cwd, $file );
			&filelist($path,$hashset);
		}
		if ($count eq @files)
		{
			my $dir_name = dirname $path; 
			chdir "$dir_name\..";
		}
	}
	else
	{
		my $FH=IO::File->new($path);
        binmode($FH);
		my $hash;
		if ($hashset == 5) {
			$hash=Digest::MD5->new->addfile(*$FH)->hexdigest;
		}else{
			$hash=Digest::SHA->new(256)->addfile(*$FH)->hexdigest;
		}       
        $FH->close;
        my $cwd1=$cwd0;
        $cwd1=~s/\/|\\/\#/g;
        $path=~s/\\|\//\#/g;
        $path=~s#$cwd1#\.#gi;
        $path=~s/\#/\\/g;        
		print $FFILE "<======$hash======> $path\n";
		push @ph,"<======$hash======> $path\n";
        #print STDOUT "<======$hash======> $path\n";
	}
}
