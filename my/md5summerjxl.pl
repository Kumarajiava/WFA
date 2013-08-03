#!perl


use strict;
use Cwd;
use File::Spec;
use File::Basename;
use Digest::MD5;
use File::Copy qw(cp);
use File::Remove;
use IO::File;
use Win32::Clipboard;


select( STDOUT ); 
$| = 1;
my $cwd0;
print "请输入要计算MD5的目录:\n";
my $mlgm=5;
while ($mlgm != -1) {
$cwd0=<STDIN>;
while ($cwd0=~m/\\\\|\/\/|\#|\!|\=|\,|\@|\$|\%|\&|\*|\。|\`/g){
	print "请输入正确的目录\n" ;
	$cwd0=<STDIN>;
	$mlgm--;
	if ($mlgm == 0){
		print "喵了个咪！能不能输入正确的目录\n";
		exit 0;
	}
	next;
}
$cwd0=~s#\/#\\#g;
chomp ($cwd0);
if (chdir ($cwd0)){
	$mlgm = -1;
	}
else{	
	$mlgm--;
	if ($mlgm == 0){
		print "咪了个喵！都说了";
		exit 0;
	}
	print "输入的目录不存在\n";
	} 
next;
}

my @files = glob q{*};
my $ext = "MD5";
my $myself ="md5summerjxl\.exe";
my $md5=$cwd0."\\".$ext;
my $FFILE = IO::File->new($ext,q{>} ) or die "Couldn't open $ext:$!";
select( $FFILE ); 
$| = 1; 
foreach my $file(@files)
{
	my $path = File::Spec->catfile( $cwd0, $file );
	&filelist($path);
}
$FFILE->close;
my $cpfile;
if (-e $md5) {
	my $FHH=IO::File->new($md5) or die "Couldn't open '$md5': $!";
    binmode($FHH);
    $cpfile = Digest::MD5->new->addfile(*$FHH)->hexdigest;        
	$FHH->close;
	cp($ext,$cpfile."\.txt");	
}
File::Remove::remove $ext;
print STDOUT "生成的MD5文件的MD5值为:\n\t$cpfile\n该值已copy到剪贴板\n";
my $CLIP = Win32::Clipboard();
$CLIP->Set($cpfile);
print STDOUT "end!\n";
<>;
# if (my $pid = fork()) {
	# system(del $0) or die $!;
	# exit;
# }else{
	# unlink $0;
	# exit;
# }


sub filelist
{
	my $path = shift @_;
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
			&filelist($path);
		}
		if ($count eq @files)
		{
			my $dir_name = dirname $path; 
			chdir "$dir_name\.." or die "can't chdir $dir_name\..:$!";
		}
	}
	else
	{
		my $FH=IO::File->new($path) or die "Couldn't open '$path': $!";
        binmode($FH);
        my $hash=Digest::MD5->new->addfile(*$FH)->hexdigest;        
        $FH->close;
        my $cwd1=$cwd0;
        $cwd1=~s/\/|\\/\#/g;
        $path=~s/\\|\//\#/g;
        $path=~s#$cwd1#\.#gi;
        $path=~s/\#/\\/g;        
        next if $path eq "\.\\$myself";
		print $FFILE "<======$hash======> $path\n";
        print STDOUT "<======$hash======> $path\n";
	}
}