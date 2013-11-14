#!perl
use warnings;
use strict;
use Cwd;
#设置要读取的目录
my $doc=getcwd;
my @filelist;#存储读取到的所有文件列表
#执行递归读取的函数
sub getfilelist {
        my $dir = $_[0];
        my @tmplist = ();
        $dir =~ s|/$|| if $dir =~ m|/$|;

        opendir DIR,"$dir" or die "$dir:$!";
        my @files = readdir DIR;
        foreach my $filename ( @files ){
                chomp $filename;

                if( $filename eq "." or $filename eq ".." or $filename =~ /^\./){
                        next; #对以点"."开头的文件跳过
                }

                my $path = "$dir/$filename";

                if(-f $path) {
                        push(@tmplist,$path);
                }elsif(-l $path){
                        next; #对于目录的软连接跳过
                }elsif(-d $path){
                        push(@tmplist, getfilelist($path) );
                }else{
                        print "Fuck! what's this?: $path\n";
                }
        }
        closedir DIR;
        return @tmplist;
}
push(@filelist,getfilelist($doc));

foreach my $filepath (@filelist) {
        print "$filepath\n";
}