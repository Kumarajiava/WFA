#! c:\Perl\bin\perl.exe
#-------------------------------------------------------------
# UserDump.pl, version 0.31 
# ProScript to parse through the SAM portion of the Registry, and 
# retrieve user info and group membership by parsing F and V values 
# for users, and C values for groups.                          
#
# Copyright 2007 H. Carvey, keydet89@yahoo.com
#-------------------------------------------------------------
use ProScript;

PSDisplayText("UserDump v.0.31, 20060522");
PSDisplayText("ProScript to parse through the SAM and pull out user information");
PSDisplayText("as well as group membership information.");
PSDisplayText("\n");
# Open Registry
$numRegs = PSGetNumRegistries();
if ($numRegs == 0) {
    PSDisplayText("No registries to process");
    return;
}

my %users = getUsers();
# %users2 is a secondary hash used to translate RIDs in the groups
# to usernames
my %users2 = ();

# ACB flags
my %acb_flags = (0x0001 => "Account Disabled",
                 0x0002 => "Home Dir Required",
                 0x0004 => "Password not required",
                 0x0008 => "Temp Dupl. account",
                 0x0010 => "Normal user account",
                 0x0020 => "MNS user account",
                 0x0040 => "Interdomain trust account",
                 0x0080 => "Wks trust account",
                 0x0100 => "Server trust account",
                 0x0200 => "Password does not expire",
                 0x0400 => "Account autolocked");

foreach (keys %users) {
	my ($name,$full,$comment) = parseV($users{$_}{V}); 
  PSDisplayText("Username : $name");
  PSDisplayText("Fullname : $full") if ($full);
  PSDisplayText("Comment  : $comment") if ($comment);
  my (@vals) = parseF($users{$_}{F});
  my ($rid,$logins,$acb) = parseF($users{$_}{F});
  $users2{$vals[6]} = $name;
  PSDisplayText("Acct Creation Date : "._getTimeDate($vals[3],$vals[2]))
  	unless ($vals[3] == 0 || $vals[2] == 0);
  PSDisplayText("Last Login Date    : "._getTimeDate($vals[5],$vals[4]))
  	unless ($vals[5] == 0 || $vals[4] == 0);
  PSDisplayText("RID                : ".$vals[6]);
  PSDisplayText("Logins             : ".$vals[9]);
  PSDisplayText("Flags              : ");
  foreach my $flag (keys %acb_flags) {
  	if ($vals[7] & $flag) {
  		PSDisplayText("                  ".$acb_flags{$flag});
  	}
  }
  PSDisplayText("");
}

my %groups = getGroups();
PSDisplayText("");

foreach (keys %groups) {
	PSDisplayText("Group    : $_");
	PSDisplayText("Comment  : ".$groups{$_}{comment});
	if ($groups{$_}{users} eq "None") {
		PSDisplayText("Users    : None");
	}
	else {
		my @u = split(/,/,$groups{$_}{users});
		foreach my $x (@u) {
			
			if ($users2{$x} eq "") {
				PSDisplayText("--> ".$x);
			}
			else {
				PSDisplayText("--> ".$x." (".$users2{$x}.")");
			}
		}
	}
	PSDisplayText("");
}
return;

#-------------------------------------------------------------
# parseV()
# Input : binary V structure from a user's entry
# Output: Name, fullname, and comment for the user
#-------------------------------------------------------------
sub parseV {
	my $v = shift;
	my $header = substr($v,0,44);
	my @vals = unpack("V*",$header);    
	my $name = _uniToAscii(substr($v,($vals[3] + 0xCC),$vals[4]));
	my $fullname = _uniToAscii(substr($v,($vals[6] + 0xCC),$vals[7])) if ($vals[7] > 0);
	my $comment = _uniToAscii(substr($v,($vals[9] + 0xCC),$vals[10])) if ($vals[10] > 0);
	return ($name,$fullname,$comment);
}

#-------------------------------------------------------------
# parseF()
# Input : binary F structure from a user's entry
# Output: RID, # of logins, and ACB flags for the user
# TODO  : Need to parse the ACB flags
#-------------------------------------------------------------
sub parseF {
	my $f = shift;
# unpack() string is a little messy, but used this way for clarity
	my @vals = unpack("x8V2x8V2x8V2Vx4vx6vvx12",$f);
# $vals[0] and $vals[1] = lockout time
# $vals[2] and $vals[3] = creation time
# $vals[4] and $vals[5] = login time
#	my $rid = $vals[6];
#	my $acb = $vals[7];
#	my $failedcnt = $vals[8];
#	my $logins = $vals[9];
	return (@vals);
}

#-------------------------------------------------------------
# _uniToAscii()
# Input : Unicode string
# Output: ASCII version of the string
#-------------------------------------------------------------
sub _uniToAscii {
  my $str = $_[0];
  my $len = length($str);
  my $newlen = $len - 1;
  my @str2;
  my @str1 = split(//,$str,$len);
  foreach my $i (0..($len - 1)) {
    if ($i % 2) {
                  
    }
    else {
      push(@str2,$str1[$i]);
    }
  }
  return join('',@str2);
} 

#-------------------------------------------------------------
# getUsers()
# Input : none
# Output: Hash of hashes with user's RID as primary keys, and V
#         and F values as secondary keys
#-------------------------------------------------------------
sub getUsers {
	$regName = PSGetRegistryAt(0);
	PSRefreshRegistry($regName);

	my $KeyName = "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users";
	my $rHandle = PSOpenRegistry($regName, $KeyName);

	my %keynames = ();

	if ($rHandle == 0) {
    PSDisplayText("Unable to locate registry key");
    return;
	}
	else {
#    PSDisplayText("Registry opened succesfully.");
	}
#Successfully opened the key. Now, enumerate the key.
	while (1) {
    $RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
    last if ($RegKeyInfo->{nType} == -1);
    if ($RegKeyInfo->{strRegName} =~ m/^0000/) {
        $keynames{$RegKeyInfo->{strRegName}} = $RegKeyInfo->{strLastWriteTime};
    }
	}
	PSCloseHandle($rHandle);

	my %users = ();

	foreach my $k (keys %keynames) {
#    PSDisplayText($k."  ".$keynames{$k});
    my $cKey = $KeyName."\\".$k;
#    PSDisplayText($cKey);
    my $cHandle = PSOpenRegistry($regName,$cKey);
#    PSDisplayText($cHandle);
    while (1) {
    	my $keyInfo  = &ProScript::PSReadRegistry($cHandle);
      last if ($keyInfo->{nType} == -1);

			$users{$k}{V} = $keyInfo->{strValueData} if ($keyInfo->{strRegName} eq "V" && $keyInfo->{nType} == PS_TYPE_VALUE_RAW_BINARY);
			$users{$k}{F} = $keyInfo->{strValueData} if ($keyInfo->{strRegName} eq "F" && $keyInfo->{nType} == PS_TYPE_VALUE_RAW_BINARY);
    }
    PSCloseHandle($cHandle);
	}
	return %users;
}

#-------------------------------------------------------------
# getGroups()
# Input : none
# Output: Hash of hashes with group name as the primary key, and 
#         the comment and users as secondary keys.  The string 
#         containing the users is either "None", or a comma-separated
#         list of user names
#-------------------------------------------------------------
sub getGroups {
	my %groups = ();
	$regName = PSGetRegistryAt(0);
#	PSRefreshRegistry($regName);

	my $KeyName = "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Builtin\\Aliases";
	my $rHandle = PSOpenRegistry($regName, $KeyName);

	my %keynames = ();

	if ($rHandle == 0) {
		PSDisplayText("Unable to locate registry key");
		return;
	}
	else {
	#	PSDisplayText("Registry opened succesfully.");
	}
#Successfully opened the key. Now, enumerate the key.
	while (1) {
		$RegKeyInfo  = &ProScript::PSReadRegistry($rHandle);
		last if ($RegKeyInfo->{nType} == -1);
		if ($RegKeyInfo->{strRegName} =~ m/^0000/) {
			$keynames{$RegKeyInfo->{strRegName}} = $RegKeyInfo->{strLastWriteTime};
		}
	}
	PSCloseHandle($rHandle);

	foreach my $k (keys %keynames) {
#	PSDisplayText($k."  ".$keynames{$k});
		my $cKey = $KeyName."\\".$k;
#	PSDisplayText($cKey);
		my $cHandle = PSOpenRegistry($regName,$cKey);
#	PSDisplayText($cHandle);
		while (1) {
			my $keyInfo  = &ProScript::PSReadRegistry($cHandle);
			last if ($keyInfo->{nType} == -1);
			if ($keyInfo->{strRegName} eq "C" && $keyInfo->{nType} == PS_TYPE_VALUE_RAW_BINARY) {
				my @users = ();
				my $header = substr($keyInfo->{strValueData},0,0x34);
				my @vals = unpack("V*",$header);	
				my $grpname = _uniToAscii(substr($keyInfo->{strValueData},(0x34 + $vals[4]),$vals[5]));
#				PSDisplayText("$grpname");	

				my $comment = _uniToAscii(substr($keyInfo->{strValueData},(0x34 + $vals[7]),$vals[8]));
#				PSDisplayText("$comment");			
				my $num = $vals[12];
				$num -= 2 if ($grpname eq "Users");
				if ($num > 0) {
					my $count = 0;
					foreach my $c (1..$num) {
						$ofs = ($vals[10] + 52 + 25 + $count - 1);
						$ofs = ($vals[10] + 52 + 25 + $count - 1 + 24) if ($grpname eq "Users");
#					PSDisplayText("Ofs = $ofs");
						my $rid = unpack("v",substr($keyInfo->{strValueData},$ofs,2));					
						push(@users,$rid);
						$count += (27 + 1) if ($count < $vals[11]);
					}
				}
				$groups{$grpname}{comment} = $comment;
				if ((scalar @users) > 0) {
					$groups{$grpname}{users} = join(',',@users);
				}
				else {
					$groups{$grpname}{users} = "None";
				}
			}
		}
		PSCloseHandle($cHandle);
	}
	return %groups;
}

#----------------------------------------------------------------
# _getTimeDate()
# Input : 2 DWORDs, each containing half of the LastWrite time
# Output: readable GMT time string
#----------------------------------------------------------------
sub _getTimeDate {
# Borrowed from Andreas Schuster's ptfinder code
	my $Hi = shift;
	my $Lo = shift;
	my $t;
	if (($Lo == 0) and ($Hi == 0)) {
		$t = 0;
	} 
	else {
		$Lo -= 0xd53e8000;
		$Hi -= 0x019db1de;
		$t = int($Hi*429.4967296 + $Lo/1e7);
	}
	$t = 0 if ($t < 0);
	return gmtime($t);
}