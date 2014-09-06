#!/usr/bin/perl -w
# $Id$

=pod

=head1 COPYRIGHT


This software is Copyright (c) 2011-2012 NETWAYS GmbH, Thomas Gelf
                               <support@netways.de>

(Except where explicitly superseded by other copyright notices)

=head1 LICENSE

This work is made available to you under the terms of Version 2 of
the GNU General Public License. A copy of that license should have
been provided with this software, but in any event can be snarfed
from http://www.fsf.org.

This work is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 or visit their web page on the internet at
http://www.fsf.org.


CONTRIBUTION SUBMISSION POLICY:

(The following paragraph is not intended to limit the rights granted
to you to modify and distribute this software under the terms of
the GNU General Public License and is only of importance to you if
you choose to contribute your changes and enhancements to the
community by submitting them to NETWAYS GmbH.)

By intentionally submitting any modifications, corrections or
derivatives to this work, or any other work intended for use with
this Software, to NETWAYS GmbH, you confirm that
you are the copyright holder for those contributions and you grant
NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
royalty-free, perpetual, license to use, copy, create derivative
works based on those contributions, and sublicense and distribute
those contributions and any derivatives thereof.

=head1 NAME

check_fujitsu_dx

=head1 SYNOPSIS

This plugin queries Fujitsu Eternus/DX Storage devices by SNMP

=head1 OPTIONS

check_fujitsu_dx.pl [options] -H <hostname> -C <SNMP community>

=over

=item   B<-H>

Hostname

=item   B<-C>

Community string (default is "public")

=item   B<-A|--available-disks>

Expected available disks

=item   B<-S|--spare-disks>

Expected spare disk count

=back

=head1 DESCRIPTION

This plugin queries Fujitsu Eternus/DX Storage devices by SNMP

MIB file is not required, OIDs are hardcoded. This plugin is able to
discover your Eternus Storage device ...

This devices also provide access to the IF-MIB, therefore you could use
other plugins to monitor their network traffic or interface status.

=cut

use Getopt::Long;
use Pod::Usage;
use File::Basename;
use Net::SNMP;
use Data::Dumper;

# predeclared subs
use subs qw/help fail fetchOids fetchSystemInfo fetchEternusTables checkEternus/;

# predeclared vars
use vars qw (
  $PROGNAME
  $VERSION

  %states
  %state_names
  %performance

  @info
  @perflist

  $opt_host
  $opt_help
  $opt_man
  $opt_verbose
  $opt_version
);

# Main values
$PROGNAME = basename($0);
$VERSION  = '1.0.3';

# Nagios exit states
%states = (
        'OK'       => 0,
        'WARNING'  => 1,
        'CRITICAL' => 2,
        'UNKNOWN'  => 3
);

# Nagios state names
%state_names = (
        0 => 'OK',
        1 => 'WARNING',
        2 => 'CRITICAL',
        3 => 'UNKNOWN'
);

# SNMP
my $opt_community       = 'public';
my $snmp_version        = '1';
my $global_state        = 'OK';
my $opt_disks_available = 0;
my $opt_disks_spare     = 0;

# Retrieve commandline options
Getopt::Long::Configure('bundling');
GetOptions(
        'h|help'               => \$opt_help,
        'man'                  => \$opt_man,
        'H=s'                  => \$opt_host,
        'C=s',                 => \$opt_community,
        'A|available-disks=s', => \$opt_disks_available,
        'S|spare-disks=s',     => \$opt_disks_spare,
        'v|verbose'            => \$opt_verbose,
        'V'                    => \$opt_version
) || help( 1, 'Please check your options!' );

my %sys = ();


# Any help needed?
help( 1) if $opt_help;
help(99) if $opt_man;
help(-1) if $opt_version;
help(1, 'Not enough options specified!') unless ($opt_host);

# Prepare SNMP Session
($session, $error) = Net::SNMP->session(
        -hostname  => $opt_host,
        -community => $opt_community,
        -port      => 161,
        -version   => $snmp_version,
);
fail('UNKNOWN', $error) unless defined($session);

# Mapping global status values (fjDary baseOid.6) to Nagios/Icinga status codes
my %global_status_map = (
        1 => 'UNKNOWN',  # unknown
        2 => 'UNKNOWN',  # unused
        3 => 'OK',       # ok
        4 => 'WARNING',  # warning
        5 => 'CRITICAL'  # failed
);

# Mapping per-object status values to Nagios/Icinga status codes
my %hw_status_map = (
    1 => 'OK',       # normal
    2 => 'CRITICAL', # alarm
    3 => 'WARNING',  # warning
    4 => 'CRITICAL', # invalid
    5 => 'WARNING',  # maintenance
    6 => 'UNKNOWN'   # undefined
);
my %hw_output_map = (
    1 => 'normal',      # normal
    2 => 'alarm',       # alarm
    3 => 'warning',     # warning
    4 => 'invalid',     # invalid
    5 => 'maintenance', # maintenance
    6 => 'undefined'    # undefined
);

my %disk_states = (
    1 => 'available',
    2 => 'broken',
    3 => 'notavailable',
    4 => 'notsupported',
    5 => 'present',
    6 => 'readying',
    7 => 'recovering',
    64 => 'partbroken',
    65 => 'spare',
    66 => 'formatting',
    67 => 'unformatted',
    68 => 'notexist',
    69 => 'copying'
);

fetchSystemInfo();

### OID definitions ###

my $debug = 0;
my $ftsMib;

print Dumper(\%sys) if $debug;

# net-snmp: 8072
if ($sys{'enterprise'} != 211) {
    fail('CRITICAL', sprintf(
        'SNMP enterprise "%d" is not supported by this check',
        $sys{'enterprise'}
    ));
}

if ($sys{'product'} eq '1.21.1.50') {
    # product(1).storage(21).nsp(1).fjdarye50(60)
    # Eternus DX50, auch bei ETERNUS-DX440-RZ-PY-DemoCenter (HMB)
    $ftsMib = 'DX50';
} elsif ($sys{'product'} eq '1.21.1.100') {
    $ftsMib = 'DX100';

} elsif ($sys{'product'} eq '1.21.1.60') {
    # product(1).storage(21).nsp(1).fjdarye60(60)
    # Eternus DX60
    # Auch bei "Eternus-DX80 in DC1C4DX80" (PRIMERGY_DemoCenter_Bad_Homburg)
    $ftsMib = 'DX60';
} elsif ($sys{'product'} eq '3.2.10') {
    # Net-SNMP Linux Test
} else {
    fail('CRITICAL', sprintf(
        'SNMP enterprise "%d" with product "%s" is not supported by this check',
        $sys{'enterprise'},
        $sys{'product'}
    ));
}

my $baseOid = $sys{'objectId'};
my $unit_status_oid    = $baseOid . '.6.0';   # fjdaryUnitStatus(6)
my $unit_vendorId_oid  = $baseOid . '.1.4.0'; # fjdarySsp(1).fjdarySspVendorId(4)
my $unit_productId_oid = $baseOid . '.1.5.0'; # fjdarySsp(1).fjdarySspProductId(5)
my $unit_machineid_oid = $baseOid . '.1.1.0'; # fjdarySSp(1).fjdarySspMachineId(1) -> contains S/N

print "FTS MIB is $ftsMib\n" if $debug;

# Hinweis: DX60 unterstützt auch RFC4044 - Fibre Channel Management MIB (experimental.94.1.6)

fetchEternusTables();
checkEternus();
print "Retrieved all OIDs\n" if $debug;


foreach (keys %performance) {
        push @perflist, $_ . '=' . $performance{$_};
}
my $info_delim = ', ';
$info_delim = "\n";
printf('%s %s|%s', $global_state, join($info_delim, @info), join(' ', sort @perflist));
exit $states{$global_state};

sub fetchEternusTables()
{
    my %tIndex = (
        'DX50' => {
            'fjdaryCm' => [1, { # Controller Modules
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 4, # 16-23
                'role'     => 5  # 1, 2, 0
                # 'ptId'   => 6, # Hex-STRING! -> "PT management information"
            }],
            'fjdaryCa' => [2, { # Channel Adapters
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 4,
                'type'     => 5
                # 'ptId'     => 6,
            }],
            # .2.3 Frt - front-end routers
            # .2.4 Brt - back-end routers
            'fjdaryCmmemory' => [5, { # CM memory
                'id'       => 2,
                'status'   => 3,
                'capacity' => 4
            }],
            # .2.6 Cmfan Controller Module Fans
            # .2.7 Cf Compact Flashs
            # .2.8 Opnl OPNL = Operation Panels
            'fjdaryCefan' => [9, { # Controller Enclosure Fan
                'id'       => 2,
                'status'   => 3
            }],
            # .2.10 Svc SerVice Controllers
            # .2.11 Smc System Management Controller
            'fjdaryBcu' => [12, { # Battery Control Unit
                'id'       => 2,
                'status'   => 3
            }],
            'fjdaryBtu' => [13, { # Battery Unit
                'id'       => 2,
                'status'   => 3
            }],
            'fjdaryCe' => [14, { # Controller Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            # .2.15 Ceinletthml CE inlet thermal sensors
            # .2.16 Cethermal CE thermal
            # .2.17 Cpsu CE Power Supply
            # .2.18 Scbb SCBB = ?
            'fjdaryDe' => [19, { # Device Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            # .2.21 Dpsu DE Power Supply
            'fjdaryDefan' => [22, { # Device Enclosure Fan
                'id'       => 2,
                'status'   => 3
            }],
            # .2.23 Deinletthml DE inlet thermal sensors
            # .2.24 Dethermal DE thermal
            'fjdaryDisk' => [25, { # DISKs
                'id'        => 2,
                'status'    => 3,
                'plun'      => 4, # PLUN
                'purpose'   => 5, # INT
                'diskType'  => 6,
                'diskWwn'   => 7, # World Wide Name
                'vendorId'  => 8, # Octet String
                'productId' => 9, # Octet String
                'revision'  => 10 # Octet String
            }],
        },
        'DX60' => {
            'fjdaryCm' => [1, { # Controller Modules
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 4, # 16-23
                'role'     => 5,  # 1, 2, 0
                # 'partNo'   => 6, # Hex-STRING!
                'serialNo' => 7 # Hex-STRING!
                # 'revision' => 8  # Hex-STRING!
            }],
            'fjdaryCa' => [2, { # Channel Adapters
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 4,
                'type'     => 5
            }],
            'fjdaryCmmemory' => [3, { # CM memory
                'id'       => 2,
                'status'   => 3,
                'capacity' => 4
                # 'partNo'   => 5, # Hex-STRING!
                # 'serialNo' => 6, # Hex-STRING!
            }],
            'fjdaryCe' => [6, { # Controller Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            'fjdaryDe' => [7, { # Device Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            # Nur bei DX60:
            #'fjdaryExpander' => [8, { # Expander
            #    'id'       => 2,
            #    'status'   => 3
            #}],
            'fjdaryDisk' => [12, { # DISKs
                'id'        => 2,
                'status'    => 3,
                # 'plun'      => 4, # PLUN
                # 'purpose'   => 5, # INT, blind guess: 5 'normal', 10 'spare', 1 'nix', 0 'keine disk'
                # 'diskType'  => 6, # INT, 6 und 12 ?!
                'diskWwn'   => 7, # World Wide Name, e.g. 50 00 C5 00 12 A9 4E C4 = Seagate
                # 'vendorId'  => 8, # Octet String, all: 53 45 41 47 41 54 45 00
                # 'productId' => 9, # Octet String, diskType 6: 53 54 33 33 30 30 36 35 36 53 53 00 00 00 00 00, diskType 12: 53 54 33 31 30 30 30 36 34 30 53 53 00 00 00 00
                # 'revision'  => 10 # Octet String, all: 42 46 30 39 00 00 00 00
            }],
        },

        'DX100' => {
            'fjdaryCm' => [1, { # Controller Modules
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 5, # 16-23
                'role'     => 6,  # 1, 2, 0
                # 'partNo'   => 6, # Hex-STRING!
                'serialNo' => 8 # Hex-STRING!
                # 'revision' => 8  # Hex-STRING!
            }],
            'fjdaryCa' => [3, { # Channel Adapters
                'id'       => 2,
                'status'   => 3,
                'moduleId' => 5,
                'type'     => 6
            }],
            'fjdaryCmmemory' => [4, { # CM memory
                'id'       => 2,
                'status'   => 3,
                'capacity' => 5
                # 'partNo'   => 5, # Hex-STRING!
                # 'serialNo' => 6, # Hex-STRING!
            }],
            'fjdaryCe' => [10, { # Controller Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            'fjdaryDe' => [14, { # Device Enclosure
                'id'       => 2,
                'status'   => 3
            }],
            # Nur bei DX60:
            #'fjdaryExpander' => [8, { # Expander
            #    'id'       => 2,
            #    'status'   => 3
            #}],
            'fjdaryDisk' => [19, { # DISKs
                'index'        => 1,
                'id'        => 2,
                'status'    => 3,
                'compStatus'    => 5,
                # 'plun'      => 4, # PLUN
                # 'purpose'   => 5, # INT, blind guess: 5 'normal', 10 'spare', 1 'nix', 0 'keine disk'
                # 'diskType'  => 6, # INT, 6 und 12 ?!
                'diskWwn'   => 10, # World Wide Name, e.g. 50 00 C5 00 12 A9 4E C4 = Seagate
                # 'vendorId'  => 8, # Octet String, all: 53 45 41 47 41 54 45 00
                # 'productId' => 9, # Octet String, diskType 6: 53 54 33 33 30 30 36 35 36 53 53 00 00 00 00 00, diskType 12: 53 54 33 31 30 30 30 36 34 30 53 53 00 00 00 00
                # 'revision'  => 10 # Octet String, all: 42 46 30 39 00 00 00 00
            }],
        },

    );
    my %fetch = ();
    foreach my $key (keys %{$tIndex{$ftsMib}}) {
        $fetch{$baseOid . '.2.' . $tIndex{$ftsMib}->{$key}[0]} =
            [$key, $tIndex{$ftsMib}->{$key}[1]];
    }

    print "Fetching as follows:\n" if $debug;
    print Dumper(\%fetch) if $debug;

    my %tables = fetchDjdaryTables(\%fetch);
    print "Fetch done\n" if $debug;
    my %components;
    my %state_count = (
        'available' => 0,
        'spare'     => 0,
    );
    foreach my $key (keys %tables) {
        if ($key eq 'fjdaryDisk') {
            for ($i = 0; $i < scalar(@{$tables{$key}}); $i++) {
                next if $disk_states{ $tables{$key}[$i]->{'status'} } eq 'notavailable';
                $state_count{ $disk_states{ $tables{$key}[$i]->{'status'} } }++;
            }
            print "Disk summary: " . Dumper(\%state_count) if $debug;
        } else {
            for ($i = 0; $i < scalar(@{$tables{$key}}); $i++) {
                if ($hw_output_map{$tables{$key}[$i]->{'status'}} ne 'invalid') {
                    $components{$key}->{$hw_output_map{$tables{$key}[$i]->{'status'}}}++;
                }
            }
        }
    }
    if ($opt_disks_available > 0 && $state_count{'available'} < $opt_disks_available) {
        raiseGlobalState('CRITICAL');
        push @info, sprintf(
            'CRITICAL: There are only %d instead of %d disks available',
            $state_count{'available'},
            $opt_disks_available
        );
    }
    if ($opt_disks_spare > 0 && $state_count{'spare'} < $opt_disks_spare) {
        raiseGlobalState('CRITICAL');
        push @info, sprintf(
            'CRITICAL: There are only %d instead of %d spare disks available',
            $state_count{'spare'},
            $opt_disks_spare
        );
    }

    my @diskinfo;
    foreach my $key (keys %state_count) {
        push @diskinfo, sprintf('%s x%s', $key, $state_count{$key});
    }
    push @info, 'Disk states: ' . join(', ', @diskinfo);
    foreach my $comp (keys %components) {
        foreach my $state (keys %{$components{$comp}}) {
            next if ($state eq 'normal');
            raiseGlobalState('CRITICAL');
            push @info, sprintf(
                'CRITICAL: %s is %dx %s',
                $comp,
                $components{$comp}->{$state},
                $state
            );
        }
    }
    print Dumper(\%components) if $debug;

    # DX60 hat zudem fjdarySensor (60.13) mit MachinePower, EncPower, MachineTemp und EncTemp

    # WWN:
    # First character -> NAA, Network Address Authority
    # 1 - IEEE 803.2 standard 48 bit ID
    # 2 - IEEE 803.2 extended 48-bit ID
    # 5 - IEEE Registered Name
    # 6 - IEEE Extended Registered Name
    # 50 00 C5 00 12 A9 4E C4
    # 5                       => Registered name
    #  0 00 C5 0              => bei 5 => vendor => 00:0C:50 => Seagate Technology
    #           0 12 A9 4E C4 => Vendor-specific, could be port, device s/n etc

    # Info: http://howto.techworld.com/storage/156/how-to-interpret-worldwide-names/
    # Vendors: http://standards.ieee.org/develop/regauth/oui/oui.txt

    # id: meist hohe INTs

    # "status" meistens:
    #  normal(1)
    #  alarm(2)
    #  warning(3)
    #  invalid(4)
    #  maintenance(5)
    #  undefined(6)

    # "status" bei DISKs:
    #  available(1),     Normal state
    #  broken(2),        Abnormal state
    #  notavailable(3),  Not available state
    #  notsupported(4),  Unsupported error state
    #  present(5),       Undefined volume set state
    #  readying(6),      Data readying state
    #  recovering(7),    Data recovering state
    #  partbroken(64),   Abnormal state
    #  spare(65),        Using spare disk state
    #  formatting(66),   Data formatting state
    #  unformatted(67),  Unformatted state
    #  notexist(68),     Not exist
    #  copying(69)       Data copying state

}

sub fetchDjdaryTables()
{
    my $base = shift;
    my %cnt;
    my %result;
    foreach my $key (keys %$base) {
        $cnt{$key . '.1.0'} = $base->{$key}[0];
    }
    print "Fetching item counts:\n" if $debug;
    print Dumper(\%cnt) if $debug;
    my %cnt_result = fetchOids(\%cnt);

    # fake
    #%cnt_result = (
    #     'fjdaryCe' => 2,
    #     'fjdaryDe' => 10,
    #     'fjdaryDisk' => 240,
    #     'fjdaryCm' => 2,
    #     'fjdaryCmmemory' => 2,
    #     'fjdaryCa' => 4
    #);

    print Dumper(\%cnt_result) if $debug;
    foreach my $key (keys %{$base}) {
        for ($i = 0; $i < $cnt_result{$base->{$key}[0]}; $i++) {
        # for ($i = 1; $i <= $cnt_result{$base->{$key}[0]}; $i++) { # Dummy IfMIB Test
            my %keys;
            foreach my $index (keys %{$base->{$key}[1]}) {
                $keys{$key . '.2.1.' . $base->{$key}[1]{$index} . '.' . $i } = $index;
            }
#            print "Fetching $key(" . $base->{$key}[0] . ") [$i]:\n" if $debug;
#            print Dumper(\%keys) if $debug;
            my %res = fetchOids(\%keys);
            $result{$base->{$key}[0]}[$i] = \%res;
            # $result{$base->{$key}[0]}[$i - 1] = \%res; # Dummy IfMIB Test
        }
    }
    print "Dumping results:\n" if $debug;
    print Dumper(\%result) if $debug;
    return %result;
}


sub checkEternus()
{
    my %oids = (
        $unit_status_oid => 'status',
        $unit_vendorId_oid => 'vendor',
        $unit_productId_oid => 'product',
        $unit_machineid_oid => 'machineId',
    );

    print "Fetching global status:\n" if $debug;
    print Dumper(\%oids) if $debug;

    my %global = fetchOids(\%oids);
    $global{'serial'} = substr($global{'machineId'}, 26, 12);

    my %global_info = (
        'OK'       => 'Overall state is OK',
        'WARNING'  => 'There is at least one component in a WARNING state',
        'CRITICAL' => 'There is one or more CRITICAL issue',
        'UNKNOWN'  => 'Overall state is unknown',
    );
    raiseGlobalState($global_status_map{$global{'status'}});
    push @info, sprintf(
        '%s: %s, s/n: %s',
        $global{'product'},
        $global_info{$global_status_map{$global{'status'}}},
        $global{'serial'},
    );
}

sub fetchSystemInfo()
{
    my $mib2 = '1.3.6.1.2.1.1';
    my %info = fetchOids({
        $mib2 . '.1.0' => 'sysDescr',
        $mib2 . '.2.0' => 'sysObjectId',
        $mib2 . '.4.0' => 'sysContact',
        $mib2 . '.5.0' => 'sysName',
        $mib2 . '.6.0' => 'sysLocation',
    });
    foreach my $var (keys %info) {
        my $key = $var;
        $key =~ s/^sys//g;
        $sys{lcfirst($key)} = $info{$var};
    }
    my $enterprise = $sys{'objectId'};
    if (substr($enterprise, 0, 12) eq '1.3.6.1.4.1.') {
        $enterprise = substr($enterprise, 12);
        my @parts = split /\./, $enterprise;
        $sys{'enterprise'} = shift @parts;
        $sys{'product'} = join '.', @parts;
    } else {
        fail('CRITICAL', "OID $enterprise is not a valid enterprise OID");
    }
}

# Fetch given OIDs, return a hash
sub fetchOids {
    my %result;
    my %oids = %{$_[0]};
    my ($r, $error) = $session->get_request(keys %oids);
    if (!defined($r)) {
            fail('CRITICAL', sprintf(
        'Failed to query device %s: %s',
        $opt_host,
        $session-> error()
    ));
    };
    foreach (keys %{$r}) {
       $result{$oids{$_}} = $r->{$_};
    }
    return %result;
}

# Raise global state if given one is higher than the current state
sub raiseGlobalState {
    my @states = @_;
    foreach my $state (@states) {
            # Pay attention: UNKNOWN > CRITICAL
            if ($states{$state} > $states{$global_state}) {
                    $global_state = $state;
            }
    }
}

# Print error message and terminate program with given status code
sub fail {
    my ($state, $msg) = @_;
    print $state_names{ $states{$state} } . ": $msg";
    exit $states{$state};
}

# help($level, $msg);
# prints some message and the POD DOC
sub help {
    my ($level, $msg) = @_;
    $level = 0 unless ($level);
    if ($level == -1) {
            print "$PROGNAME - Version: $VERSION\n";
            exit $states{UNKNOWN};
    }
    pod2usage({
            -message => $msg,
            -verbose => $level
    });
    exit $states{'UNKNOWN'};
}

1;
