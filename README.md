check_fujitsu_dx
================

This plugin queries Fujitsu Eternus/DX Storage devices by SNMP

MIB file is not required, OIDs are hardcoded. This plugin is able to
discover your Eternus Storage device.

This devices also provide access to the IF-MIB, therefore you could use
other plugins to monitor their network traffic or interface status.


### Requirements

* Perl Net SNMP library



### Usage

    check_fujitsu_dx.pl [options] -H <hostname> -C <SNMP community>

    -H  Hostname
    -C  Community string (default is "public")
    -A|--available-disks
        Expected available disks
    -S|--spare-disks
        Expected spare disk count

