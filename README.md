# ansible-geofirewall
Ansible role that deploys a bash firewall script called `geofirewall.sh`.

This role also builds the configuration file based on vars set for the host.

The main feature of the script is the use of __xtables/geoip__ information for filtering.

If xtables/geoip is unavalable, the script just skips parameters that use country codes.

This role has been tested on __Ubuntu 14.04 LTS__.
