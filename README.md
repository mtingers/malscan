## malscan

Scan files for malware and other haxx

## Description

malscan consists of a set of rules (rules.cfg) crafted to detect possible
malware, backdoors, and other related hacks that are often seen with outdated
Wordpress, Joomla, etc, installs.

## Usage

    usage: malscan.py [-h] -r RULESET -f INCLUDEFILTER -s SCANPATH [-p]

    optional arguments:
      -h, --help            show this help message and exit
      -r RULESET, --ruleset RULESET
                            The path to rule definition file
      -f INCLUDEFILTER, --file-regex INCLUDEFILTER
                            Scan files matching this regex pattern
      -s SCANPATH, --scanpath SCANPATH
                            The file or directory to scan
      -p, --printpass       Print OK files to stderr


### Example
    malscan.py -r rules.cfg -f '\.(php|htm|html|htaccess|cgi)' -s /var/www/

