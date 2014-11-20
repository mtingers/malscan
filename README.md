## malscan

Scan files for malware and other haxx

## Description

malscan consists of a set of rules (rules.cfg) crafted to detect possible
malware, backdoors, and other related hacks that are often seen with outdated
Wordpress, Joomla, etc, installs.

## Usage

    malscan.py <rules> <regex-filename-filter> <path>

### Example
    malscan.py rules.cfg '\.(php|htm|html|htaccess|cgi)' /var/www/

