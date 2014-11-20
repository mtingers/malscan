## malscan

Scan files for malware and other haxx

## Description

malscan consists of a set of rules (rules.cfg) to be run against files that will detect
possible malware, backdoors, and other related hacks that are often seen with outdated
Wordpress, Joomla, etc, installs.

## Usage

    malscan.py <rules> <regex-filename-filter> <path>

### Example
    malscan.py rules.cfg '\.(php|htm|html|htaccess|cgi)' /var/www/

