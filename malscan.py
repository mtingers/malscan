#!/usr/bin/python

import sys, os, re
from configobj import ConfigObj
#import cProfile

def readconf(path):
    return ConfigObj(path)

def validate_patterns(rules):
    errors = 0
    nc = {}
    for rule, conf in rules.items():
        nc[rule] = {'sha256':[], 'patterns':[], 'excludes':[], 'exact':False, 'sensitive':False}
        sensitive = 0
        exact = False
        if 'exact' in conf:
            if conf['exact'] == 'yes':
                nc[rule]['exact'] = True
                exact = True
        if 'sensitive' in conf:
            if conf['sensitive'] == 'yes':
                nc[rule]['sensitive'] = True
                sensitive = True
        if exact:
            nc[rule]['patterns'] = conf['patterns']
            if 'excludes' in conf:
                nc[rule]['excludes'] = conf['excludes']
        elif sensitive:
            for p in conf['patterns']:
                try:
                    nc[rule]['patterns'].append(re.compile(p))
                except Exception, e:
                    print "Bad pattern:", rule, type(p), p, e
                    errors += 1

            if 'excludes' in conf:
                for p in conf['excludes']:
                    try:
                        nc[rule]['excludes'].append(re.compile(p))
                    except Exception,e :
                        print "Bad exclude pattern:", rule, type(p), p, e
                        errors += 1
        else:
            if 'sha256' in conf:
                for p in conf['sha256']:
                    nc[rule]['sha256'].append(p)

            if not 'patterns' in conf: continue

            for p in conf['patterns']:
                try:
                    nc[rule]['patterns'].append(re.compile(p, flags=re.IGNORECASE))
                except Exception, e:
                    print "Bad pattern:", rule, type(p), p, e
                    errors += 1

            if 'excludes' in conf:
                for p in conf['excludes']:
                    try:
                        nc[rule]['excludes'].append(re.compile(p, flags=re.IGNORECASE))
                    except Exception,e :
                        print "Bad exclude pattern:", rule, type(p), p, e
                        errors += 1
    if errors > 1:
        sys.exit(1)
    return nc

def chk_line(line, rules):
    matches = []
    for rule, conf in rules.items():
        ematch = 0
        failed = 0
        # It's a hashlib check only
        if not conf['patterns']:
            continue

        if conf['exact']:
            if not conf['patterns']:
                nopatterns = 1
            for p in conf['patterns']:
                if not p in line:
                    failed = 1 #didnt match all patterns
                    break
            if failed < 1:
                for p in conf['excludes']:
                    if p in line:
                        ematch += 1 # matched an exclude pattern
                        break
        else:
            for p in conf['patterns']:
                if not p.search(line):
                    failed = 1
                    break
            if failed < 1:
                for p in conf['excludes']:
                    if p.search(line):
                        ematch += 1
                        break
        if failed < 1 and ematch < 1:
            matches.append(rule)

    return matches

def hashfile(fname, blocksize=65536):
    import hashlib
    try:
        f = open(fname, 'rb')
    except IOError, e:
        print e
        return ''

    hasher = hashlib.sha256()
    buf = f.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = f.read(blocksize)
    f.close()
    return hasher.hexdigest()

def check_hashes(fpath, rules):
    matches = []
    for rule, conf in rules.items():
        if not conf['sha256']: continue
        h = hashfile(fpath)
        for p in conf['sha256']:
            if h == p:
                matches.append(rule)
                break
    return matches

def process(path, rules):
    try:
        fh = open(path)
    except IOError, e:
        print e
        return

    allmatches = []
    for line in fh:
        matches = chk_line(line, rules)
        if matches:
            for m in matches:
                if not m in allmatches:
                    allmatches.append(m)

    fh.close()
    matches = check_hashes(path, rules)
    for m in matches:
        allmatches.append(m)

    if allmatches:
        print path, allmatches

def run(path, includefilter, config):
    ifre = re.compile(includefilter)
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for f in files:
                if os.path.islink(root+'/'+f): continue
                if ifre.search(f):
                    process(root+'/'+f, config)
    else:
        process(path, config)

def usage():
    print "usage: malscan <rules> <filter> <path>"
    sys.exit(1)

def main(scanpath, includefilter, ruleset):
    path = scanpath
    includefilter = includefilter
    config = readconf(ruleset)
    config = validate_patterns(config)
    run(path, includefilter, config)
    #cProfile.run('run(path, includefilter, config)')


if __name__ == "__main__":
    try:
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('-r', '--ruleset', required=True, dest='ruleset')
        parser.add_argument('-f', '--file-regex', required=True, dest='includefilter')
        parser.add_argument('-p', '--scanpath', required=True, dest='scanpath')
        args = parser.parse_args()
        main(args.scanpath, args.includefilter, args.ruleset)
    except KeyboardInterrupt:
        sys.exit(1)
