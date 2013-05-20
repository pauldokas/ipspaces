#!/usr/bin/env python

from __future__ import print_function

import re
import argparse
import datetime
import urllib2
import json
#from scapy.all import *


filename = 'TR_Subnets.csv'
#URL = 'http://bgp.he.net/AS217'
#URL = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS217&starttime=2012-11-09T00:00:00'
#URL = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s&starttime=%s'

debug = False
verbose = False


#
def ip2subnet(ip):
    if debug:
        print("analyzing IP %s" % ip)

    if not re.match('^\d{1,3]\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip, re.I):
        if debug:
            print("%s is not an IP address" % ip)
        return

    yield('0.0.0.0/0')


#
def asn2subnet(asn):
    if debug:
        print("analyzing ASN %s" % asn)

    m = re.match('^(as)?(\d+)$', asn, re.I)
    if not m:
        if debug:
            print("%s is not an ASN" % asn)
        return

    asn = m.group(2)
    if debug:
        print("extracted asn = %s" % str(asn))

    #
    today = datetime.date.today()
    onedayago = datetime.timedelta(days=1)
    yesterday = today - onedayago

    # pull the ASN subnets from stat.ripe.net
    URL = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s&starttime=%s'
    f = urllib2.urlopen(URL % (asn, yesterday.strftime('%FT%T')))
    prefixes = json.load(f)
    f.close()

    if debug:
        print("%s" % str(prefixes))

    for p in prefixes[u'data'][u'prefixes']:
        subnet = str(p[u'prefix'])
        yield(subnet)


#
if __name__ == '__main__':

    p = argparse.ArgumentParser(description="Find Internet gateway routers in an ASN")

    p.add_argument("-d", "--debug", action="store_true", default=False)
    p.add_argument("-v", "--verbose", action="store_true", default=False)

    (args, items) = p.parse_known_args()

    debug = args.debug
    verbose = args.verbose

    if len(items) == 0:
        p.print_help()
        exit(1)

    if debug:
        print("ASNs = %s" % ','.join(items))

    #
    asninfo = {}
    asn2sn = {}
    ip2tr = {}
    routers = {}

    #
    asnre = re.compile('^(as)?\d+$', re.I)
    ipre = re.compile('^\d{1,3]\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    for i in items:
        if debug:
            print("item = %s" % str(i))

        if asnre.match(i):
            for sn in asn2subnet(i):
                print("%s" % str(sn))
        elif ipre.match(i):
            for sn in ip2subnet(i):
                print("%s" % str(sn))

    exit(0)
