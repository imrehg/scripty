#!/usr/bin/env python2
"""
Scipt to extract IP addresses matching a named iptables rule from
from log files. Get their geolocation an create a link to a generated
map showing them.

Input is in syslog format.
"""
import re
import sys
import GeoIP

#### General settings
_MAPSTR = "&markers=color:%s|%.6f,%.6f"
_MAPURLBASE = "http://maps.google.com/maps/api/staticmap?zoom=1&size=500x300&sensor=false"
_SRC_IP = re.compile(r'.*?ATTACKED.*?SRC=(?P<sourceIP>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)')

def ipmatch(lines, matchrule):
    """
    Take a bunch of line and match the source IPs.
    """
    out = []
    for line in lines:
        res = matchrule.match(line)
        if res.group('sourceIP') is not None:
            out += [res.group('sourceIP')]
    return out

def counts(count1, count2):
    """
    Reducer for counting data stored in a dict
    """
    for key in count2.keys():
        if key in count1:
            count1[key] += count2[key]
        else:
            count1[key] = count2[key]
    return count1

def getmap(retries, mapbase=_MAPURLBASE):
    """
    Create Google Static Map API URL based on IPs and the number of times they
    tried and got blocked.

    Input:
    retries: dict if {IP: blocked_times} format
    mapbase

    Output:
    Url string to the map picture
    """
    # Explicitly need to download database
    # See http://www.pointlessrants.com/2010/05/python-geoip-python-geoip-cities-tutorial/
    geo = GeoIP.open("/usr/share/GeoIP/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)
    maps = []
    colors = ['red', 'blue', 'yellow']

    for srcip in retries.keys():
        # Get location record
        rec = geo.record_by_addr(srcip)

        if retries[srcip] > 10:
            coloridx = 2
        elif retries[srcip] > 1:
            coloridx = 1
        else:
            coloridx = 0

        maps += [_MAPSTR % (colors[coloridx],
                            rec['latitude'],
                            rec['longitude'])
                 ]
    url = mapbase + "".join(maps)
    return url

def main(argv=None):
    """
    Take any number of log file names and generate a map URL for the
    location of the attacker IP addresses.
    """
    if argv is None:
        argv = sys.argv

    if len(argv) < 2:
        sys.exit(0)

    infiles = sys.argv[1:]
    total = []
    for fname in infiles:
        logfile = open(fname, "r")
        addr = ipmatch(logfile.readlines(), _SRC_IP)
        if len(addr) > 0:
            total += addr

    tries = [{ip: 1} for ip in total]
    retries = reduce(counts, tries)

    url = getmap(retries)
    print url

if __name__ == "__main__":
    main()
