#!/usr/bin/env python3
#

import sys
import json
import numpy as np
import matplotlib.pyplot as plt

from collections import defaultdict


def semver2int(semver):
    if semver == 'trunk':
        semver = '0.10.0.0'
    vi = 0
    i = 0
    for v in reversed(semver.split('.')):
        vi += int(v) * (i * 10)
        i += 1
    return vi


def get_perf_data(perfname, stats):
    """ Return [labels,x,y,errs] for perfname 'mb_per_sec' as a numpy arrays
        labels: broker versions
        x: list with identical value (to plot on same x point)
        y: perfname counter (average)
        errs: errors
    """
    ver = defaultdict(list)

    # Per version:
    #  * accumulate values
    #  * calculate average
    #  * calculate error

    # Accumulate values per version
    for x in stats:
        v = str(x[0])
        ver[v].append(x[1][perfname])
    print('%s is %s' % (perfname, ver))

    labels0 = sorted(ver.keys(), key=semver2int)
    y0 = list()
    errs0 = list()

    # Maintain order by using labels0
    for v in labels0:
        # Calculate average
        avg = sum(ver[v]) / float(len(ver[v]))
        y0.append(avg)
        # Calculate error
        errs0.append(max(ver[v]) - avg)

    labels = np.array(labels0)
    y1 = np.array(y0)
    x1 = np.array(range(0, len(labels)))
    errs = np.array(errs0)
    return [labels, x1, y1, errs]


def plot(description, name, stats, perfname, outfile=None):
    labels, x, y, errs = get_perf_data(perfname, stats)
    plt.title('%s: %s %s' % (description, name, perfname))
    plt.xlabel('Kafka version')
    plt.ylabel(perfname)
    plt.errorbar(x, y, yerr=errs, alpha=0.5)
    plt.xticks(x, labels, rotation='vertical')
    plt.margins(0.2)
    plt.subplots_adjust(bottom=0.2)
    if outfile is None:
        plt.show()
    else:
        plt.savefig(outfile, bbox_inches='tight')
    return


if __name__ == '__main__':

    outfile = sys.argv[1]

    reports = []
    for rf in sys.argv[2:]:
        with open(rf) as f:
            reports.append(json.load(f))

    stats = defaultdict(list)

    # Extract performance test data
    for rep in reports:
        perfs = rep.get(
            'tests',
            dict()).get(
            '0038_performance',
            list).get(
            'report',
            None)
        if perfs is None:
            continue

        for perf in perfs:
            for n in ['producer', 'consumer']:
                o = perf.get(n, None)
                if o is None:
                    print('no %s in %s' % (n, perf))
                    continue

                stats[n].append((rep.get('broker_version', 'unknown'), o))

    for t in ['producer', 'consumer']:
        for perfname in ['mb_per_sec', 'records_per_sec']:
            plot('librdkafka 0038_performance test: %s (%d samples)' %
                 (outfile, len(reports)),
                 t, stats[t], perfname, outfile='%s_%s_%s.png' % (
                     outfile, t, perfname))
