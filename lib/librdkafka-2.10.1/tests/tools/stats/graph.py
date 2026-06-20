#!/usr/bin/env python3
#
# Use pandas + bokeh to create graphs/charts/plots for stats CSV (to_csv.py).
#

import os
import pandas as pd
from bokeh.io import curdoc
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.plotting import figure
from bokeh.palettes import Dark2_5 as palette
from bokeh.models.formatters import DatetimeTickFormatter

import pandas_bokeh
import argparse
import itertools
from fnmatch import fnmatch

datecolumn = '0time'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Graph CSV files')
    parser.add_argument('infiles', nargs='+', type=str,
                        help='CSV files to plot.')
    parser.add_argument('--cols', type=str,
                        help='Columns to plot (CSV list)')
    parser.add_argument('--skip', type=str,
                        help='Columns to skip (CSV list)')
    parser.add_argument('--group-by', type=str,
                        help='Group data series by field')
    parser.add_argument('--chart-cols', type=int, default=3,
                        help='Number of chart columns')
    parser.add_argument('--plot-width', type=int, default=400,
                        help='Per-plot width')
    parser.add_argument('--plot-height', type=int, default=300,
                        help='Per-plot height')
    parser.add_argument('--out', type=str, default='out.html',
                        help='Output file (HTML)')
    args = parser.parse_args()

    outpath = args.out
    if args.cols is None:
        cols = None
    else:
        cols = args.cols.split(',')
        cols.append(datecolumn)

    if args.skip is None:
        assert cols is None, "--cols and --skip are mutually exclusive"
        skip = None
    else:
        skip = args.skip.split(',')

    group_by = args.group_by

    pandas_bokeh.output_file(outpath)
    curdoc().theme = 'dark_minimal'

    figs = {}
    plots = []
    for infile in args.infiles:

        colors = itertools.cycle(palette)

        cols_to_use = cols

        if skip is not None:
            # First read available fields
            avail_cols = list(pd.read_csv(infile, nrows=1))

            cols_to_use = [c for c in avail_cols
                           if len([x for x in skip if fnmatch(c, x)]) == 0]

        df = pd.read_csv(infile,
                         parse_dates=[datecolumn],
                         index_col=datecolumn,
                         usecols=cols_to_use)
        title = os.path.basename(infile)
        print(f"{infile}:")

        if group_by is not None:

            grp = df.groupby([group_by])

            # Make one plot per column, skipping the index and group_by cols.
            for col in df.keys():
                if col in (datecolumn, group_by):
                    continue

                print("col: ", col)

                for _, dg in grp:
                    print(col, " dg:\n", dg.head())
                    figtitle = f"{title}: {col}"
                    p = figs.get(figtitle, None)
                    if p is None:
                        p = figure(title=f"{title}: {col}",
                                   plot_width=args.plot_width,
                                   plot_height=args.plot_height,
                                   x_axis_type='datetime',
                                   tools="hover,box_zoom,wheel_zoom," +
                                   "reset,pan,poly_select,tap,save")
                        figs[figtitle] = p
                        plots.append(p)

                        p.add_tools(HoverTool(
                            tooltips=[
                                ("index", "$index"),
                                ("time", "@0time{%F}"),
                                ("y", "$y"),
                                ("desc", "$name"),
                            ],
                            formatters={
                                "@0time": "datetime",
                            },
                            mode='vline'))

                        p.xaxis.formatter = DatetimeTickFormatter(
                            minutes=['%H:%M'],
                            seconds=['%H:%M:%S'])

                    source = ColumnDataSource(dg)

                    val = dg[group_by][0]
                    for k in dg:
                        if k != col:
                            continue

                        p.line(x=datecolumn, y=k, source=source,
                               legend_label=f"{k}[{val}]",
                               name=f"{k}[{val}]",
                               color=next(colors))

            continue

        else:
            p = df.plot_bokeh(title=title,
                              kind='line', show_figure=False)

        plots.append(p)

    for p in plots:
        p.legend.click_policy = "hide"

    grid = []
    for i in range(0, len(plots), args.chart_cols):
        grid.append(plots[i:i + args.chart_cols])

    pandas_bokeh.plot_grid(grid)
