"""Result figures for the paper (replace Tables II, IV and V; full tables in the supplement).

Fig. 2 (C1): B3 error and whole-relation cost ratio versus bucket width.
Fig. 3 (C3): (a) min-entropy leakage versus budget under the two charging
rules; (b) person identification versus number of trips, per-trace versus
per-device budget.

Reads results/{n1_fair_summary, n5_bounds_charging, n5_bounds_users,
n5_bounds_users_device}.csv and writes fig_c1.pdf and fig_c3.pdf to OUT_DIR
(default: the current directory).

    python3 scripts/results_figs.py [OUT_DIR]
"""
import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, NullLocator

HERE = Path(__file__).resolve().parent
RES = HERE.parent / "results"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

# Validated categorical slots 1-3 (all-pairs CVD/normal-vision pass); color follows the dataset.
COLOR = {"geolife": "#2a78d6", "porto": "#eb6834", "tdrive": "#1baf7a"}
MARK = {"geolife": "o", "porto": "s", "tdrive": "^"}
NAME = {"geolife": "GeoLife", "porto": "Porto", "tdrive": "T-Drive"}
INK, MUTED, GRID = "#1f1f1e", "#6b6a63", "#e4e3dd"

plt.rcParams.update({
    "font.family": "STIXGeneral", "mathtext.fontset": "stix", "font.size": 7.5,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "axes.linewidth": 0.6,
    "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelcolor": INK, "ytick.labelcolor": INK,
    "xtick.major.width": 0.6, "ytick.major.width": 0.6, "xtick.major.size": 2.5, "ytick.major.size": 2.5,
    "axes.spines.top": False, "axes.spines.right": False,
    "legend.frameon": False, "legend.fontsize": 7, "pdf.fonttype": 42, "ps.fonttype": 42,
})
LINE = dict(linewidth=1.3, markersize=4.2, markeredgecolor="white", markeredgewidth=0.6)


def grid(ax):
    ax.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


def ref_line(ax, y, text, x_text, va="bottom"):
    ax.axhline(y, color=MUTED, linewidth=0.7, linestyle=(0, (2, 2)), zorder=1)
    ax.text(x_text, y, text, color=MUTED, fontsize=6.5, va=va, ha="left")


# ---------------------------------------------------------------- Fig. 2 (C1)
rows = list(csv.DictReader(open(RES / "n1_fair_summary.csv")))
fig, (top, bot) = plt.subplots(2, 1, figsize=(3.5, 2.75), sharex=True,
                               gridspec_kw={"height_ratios": [1, 1], "hspace": 0.12})
for ds in ("geolife", "porto", "tdrive"):
    rs = sorted((r for r in rows if r["dataset"] == ds), key=lambda r: int(r["bucket_s"]))
    w = [int(r["bucket_s"]) for r in rs]
    err = [100 * float(r["err_any"]) for r in rs]
    cost = [float(r["ratio_e2e"]) for r in rs]
    top.plot(w, err, color=COLOR[ds], marker=MARK[ds], label=NAME[ds], **LINE)
    bot.plot(w, cost, color=COLOR[ds], marker=MARK[ds], **LINE)
    top.text(w[-1] * 1.08, err[-1], NAME[ds], color=INK, fontsize=6.5, va="center")
for ax in (top, bot):
    ax.set_xscale("log")
    grid(ax)
top.set_yscale("log")
top.yaxis.set_major_locator(FixedLocator([0.5, 1, 2, 5, 10, 20, 50]))
top.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
top.yaxis.set_minor_locator(NullLocator())
top.set_ylabel("B3 error (%)")
ref_line(top, 1, "1% error", 330, va="top")
bot.set_yscale("log")
bot.yaxis.set_major_locator(FixedLocator([1, 2, 4, 10]))
bot.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}$\\times$"))
bot.yaxis.set_minor_locator(NullLocator())
bot.set_ylabel("cost, B3 / ours")
ref_line(bot, 1, "equal cost", 5.2, va="top")
bot.set_xlabel("bucket width $w$ (s)")
bot.xaxis.set_major_locator(FixedLocator([5, 10, 30, 60, 120, 300, 600]))
bot.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
bot.xaxis.set_minor_locator(NullLocator())
bot.set_xlim(4.3, 1150)
top.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, handlelength=2.2, columnspacing=1.2)
fig.savefig(OUT / "fig_c1.pdf", bbox_inches="tight", pad_inches=0.02)
plt.close(fig)

# ---------------------------------------------------------------- Fig. 3 (C3)
charge = list(csv.DictReader(open(RES / "n5_bounds_charging.csv")))
users = list(csv.DictReader(open(RES / "n5_bounds_users.csv")))
device = list(csv.DictReader(open(RES / "n5_bounds_users_device.csv")))
fig, (a, b) = plt.subplots(1, 2, figsize=(3.5, 1.85), gridspec_kw={"wspace": 0.42})

for ds in ("porto", "geolife"):
    for rule, style, q in (("all", "-", "300"), ("yes_only", (0, (3, 1.6)), "100")):
        rs = sorted((r for r in charge if r["scope"] == ds and r["charge"] == rule
                     and r["attacker"] == "adaptive" and r["max_queries"] == q),
                    key=lambda r: int(r["budget"]))
        a.plot([int(r["budget"]) for r in rs], [float(r["minent_bits"]) for r in rs],
               color=COLOR[ds], marker=MARK[ds], linestyle=style, **LINE)
a.plot([1, 8], [1, 8], color=MUTED, linewidth=0.7, linestyle=(0, (1, 1.5)), zorder=1)
a.text(3.9, 5.6, "bound $B$", color=MUTED, fontsize=6.5, rotation=33)
ref_line(a, 10.97, "prior 10.97", 1.0, va="bottom")
a.set_xlabel("budget $B$")
a.set_ylabel("min-entropy leakage (bits)")
a.set_xticks([1, 2, 4, 6, 8])
a.set_ylim(0, 12.5)
a.set_yticks([0, 2, 4, 6, 8, 10, 12])
a.set_title("(a) charging rule", fontsize=7.5, color=INK, pad=3)
grid(a)

ks = [1, 2, 4, 8]
for ds in ("porto", "geolife"):
    for rows_, key, style in ((users, "budget", "-"), (device, "budget", (0, (3, 1.6)))):
        rs = {int(r["traces"]): r for r in rows_ if r["scope"] == ds and r[key] == "4"}
        b.plot(ks, [100 * float(rs[k]["top1_identified"]) for k in ks],
               color=COLOR[ds], marker=MARK[ds], linestyle=style, **LINE)
b.set_xscale("log", base=2)
b.set_xticks(ks)
b.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
b.xaxis.set_minor_locator(NullLocator())
b.set_xlabel("trips $K$ of one person")
b.set_ylabel("persons identified (%)")
b.set_ylim(0, 85)
b.set_title("(b) $B=4$: per trace vs. per device", fontsize=7.5, color=INK, pad=3)
grid(b)

from matplotlib.lines import Line2D
handles = [Line2D([], [], color=COLOR["porto"], marker=MARK["porto"], **LINE),
           Line2D([], [], color=COLOR["geolife"], marker=MARK["geolife"], **LINE),
           Line2D([], [], color=INK, linewidth=1.3),
           Line2D([], [], color=INK, linewidth=1.3, linestyle=(0, (3, 1.6)))]
labels = ["Porto", "GeoLife", "(a) every answer / (b) per trace", "(a) only “yes” / (b) per device"]
fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, 0.98), ncol=2,
           handlelength=2.4, columnspacing=1.0, fontsize=6.6)
fig.savefig(OUT / "fig_c3.pdf", bbox_inches="tight", pad_inches=0.02)
plt.close(fig)
print("wrote fig_c1.pdf and fig_c3.pdf")
