from pathlib import Path
import json,shutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
R=Path(__file__).resolve().parent;V=R
d=json.loads((R/'comparison.json').read_text());a=d['ordinary_two_sided_udt_capacity_scenario']
font=FontProperties(fname='/usr/share/fonts/wqy-zenhei-fonts/wqy-zenhei.ttc')
plt.rcParams.update({'font.family':font.get_name(),'svg.fonttype':'path','axes.spines.top':False,'axes.spines.right':False,'axes.spines.left':False,'axes.spines.bottom':False,'figure.facecolor':'#faf9fc','axes.facecolor':'#faf9fc','text.color':'#25233c','axes.labelcolor':'#514b66','xtick.color':'#514b66','ytick.color':'#514b66','font.size':11})
fig,ax=plt.subplots(figsize=(11.5,6.7));fig.subplots_adjust(left=.1,right=.90,top=.78,bottom=.27)
x=[r['udt_count'] for r in a];m=[r['morph_geometry_ckb'] for r in a];f=[r['fiber_without_fee_buffer_ckb'] for r in a];b=[r['fiber_default_reserve_ckb'] for r in a]
ax.plot(x,m,color='#6953d6',linewidth=2.8,marker='o',markersize=6,label='Morph：一条多资产通道')
ax.plot(x,f,color='#3c83c5',linewidth=2.8,marker='o',markersize=6,label='Fiber：N 条单资产通道，去掉 fee 缓冲')
ax.plot(x,b,color='#9bb5ca',linewidth=1.7,linestyle='--',label='Fiber：另含默认每资产 2 CKB fee 缓冲')
ax.set_xticks(x);ax.set_xlim(.8,8.8);ax.set_ylim(0,3250);ax.set_xlabel('UDT 种数（双方每种资产均有非零 token 余额）',labelpad=12);ax.set_ylabel('退出几何需要的 CKB 容量',labelpad=12);ax.grid(axis='y',color='#e7e3ee',linewidth=.8);ax.set_axisbelow(True);ax.tick_params(length=0,pad=9)
ax.annotate('2,864 CKB',xy=(8,2864),xytext=(8.1,3030),color='#2f6da6',fontsize=10)
ax.annotate('2,736 CKB',xy=(8,2736),xytext=(8.1,2580),color='#6953d6',fontsize=10)
ax.annotate('第 7 种资产起出现交叉',xy=(7,2452),xytext=(4.2,2980),fontsize=11,color='#514b66',arrowprops={'arrowstyle':'-','color':'#aaa0bf','linewidth':1})
fig.text(.10,.94,'容量本金：单资产更轻，多资产共享 State 才有摊销',fontproperties=font,fontsize=18,color='#242039')
fig.text(.10,.89,f'2026-11-12 上海价格快照  ·  1 CKB = ${d["price_usd_per_ckb"]}  ·  资金可回收，不是手续费',fontproperties=font,fontsize=10,color='#6d657d')
ax.legend(loc='upper left',frameon=False,fontsize=10)
fig.text(.10,.10,'同口径、不含 fee 缓冲：8 UDT 的 Morph 比 Fiber 少约 4.47% 容量。',fontproperties=font,fontsize=11,color='#514b66')
fig.text(.10,.055,'假设提现 lock args=20、Type args=32、token data=16；不含支付本金、条件额外输出、Factory 地板和运营缓冲。',fontproperties=font,fontsize=9,color='#7a7288')
for ext in ['svg','png']:
 p=R/('capacity-comparison.'+ext);fig.savefig(p,dpi=165)
 if ext == 'svg':
  p.write_text('\n'.join(line.rstrip() for line in p.read_text().splitlines())+'\n')
 if V != R:
  shutil.copy(p,V/p.name)
