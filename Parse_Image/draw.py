import drawsvg as draw
import bincopy
import sys
import numpy

colors = {0:'#ffffff',1:'#aaaaff',3:'#00ff00'}
desc = {0:'No data in file',1:'Entire page is 0xFF',3:'Normal data'}
fontsize = 16
cellx = 30
celly = 25

pages = numpy.zeros(64,dtype=int)
f = bincopy.BinFile(sys.argv[1])
for c in f.segments.chunks() :
    page = c.address >> 13
    cleared = 0
    for b in c.data :
        cleared |= 0xff != b
    pages[page] |= 1 | cleared << 1
print(pages)

d = draw.Drawing(600,600, origin=(-120,-32),font_family='Courier')


for i in range(2) :
    x = 4*cellx*i
    d.append(draw.Line(x,0,x,-fontsize>>1,stroke='black'))
    d.append(draw.Text('+0x%04x'%(0x8000*i),
                       fontsize,
                       x,
                       -fontsize>>1,
                       fill='black'))
for row in range(8) :
    d.append(draw.Text('0x%08x'%(0x10000*row),
                       fontsize,
                       -3,
                       celly*row+(celly>>1)+(fontsize>>1),
                       text_anchor='end', fill='black'))
    for column in range(8) :
        page = 8*row+column
        color = colors[pages[page]]
        x = cellx*column
        y = celly*row
        r = draw.Rectangle(x,y,cellx,celly,fill=color,stroke='black')
        d.append(r)

d.append(draw.Text('Legend:',
                   fontsize,
                   -3,
                   celly*8+(celly>>1)+(fontsize>>1),
                   text_anchor='end', fill='black'))
values = [0,1,3]
for index in range(3) :
    color = colors[values[index]]
    x = 0
    y = celly*(8+index) + ((celly*index)>>1) + ((3*celly)>>2)
    r = draw.Rectangle(x,y,cellx,celly,fill=color,stroke='black')
    print('y: %d'%(y))
    d.append(r)
    d.append(draw.Text(desc[values[index]],
                       fontsize,
                       cellx+3,
                       y+(celly>>1)+(fontsize>>1),
                       text_anchor='start', fill='black'))


d.save_svg('example.svg')
#d.save_png('example.png')
