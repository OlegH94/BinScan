"""Regola sprintf con controllo della dimensione del buffer di destinazione.
Legge il decompilato e i finding YARA esistenti e riclassifica i finding di BOF_Sprintf_No_Bound.
Uso: python prototipo_sprintf_bound.py <decompiled.c> <findings_yara.json>"""
import json,re,collections,sys
src=open(sys.argv[1],encoding='utf-8',errors='replace').read()
find=[x for x in json.load(open(sys.argv[2],encoding='utf-8')) if x['rule']=='BOF_Sprintf_No_Bound']

# --- funzioni: divide sulle graffe di chiusura in prima colonna
funcs={}
for blk in re.split(r'\n}\n',src):
    m=re.search(r'\n(?:[\w\*\s]+?[\s\*])(\w+)\s*\n?\s*\(([^;{]*)\)\s*\n*\{',blk)
    if m: funcs.setdefault(m.group(1),blk)

ARR=re.compile(r'\b(?:char|undefined1|undefined|byte|uchar)\s+(\w+)\s*\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]\s*;')
ALIAS=re.compile(r'\b(\w+)\s*=\s*(\w+)\s*;')
SPEC=re.compile(r'%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|z|j|t)?([diouxXcsp%])')

def split_args(s):
    out=[];d=0;cur='';q=False;i=0
    while i<len(s):
        c=s[i]
        if q:
            cur+=c
            if c=='\\': cur+=s[i+1]; i+=1
            elif c=='"': q=False
        elif c=='"': q=True; cur+=c
        elif c in '([': d+=1; cur+=c
        elif c in ')]': d-=1; cur+=c
        elif c==',' and d==0: out.append(cur.strip()); cur=''
        else: cur+=c
        i+=1
    if cur.strip(): out.append(cur.strip())
    return out

def fmt_bound(fmt,args):
    """lunghezza massima scritta (senza terminatore) oppure None se non limitata"""
    lit=SPEC.sub('',fmt.replace('%%','%'))  # approssimazione per i letterali
    n=len(bytes(fmt,'utf-8').decode('unicode_escape',errors='ignore'))-sum(len(m.group(0)) for m in SPEC.finditer(fmt))
    k=0
    for m in SPEC.finditer(fmt):
        fl,w,p,ln,cv=m.groups()
        if cv=='%': n+=1; continue
        arg=args[k] if k<len(args) else None; k+=1
        if w=='*' or p=='*': return None
        if cv=='s':
            if p: b=int(p)
            elif arg and arg.startswith('"'): b=len(arg)-2
            else: return None
        elif cv=='c': b=1
        elif cv=='p': b=18
        else:
            big=ln in('l','ll','z','j','t')
            b={'d':20 if big else 11,'i':20 if big else 11,'u':20 if big else 10,'o':22 if big else 11,'x':16 if big else 8,'X':16 if big else 8}[cv]
            if '#' in fl: b+=2
            if p: b=max(b,int(p))
        if w: b=max(b,int(w))
        n+=b
    return n

res=collections.Counter(); rows=[]
for x in find:
    body=funcs.get(x['function'],'')
    sizes={m.group(1):int(m.group(2),0) for m in ARR.finditer(body)}
    alias={}
    for _ in range(2):
        for a,b in ALIAS.findall(body):
            if b in sizes and a not in sizes: alias[a]=b
            elif b in alias and a not in sizes: alias[a]=alias[b]
    line=x['matched_line']
    m=re.search(r'sprintf\s*\((.*)\)\s*;?\s*$',line)
    args=split_args(m.group(1)) if m else []
    dest=args[0] if args else ''
    dname=re.sub(r'^\(char \*\)','',dest).strip()
    size=sizes.get(dname) or sizes.get(alias.get(dname,''))
    fmt=args[1] if len(args)>1 else ''
    bound=fmt_bound(fmt[1:-1],args[2:]) if fmt.startswith('"') else None
    rest=args[2:]
    costanti=bool(rest) and all(re.fullmatch(r'&DAT_[0-9a-fA-F]+|"[^"]*"',r.strip()) for r in rest)
    if bound is None and fmt.startswith('"') and costanti: stato='solo argomenti costanti'
    elif bound is None: stato='scrittura NON limitata'
    elif size is not None and bound+1>size: stato='scrittura limitata ma troppo grande'
    else: stato='scrittura limitata'
    cls=('buffer noto' if size is not None else 'destinazione ignota')+', '+stato
    res[cls]+=1; rows.append((cls,x['function'],size,bound,line.strip()))
for k,v in sorted(res.items()): print(f'{v:4d}  {k}')
print('totale',sum(res.values()))
print('\n-- buffer noto, scrittura NON limitata (candidati ad alta confidenza):')
for r in rows:
    if r[0]=='buffer noto, scrittura NON limitata': print('  ',r[1],r[2],r[4])
