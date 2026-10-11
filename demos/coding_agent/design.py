"""A shared, offline presentation for fixture and learned-model receipts."""
import html
import re
from html.parser import HTMLParser


STYLES = '''<style id="report-design">
:root{color-scheme:light;--ink:#17211e;--muted:#64716b;--line:#dde3df;--soft:#f5f7f5;--accent:#177b63;--before:#9ca7a1}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:78px}
body{margin:0;background:#fff;color:var(--ink);font:15px/1.65 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-underline-offset:4px;text-decoration-thickness:1px}a:hover{color:var(--ink)}
header,main{max-width:1080px;margin:0 auto;padding:0 36px}header{padding-top:26px}
.masthead{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:18px;gap:20px}
.wordmark{font-size:16px;font-weight:650;letter-spacing:-.025em}.report-label,.section-label{font-size:11px;font-weight:600;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
h1{font-size:clamp(32px,4.5vw,48px);line-height:1.1;font-weight:600;letter-spacing:-.045em;margin:36px 0 14px}
header .lede{font-size:17px;color:var(--muted);margin:0 0 16px;max-width:720px}.context{font-size:12px;color:var(--muted);margin:0 0 30px}
nav{display:flex;gap:24px;overflow-x:auto;white-space:nowrap;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:13px 0;font-size:13px}
nav a{color:var(--muted);text-decoration:none}nav a:hover,nav a:focus{color:var(--accent)}
main{padding-bottom:48px}section{padding:38px 0;border-bottom:1px solid var(--line);scroll-margin-top:24px}
h2{font-size:25px;line-height:1.25;letter-spacing:-.025em;font-weight:600;margin:0 0 18px}h3{font-size:16px;line-height:1.4;font-weight:600;margin:25px 0 9px}
p{margin:12px 0;max-width:900px}b,strong{font-weight:600}.muted,small,figcaption{color:var(--muted)}small{font-size:12px}
.note{font-size:13px;background:var(--soft);border-left:2px solid #a9b9af;padding:13px 16px;margin:22px 0}
.caption{font-size:12px;color:var(--muted);margin:12px 0 22px;max-width:none}
.explanations{display:grid;grid-template-columns:1fr 1fr;gap:32px;margin-top:22px}.explanations h3{margin-top:0}.explanations p{font-size:14px;margin:8px 0}
figure{margin:24px 0}img,svg{display:block;max-width:100%;height:auto}svg,figure img{width:100%}figcaption{font-size:12px;margin-top:12px}
.recovery-chart{margin:28px 0 0;--label:260px;--value:110px;font-variant-numeric:tabular-nums}
.chart-row{display:grid;grid-template-columns:var(--label) minmax(0,1fr) var(--value);align-items:center;gap:20px;min-height:55px}
.chart-row.pair-end{margin-bottom:18px}.chart-label{font-size:13px}.chart-value{text-align:right;font-weight:600;font-size:16px;white-space:nowrap}.chart-value small{font-size:11px;margin-left:5px;font-weight:400}
.bar-track{position:relative;height:26px;background:#f5f7f5;border-radius:2px}.bar-track:after{content:"";position:absolute;left:50%;top:-8px;bottom:-8px;border-left:1px dashed #a6b1aa}
.bar-fill{position:absolute;height:100%;width:var(--rate);background:var(--before);border-radius:2px}.after .bar-fill{background:var(--accent)}
.whisker{position:absolute;z-index:1;left:var(--low);width:calc(var(--high) - var(--low));height:12px;top:7px;border-left:1.5px solid #273f33;border-right:1.5px solid #273f33}.whisker:after{content:"";position:absolute;top:5px;left:0;right:0;border-top:1.5px solid #273f33}
.chart-scale{margin:6px calc(var(--value) + 20px) 0 calc(var(--label) + 20px);display:flex;justify-content:space-between;font-size:11px;color:var(--muted)}
.grid,.facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:28px;margin:22px 0}.stat{padding:16px 0;border-top:1px solid var(--line);min-width:0}.stat span{display:block;font-size:12px;color:var(--muted)}.stat strong{display:block;font-size:30px;font-weight:550;letter-spacing:-.035em;font-variant-numeric:tabular-nums;line-height:1.4}.stat p{font-size:12px;margin:8px 0}
.facts{gap:24px}.facts dt{font-size:12px;color:var(--muted)}.facts dd{font-size:27px;font-weight:550;letter-spacing:-.03em;margin:3px 0;font-variant-numeric:tabular-nums}
.scroll{max-width:100%;overflow:auto;margin:20px 0}table{border-collapse:collapse;width:100%;font-size:12px;line-height:1.55;font-variant-numeric:tabular-nums}
td,th{padding:13px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:11px;font-weight:600;color:var(--muted);background:var(--soft)}td:first-child,th:first-child{padding-left:12px}td code{font-size:11px;overflow-wrap:anywhere}tr[data-row]{cursor:pointer}tr[data-row]:hover{background:var(--soft)}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85em}pre{border:1px solid var(--line);background:var(--soft);padding:18px;overflow:auto;max-height:420px;color:#344a3e;font-size:12px;line-height:1.6;border-radius:3px}
input{font:inherit;font-size:13px;padding:10px 12px;border:1px solid #c7d0ca;background:#fff;border-radius:3px;width:min(100%,420px)}button{font:inherit;font-size:12px;background:#fff;color:var(--ink);border:1px solid #c7d0ca;border-radius:3px;padding:8px 13px;cursor:pointer}button:hover{background:var(--soft)}
button:focus-visible,input:focus-visible,a:focus-visible,summary:focus-visible,tr:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
details{margin:18px 0;border:1px solid var(--line);border-radius:3px;padding:0 16px}summary{cursor:pointer;font-size:13px;font-weight:500;padding:13px 0}details[open]>summary{border-bottom:1px solid var(--line);margin-bottom:16px}details section{border:0;padding:4px 0 16px}details details{border:0;border-top:1px solid var(--line);border-radius:0;padding:0}details h2{font-size:19px}.evidence-list>details{margin:10px 0}.evidence-list footer{padding:6px 0 18px}
footer{font-size:11px;line-height:1.9;color:var(--muted);overflow-wrap:anywhere;padding:28px 0}.ok{color:var(--accent)}.bad{color:#a13b32}
.badge{display:inline-block;font-size:12px;color:var(--muted);margin-right:16px}.eyebrow{font-size:11px;color:var(--muted)}
@media(max-width:700px){header,main{padding-left:22px;padding-right:22px}.masthead{gap:12px}.report-label{font-size:9px}nav{flex-wrap:wrap;gap:8px 20px;overflow:visible;white-space:normal}.context{line-height:1.8}h1{margin-top:28px}section{padding:28px 0}h2{font-size:22px}.explanations,.grid{grid-template-columns:1fr;gap:18px}.chart-row{grid-template-columns:1fr auto;gap:8px;min-height:76px}.chart-label{grid-column:1;grid-row:1}.chart-value{grid-column:2;grid-row:1;font-size:14px}.bar-track{grid-column:1 / -1;grid-row:2;height:22px;margin-bottom:12px}.whisker{top:5px}.chart-scale{margin:0}.chart-row.pair-end{margin-bottom:12px}.facts{gap:12px}.facts dd{font-size:21px}.facts dt{font-size:11px}.stat{padding:12px 0}.explanations p{font-size:14px}td,th{padding:10px 9px}.note{padding:11px 13px}details{padding:0 12px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{header,main{max-width:none;padding:0}nav,input,button{display:none}section{break-inside:avoid}details{border:0}h1{font-size:30px}.explanations{gap:20px}}
</style>'''


class _MainChildren(HTMLParser):
    """Keep each original main child verbatim, including JSON-free nested HTML."""
    void = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, document):
        super().__init__(convert_charrefs=False)
        self.document = document
        self.lines = [0]
        for match in re.finditer("\n", document):
            self.lines.append(match.end())
        self.in_main = False
        self.depth = 0
        self.children = []

    def source_position(self):
        line, column = self.getpos()
        return self.lines[line-1] + column

    def handle_starttag(self, tag, attrs):
        if tag == "main":
            self.in_main = True
            return
        if not self.in_main:
            return
        if self.depth == 0:
            self.start = self.source_position()
            self.identity = dict(attrs).get("id", tag)
        if tag not in self.void:
            self.depth += 1

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main = False
            return
        if not self.in_main or tag in self.void:
            return
        self.depth -= 1
        if self.depth == 0:
            end = self.document.index(">", self.source_position()) + 1
            self.children.append((self.identity, self.document[self.start:end]))


def _disclosure(content, title):
    return f'<details><summary>{html.escape(title)}</summary>{content}</details>'


def apply_design(document):
    """Restyle and order the receipt without touching its embedded evidence."""
    document = re.sub(r'<style(?: [^>]*)?>.*?</style>', lambda _: STYLES, document, count=1, flags=re.S)
    start, end = document.index('<header>'), document.index('</header>') + len('</header>')
    original_header = document[start:end]
    badges = re.findall(r'<span class="badge">(.*?)</span>', original_header, re.S)
    backend = html.unescape(badges[0]) if badges else "Coding evaluation"
    if "Qwen" in backend:
        backend = "Qwen3-0.6B · local model"
    context = html.escape(backend) + ' · Synthetic canary · Trusted custodian · Software sandbox'
    setup = re.sub(r'<nav>.*?</nav>|<h1>.*?</h1>|<div class="eyebrow">.*?</div>', '', original_header, flags=re.S).removeprefix('<header>').removesuffix('</header>')
    setup = setup.replace('style="color:#b8efe7"', '')
    links = [('recovery', 'Results'), ('filings', 'Repeated filings'), ('budget', 'Privacy cost'), ('utility', 'Utility'), ('verification', 'Integrity'), ('evidence', 'Evidence')]
    nav = ''.join(f'<a href="#{identity}">{label}</a>' for identity, label in links if identity == 'evidence' or f'id="{identity}"' in document)
    header = f'<header><div class="masthead"><span class="wordmark">A Right to Test</span><span class="report-label">Coding evaluation / executed evidence</span></div><h1>Hidden test leakage</h1><p class="lede">What a malicious evaluator can recover through published results.</p><p class="context">{context}</p><nav aria-label="Report sections">{nav}</nav></header>'
    document = document[:start] + header + document[end:]
    parser = _MainChildren(document)
    parser.feed(document)
    children = list(parser.children)
    lead = ['recovery', 'filings', 'budget', 'utility', 'verification']
    main = ''
    for identity in lead:
        for index, (key, content) in enumerate(children):
            if key == identity:
                main += content
                children.pop(index)
                break
    titles = {'retained-recovery': 'Original measurements', 'patches': 'Model-generated patches', 'ledger': 'Public records', 'passport': 'Passport export', 'budget-retained': 'Historical counter receipt', 'footer': 'Protocol and execution provenance', 'details': 'Historical counter receipt'}
    evidence = ''.join(_disclosure(content, titles.get(identity, identity.replace('-', ' ').capitalize())) for identity, content in children)
    main += '<section id="evidence"><h2>Evidence</h2><p class="muted">Original measurements, generated patches and public records. Each receipt remains tied to its declared cohort.</p><div class="evidence-list">' + _disclosure(setup, 'Evaluation setup and retained reports') + evidence + '</div></section>'
    start, end = document.index('<main>'), document.index('</main>') + len('</main>')
    document = document[:start] + '<main>' + main + '</main>' + document[end:]
    # Opening an evidence deep link also opens its containing disclosures.
    script = '''<script id="evidence-navigation">function revealEvidence(){const id=decodeURIComponent(location.hash.slice(1));let target=document.getElementById(id);if(!target)return;for(let parent=target.parentElement;parent;parent=parent.parentElement){if(parent.tagName==='DETAILS')parent.open=true}if(id)target.scrollIntoView({block:'start'})}window.addEventListener('hashchange',revealEvidence);if(location.hash)revealEvidence();</script>'''
    return document.replace('</html>', script+'</html>')
