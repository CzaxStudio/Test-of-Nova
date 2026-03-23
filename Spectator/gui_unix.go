//go:build (linux || darwin) && gui
// +build linux darwin
// +build gui

package main

// ── Spectator GUI — Linux / macOS (WebKit) ────────────────────────────────────
// Uses github.com/webview/webview_go which wraps:
//   Linux  → WebKitGTK (pre-installed on Ubuntu/Debian/Fedora)
//   macOS  → WKWebView (built into macOS, no install needed)
//
// Build on Linux:  go build -tags gui -o spectator .
// Build on macOS:  go build -tags gui -o spectator .
// Cross-compile:   not supported for CGO targets; build natively on each OS.

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	webview "github.com/webview/webview_go"
)

type GUIWidget struct {
	ID      string
	Kind    string
	Text    string
	Opts    map[string]interface{}
	EventID string
}

type GUIState struct {
	wv        webview.WebView
	widgets   []GUIWidget
	events    map[string]func()
	values    map[string]string
	outputs   map[string][]string
	tables    map[string][][]string
	mu        sync.Mutex
	ready     bool
	safeEval  func(string)
	confirm   chan bool
	title     string
	width     int
	height    int
	bg        string
	accent    string
	textClr   string
	font      string
	radius    string
	padding   string
	resizable bool
	scrollbar bool
	customCSS string
}

var gui = &GUIState{
	events:    make(map[string]func()),
	values:    make(map[string]string),
	outputs:   make(map[string][]string),
	tables:    make(map[string][][]string),
	confirm:   make(chan bool, 1),
	title:     "MyApp",
	width:     900,
	height:    600,
	bg:        "#0a0f1a",
	accent:    "#38bdf8",
	textClr:   "#cbd5e1",
	font:      "system-ui",
	radius:    "8",
	padding:   "24",
	resizable: true,
	scrollbar: true,
}

func gS(o map[string]interface{}, k, d string) string {
	if o == nil { return d }
	if v, ok := o[k]; ok { return toStr(v) }
	return d
}
func gF(o map[string]interface{}, k string, d float64) float64 {
	if o == nil { return d }
	if v, ok := o[k]; ok { return toFloat(v) }
	return d
}
func gB(o map[string]interface{}, k string, d bool) bool {
	if o == nil { return d }
	if v, ok := o[k]; ok { return isTruthy(v) }
	return d
}

// buildPage, renderWidget, embedImg, he — identical to gui_windows.go
// (shared logic; kept here to avoid CGO cross-file issues)

func buildPage() string {
	var body strings.Builder
	for _, w := range gui.widgets {
		body.WriteString(renderWidget(w))
	}
	sbCSS := ""
	if !gui.scrollbar { sbCSS = "::-webkit-scrollbar{display:none}" }
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>%s</title><style>
:root{--bg:%s;--ac:%s;--tx:%s;--fn:'%s',system-ui,sans-serif;--r:%spx;--p:%spx;
--sf:rgba(255,255,255,.05);--bd:rgba(255,255,255,.1);--mt:rgba(255,255,255,.35);}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{background:var(--bg);color:var(--tx);font-family:var(--fn);font-size:14px;line-height:1.6;height:100%%;}
.page{padding:var(--p);height:100%%;overflow-y:auto;}
%s%s
.g-label{margin:3px 0;}
.g-input{width:100%%;background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  padding:9px 13px;color:var(--tx);font-family:var(--fn);font-size:14px;outline:none;margin:4px 0;
  transition:border-color .15s,box-shadow .15s;}
.g-input:focus{border-color:var(--ac);box-shadow:0 0 0 3px color-mix(in srgb,var(--ac) 20%%,transparent);}
.g-input::placeholder{color:var(--mt);}.g-input:disabled{opacity:.4;cursor:not-allowed;}
textarea.g-input{resize:vertical;}
.g-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:9px 20px;border-radius:var(--r);border:none;cursor:pointer;
  font-family:var(--fn);font-size:14px;font-weight:600;margin:4px 4px 4px 0;
  transition:filter .12s,transform .1s,box-shadow .1s;letter-spacing:.02em;}
.g-btn:hover:not(:disabled){filter:brightness(1.15);transform:translateY(-1px);box-shadow:0 4px 14px rgba(0,0,0,.35);}
.g-btn:active:not(:disabled){transform:translateY(0);filter:brightness(.93);}
.g-btn:disabled{opacity:.4;cursor:not-allowed;}
.g-btn-sm{padding:6px 14px;font-size:12px;}.g-btn-lg{padding:12px 28px;font-size:16px;}
.g-btn-outline{background:transparent!important;border:1.5px solid var(--bc,var(--ac));color:var(--bc,var(--ac))!important;}
.g-btn-outline:hover:not(:disabled){background:color-mix(in srgb,var(--bc,var(--ac)) 12%%,transparent)!important;}
.g-link{background:none;border:none;cursor:pointer;font-family:var(--fn);font-size:14px;text-decoration:underline;padding:0;margin:4px 0;}
.g-output{width:100%%;background:rgba(0,0,0,.35);border:1px solid var(--bd);border-radius:var(--r);
  padding:12px;font-family:'Cascadia Code','Consolas',monospace;font-size:13px;
  color:#94a3b8;overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin:4px 0;}
.g-prog-wrap{margin:6px 0;}.g-prog-label{font-size:11px;color:var(--mt);margin-bottom:3px;}
.g-prog-track{width:100%%;background:rgba(0,0,0,.3);border-radius:999px;overflow:hidden;}
.g-prog-fill{height:100%%;background:var(--ac);border-radius:999px;transition:width .3s ease;width:0%%;}
.g-spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--bd);
  border-top-color:var(--ac);border-radius:50%%;animation:spin .7s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
.g-check-wrap{display:flex;align-items:center;gap:8px;margin:6px 0;cursor:pointer;user-select:none;}
.g-check-wrap input[type=checkbox]{accent-color:var(--ac);width:16px;height:16px;cursor:pointer;}
.g-toggle-wrap{display:flex;align-items:center;gap:10px;margin:6px 0;cursor:pointer;user-select:none;}
.g-toggle-track{position:relative;width:40px;height:22px;background:var(--bd);border-radius:999px;transition:background .2s;flex-shrink:0;}
.g-toggle-thumb{position:absolute;top:3px;left:3px;width:16px;height:16px;background:#fff;border-radius:50%%;transition:transform .2s;}
.g-toggle-input{position:absolute;opacity:0;width:100%%;height:100%%;cursor:pointer;margin:0;}
.g-toggle-wrap:has(input:checked) .g-toggle-track{background:var(--ac);}
.g-toggle-input:checked+.g-toggle-thumb{transform:translateX(18px);}
.g-radio-wrap{display:flex;align-items:center;gap:8px;margin:4px 0;cursor:pointer;}
.g-radio-wrap input{accent-color:var(--ac);cursor:pointer;}
.g-select{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  padding:9px 13px;color:var(--tx);font-family:var(--fn);font-size:14px;
  outline:none;margin:4px 0;cursor:pointer;transition:border-color .15s;}
.g-select:focus{border-color:var(--ac);}
.g-slider-wrap{margin:6px 0;}.g-slider{width:100%%;accent-color:var(--ac);cursor:pointer;display:block;}
.g-slider-val{font-size:12px;color:var(--mt);margin-top:2px;text-align:right;}
.g-table-wrap{overflow:auto;margin:6px 0;border-radius:var(--r);border:1px solid var(--bd);}
.g-table{width:100%%;border-collapse:collapse;font-size:13px;}
.g-table th{background:var(--sf);padding:9px 14px;text-align:left;font-weight:600;color:var(--ac);border-bottom:1px solid var(--bd);}
.g-table td{padding:8px 14px;border-bottom:1px solid rgba(255,255,255,.05);}
.g-table tr:last-child td{border-bottom:none;}
.g-table-striped tr:nth-child(even) td{background:rgba(255,255,255,.03);}
.g-table tr:hover td{background:rgba(255,255,255,.05);}
.g-divider{border:none;margin:10px 0;}
.g-div-text{display:flex;align-items:center;gap:10px;margin:12px 0;font-size:12px;color:var(--mt);}
.g-div-text::before,.g-div-text::after{content:'';flex:1;border-top:1px solid var(--bd);}
.g-card{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);padding:16px;margin:8px 0;}
.g-card-accent{border-left:3px solid var(--ac);}
.g-card-title{font-weight:700;margin-bottom:10px;font-size:15px;}
.g-badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;margin:2px;letter-spacing:.06em;text-transform:uppercase;}
.g-alert{display:flex;align-items:flex-start;gap:10px;padding:12px 16px;border-radius:var(--r);margin:8px 0;font-size:13px;border-left:4px solid;}
.g-alert-info{background:rgba(59,130,246,.12);border-color:#3b82f6;color:#93c5fd;}
.g-alert-success{background:rgba(34,197,94,.12);border-color:#22c55e;color:#86efac;}
.g-alert-warning{background:rgba(245,158,11,.12);border-color:#f59e0b;color:#fcd34d;}
.g-alert-error{background:rgba(239,68,68,.12);border-color:#ef4444;color:#fca5a5;}
.g-code{background:rgba(0,0,0,.4);border:1px solid var(--bd);border-radius:var(--r);
  padding:14px;font-family:'Cascadia Code','Consolas',monospace;font-size:13px;
  color:#e2e8f0;overflow:auto;white-space:pre;margin:6px 0;}
.g-tabs{display:flex;gap:2px;margin-bottom:0;border-bottom:1px solid var(--bd);}
.g-tab-btn{background:none;border:none;padding:9px 18px;cursor:pointer;font-family:var(--fn);
  font-size:13px;color:var(--mt);border-bottom:2px solid transparent;transition:color .15s,border-color .15s;margin-bottom:-1px;}
.g-tab-btn.active{color:var(--ac);border-bottom-color:var(--ac);}
.g-tab-btn:hover{color:var(--tx);}
.g-tab-panel{display:none;padding-top:14px;}.g-tab-panel.active{display:block;}
.g-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0;}
.g-col{display:flex;flex-direction:column;gap:6px;}
.g-layout{display:flex;height:100%%;gap:0;}
.g-sidebar{width:220px;flex-shrink:0;background:rgba(0,0,0,.25);border-right:1px solid var(--bd);padding:16px 0;overflow-y:auto;}
.g-sb-item{display:flex;align-items:center;gap:10px;padding:10px 20px;cursor:pointer;color:var(--mt);
  font-size:13px;transition:all .15s;border:none;background:none;font-family:var(--fn);width:100%%;text-align:left;}
.g-sb-item:hover{color:var(--tx);background:var(--sf);}
.g-sb-item.active{color:var(--ac);background:color-mix(in srgb,var(--ac) 10%%,transparent);}
.g-sb-icon{font-size:16px;width:20px;text-align:center;}
.g-main{flex:1;overflow-y:auto;padding:var(--p);}
.g-header{padding:16px var(--p);background:var(--sf);border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:16px;margin:-1px calc(-1 * var(--p)) 20px;}
.g-header-title{font-weight:700;font-size:18px;}.g-header-sub{font-size:12px;color:var(--mt);margin-top:1px;}
.g-header-logo{height:36px;border-radius:6px;}
.g-footer{padding:12px var(--p);background:var(--sf);border-top:1px solid var(--bd);
  font-size:12px;color:var(--mt);text-align:center;margin:20px calc(-1 * var(--p)) calc(-1 * var(--p));}
.g-image{display:block;margin:6px 0;}
.hidden{display:none!important;}
</style></head><body><div class="page">
%s
</div><script>
function _sSetOutput(id,val){const e=document.getElementById('out_'+id);if(e){e.textContent=val;e.scrollTop=e.scrollHeight;}}
function _sSetProgress(id,pct){const e=document.getElementById('prog_'+id);if(e)e.style.width=(pct*100)+'%%';}
function _sSetValue(id,val){const e=document.getElementById('inp_'+id)||document.getElementById(id);if(!e)return;if(e.tagName==='INPUT'||e.tagName==='TEXTAREA'||e.tagName==='SELECT')e.value=val;else e.textContent=val;}
function _sShow(id){const e=document.getElementById('w_'+id)||document.getElementById(id);if(e)e.classList.remove('hidden');}
function _sHide(id){const e=document.getElementById('w_'+id)||document.getElementById(id);if(e)e.classList.add('hidden');}
function _sEnable(id){['inp_','btn_'].forEach(p=>{const e=document.getElementById(p+id);if(e)e.disabled=false;});}
function _sDisable(id){['inp_','btn_'].forEach(p=>{const e=document.getElementById(p+id);if(e)e.disabled=true;});}
function _sCSS(sel,prop,val){document.querySelectorAll(sel).forEach(e=>e.style[prop]=val);}
function _sClass(id,cls,add){const e=document.getElementById('w_'+id)||document.getElementById(id);if(e){if(add)e.classList.add(cls);else e.classList.remove(cls);}}
function _sFocus(id){const e=document.getElementById('inp_'+id);if(e)e.focus();}
function _sBg(c){document.documentElement.style.setProperty('--bg',c);}
function _sAccent(c){document.documentElement.style.setProperty('--ac',c);}
function _sAlert(msg){alert(msg);}
function _sConfirm(msg){const ok=confirm(msg);try{window._goConfirmResult(ok?'true':'false');}catch(e){}}
function _sAppendRow(id,cells){const tb=document.getElementById('tb_'+id);if(!tb)return;const tr=document.createElement('tr');cells.forEach(c=>{const td=document.createElement('td');td.textContent=c;tr.appendChild(td);});tb.appendChild(tr);}
function _sClearTable(id){const tb=document.getElementById('tb_'+id);if(tb)tb.innerHTML='';}
function _sOpenTab(tid,grp){const g=grp||'default';document.querySelectorAll('.g-tab-btn[data-group="'+g+'"]').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.g-tab-panel[data-group="'+g+'"]').forEach(p=>p.classList.remove('active'));const tb=document.querySelector('.g-tab-btn[data-tab="'+tid+'"]');const tp=document.getElementById('tab_'+tid);if(tb)tb.classList.add('active');if(tp)tp.classList.add('active');}
function _sShowSpin(id){const e=document.getElementById('spin_'+id);if(e)e.classList.remove('hidden');}
function _sHideSpin(id){const e=document.getElementById('spin_'+id);if(e)e.classList.add('hidden');}
function _sSbNav(id){document.querySelectorAll('.g-sb-item').forEach(el=>el.classList.remove('active'));const el=document.getElementById('sb_'+id);if(el)el.classList.add('active');try{window._goTriggerEvent('sidebar:'+id);}catch(e){}}
function _sSlider(id,val,show){try{window._goUpdateValue(id,val);}catch(e){}if(show){const e=document.getElementById('slv_'+id);if(e)e.textContent=val;}}
function _trig(id){try{window._goTriggerEvent(id);}catch(e){}}
function _upd(id,val){try{window._goUpdateValue(id,val);}catch(e){}}
</script></body></html>`,
		gui.title,
		gui.bg, gui.accent, gui.textClr, gui.font, gui.radius, gui.padding,
		sbCSS, gui.customCSS,
		body.String())
}

func renderWidget(w GUIWidget) string {
	o := w.Opts
	if o == nil { o = map[string]interface{}{} }
	switch w.Kind {
	case "label":
		clr:=gS(o,"color","var(--tx)");sz:=gF(o,"size",14)
		sty:=fmt.Sprintf("color:%s;font-size:%.0fpx;text-align:%s;margin:%s;",clr,sz,gS(o,"align","left"),gS(o,"margin","3px 0"))
		if gB(o,"bold",false){sty+="font-weight:700;"}
		if gB(o,"italic",false){sty+="font-style:italic;"}
		id:=gS(o,"id","");idA:="";if id!=""{idA=fmt.Sprintf(` id="lbl_%s"`,id)}
		return fmt.Sprintf(`<div class="g-label"%s style="%s">%s</div>`,idA,sty,he(w.Text))
	case "input":
		ph:=gS(o,"placeholder","");wide:=gS(o,"width","100%%");val:=gS(o,"value","");dis:="";if gB(o,"disabled",false){dis=" disabled"}
		if gB(o,"multiline",false){rows:=int(gF(o,"rows",4));return fmt.Sprintf(`<textarea class="g-input" id="inp_%s" placeholder="%s" rows="%d" style="width:%s"%s oninput="_upd('%s',this.value)">%s</textarea>`,w.ID,he(ph),rows,wide,dis,w.ID,he(val))}
		return fmt.Sprintf(`<input class="g-input" type="text" id="inp_%s" placeholder="%s" value="%s" style="width:%s"%s oninput="_upd('%s',this.value)">`,w.ID,he(ph),he(val),wide,dis,w.ID)
	case "password":
		ph:=gS(o,"placeholder","");return fmt.Sprintf(`<input class="g-input" type="password" id="inp_%s" placeholder="%s" oninput="_upd('%s',this.value)">`,w.ID,he(ph),w.ID)
	case "number":
		ph:=gS(o,"placeholder","0");val:=gS(o,"value","");step:=gS(o,"step","1");mn:="";if v:=gS(o,"min","");v!=""{mn=` min="`+v+`"`};mx:="";if v:=gS(o,"max","");v!=""{mx=` max="`+v+`"`}
		return fmt.Sprintf(`<input class="g-input" type="number" id="inp_%s" placeholder="%s" value="%s" step="%s"%s%s oninput="_upd('%s',this.value)">`,w.ID,he(ph),he(val),step,mn,mx,w.ID)
	case "button":
		clr:=gS(o,"color","var(--ac)");tc:=gS(o,"textColor","#fff");wide:=gS(o,"width","auto");sz:=gS(o,"size","");icon:=gS(o,"icon","");dis:="";if gB(o,"disabled",false){dis=" disabled"}
		szC:="";switch sz{case "sm":szC=" g-btn-sm";case "lg":szC=" g-btn-lg"}
		outC:="";bgS:=fmt.Sprintf("background:%s;color:%s;",clr,tc);if gB(o,"outline",false){outC=" g-btn-outline";bgS=fmt.Sprintf("--bc:%s;",clr)}
		iconH:="";if icon!=""{iconH=fmt.Sprintf(`<span>%s</span>`,icon)}
		return fmt.Sprintf(`<button class="g-btn%s%s" id="btn_%s" style="%swidth:%s"%s onclick="_trig('%s')">%s%s</button>`,szC,outC,w.ID,bgS,wide,dis,w.EventID,iconH,he(w.Text))
	case "iconButton":
		clr:=gS(o,"color","var(--tx)");sz:=gS(o,"size","20px")
		return fmt.Sprintf(`<button style="background:none;border:none;cursor:pointer;font-size:%s;color:%s;padding:6px;border-radius:var(--r);transition:opacity .15s;" onclick="_trig('%s')">%s</button>`,sz,clr,w.EventID,he(w.Text))
	case "link":
		return fmt.Sprintf(`<button class="g-link" style="color:%s" onclick="_trig('%s')">%s</button>`,gS(o,"color","var(--ac)"),w.EventID,he(w.Text))
	case "output":
		h:=gF(o,"height",300);bg:=gS(o,"bg","");clr:=gS(o,"color","");sty:=fmt.Sprintf("height:%.0fpx;",h);if bg!=""{sty+="background:"+bg+";"};if clr!=""{sty+="color:"+clr+";"}
		return fmt.Sprintf(`<div class="g-output" id="out_%s" style="%s"></div>`,w.ID,sty)
	case "progress":
		clr:=gS(o,"color","var(--ac)");bg:=gS(o,"bg","");h:=gF(o,"height",8);lbl:=gS(o,"label","");bgS:="";if bg!=""{bgS="background:"+bg+";"}
		lblH:="";if lbl!=""{lblH=fmt.Sprintf(`<div class="g-prog-label">%s</div>`,he(lbl))}
		return fmt.Sprintf(`<div class="g-prog-wrap">%s<div class="g-prog-track" style="height:%.0fpx;%s"><div class="g-prog-fill" id="prog_%s" style="background:%s;height:100%%"></div></div></div>`,lblH,h,bgS,w.ID,clr)
	case "spinner":
		return fmt.Sprintf(`<div class="g-spinner hidden" id="spin_%s"></div>`,w.ID)
	case "checkbox":
		chkd:="";if gB(o,"checked",false){chkd=" checked"}
		return fmt.Sprintf(`<label class="g-check-wrap" style="color:%s"><input type="checkbox" id="inp_%s"%s onchange="_upd('%s',this.checked?'true':'false')"> %s</label>`,gS(o,"color","var(--tx)"),w.ID,chkd,w.ID,he(w.Text))
	case "toggle":
		chkd:="";if gB(o,"checked",false){chkd=" checked"}
		return fmt.Sprintf(`<div class="g-toggle-wrap"><div class="g-toggle-track"><input type="checkbox" class="g-toggle-input" id="inp_%s"%s onchange="_upd('%s',this.checked?'true':'false')"><div class="g-toggle-thumb"></div></div><span style="color:%s">%s</span></div>`,w.ID,chkd,w.ID,gS(o,"color","var(--tx)"),he(w.Text))
	case "radio":
		nm:=gS(o,"name","radio");val:=gS(o,"value",w.Text);chkd:="";if gB(o,"checked",false){chkd=" checked"}
		return fmt.Sprintf(`<label class="g-radio-wrap"><input type="radio" name="%s" id="inp_%s" value="%s"%s onchange="_upd('%s',this.value)"> %s</label>`,he(nm),w.ID,he(val),chkd,w.ID,he(w.Text))
	case "dropdown":
		wide:=gS(o,"width","100%%");ph:=gS(o,"placeholder","");var sb strings.Builder
		sb.WriteString(fmt.Sprintf(`<select class="g-select" id="inp_%s" style="width:%s" onchange="_upd('%s',this.value)">`,w.ID,wide,w.ID))
		if ph!=""{sb.WriteString(fmt.Sprintf(`<option value="" disabled>%s</option>`,he(ph)))}
		if list,ok:=o["options"].([]interface{});ok{for i,item:=range list{sel:="";if i==0&&ph==""{sel=" selected"};sb.WriteString(fmt.Sprintf(`<option value="%s"%s>%s</option>`,he(toStr(item)),sel,he(toStr(item))));};if len(list)>0&&ph==""{gui.mu.Lock();if gui.values[w.ID]==""{gui.values[w.ID]=toStr(list[0])};gui.mu.Unlock()}}
		sb.WriteString(`</select>`);return sb.String()
	case "slider":
		mn:=gF(o,"min",0);mx:=gF(o,"max",100);step:=gS(o,"step","1");wide:=gS(o,"width","100%%");clr:=gS(o,"color","");show:=gB(o,"showValue",false)
		sty:=fmt.Sprintf("width:%s;",wide);if clr!=""{sty+="accent-color:"+clr+";"}
		sv:="";if show{sv=fmt.Sprintf(`<div class="g-slider-val" id="slv_%s">%.0f</div>`,w.ID,mn)};bv:="false";if show{bv="true"}
		return fmt.Sprintf(`<div class="g-slider-wrap"><input type="range" class="g-slider" id="inp_%s" min="%.0f" max="%.0f" step="%s" value="%.0f" style="%s" oninput="_sSlider('%s',this.value,%s)">%s</div>`,w.ID,mn,mx,step,mn,sty,w.ID,bv,sv)
	case "table":
		h:=gF(o,"height",0);striped:=gB(o,"striped",true);hSty:="";if h>0{hSty=fmt.Sprintf("max-height:%.0fpx;",h)};stpC:="";if striped{stpC=" g-table-striped"}
		var sb strings.Builder;sb.WriteString(fmt.Sprintf(`<div class="g-table-wrap" style="%s"><table class="g-table%s"><thead><tr>`,hSty,stpC))
		if hdrs,ok:=o["headers"].([]interface{});ok{for _,h:=range hdrs{sb.WriteString(fmt.Sprintf(`<th>%s</th>`,he(toStr(h))))}}
		sb.WriteString(fmt.Sprintf(`</tr></thead><tbody id="tb_%s">`,w.ID))
		if rows,ok:=o["rows"].([]interface{});ok{for _,row:=range rows{sb.WriteString(`<tr>`);if cells,ok2:=row.([]interface{});ok2{for _,c:=range cells{sb.WriteString(fmt.Sprintf(`<td>%s</td>`,he(toStr(c))))}};sb.WriteString(`</tr>`)}}
		sb.WriteString(`</tbody></table></div>`);return sb.String()
	case "image":
		wide:=gS(o,"width","auto");high:=gS(o,"height","auto");rad:=gS(o,"radius","0")
		return fmt.Sprintf(`<img class="g-image" src="%s" style="width:%s;height:%s;border-radius:%spx;max-width:100%%;">`,embedImg(w.Text),wide,high,rad)
	case "space":
		return fmt.Sprintf(`<div style="height:%.0fpx"></div>`,gF(o,"height",16))
	case "divider":
		clr:=gS(o,"color","var(--bd)");mg:=gS(o,"margin","10px 0");txt:=gS(o,"text","")
		if txt!=""{return fmt.Sprintf(`<div class="g-div-text" style="margin:%s;color:%s">%s</div>`,mg,clr,he(txt))}
		return fmt.Sprintf(`<hr class="g-divider" style="border-top:1px solid %s;margin:%s">`,clr,mg)
	case "card":
		sty:="";if bg:=gS(o,"bg","");bg!=""{sty+="background:"+bg+";"};if bd:=gS(o,"border","");bd!=""{sty+="border-color:"+bd+";"};if r:=gS(o,"radius","");r!=""{sty+="border-radius:"+r+"px;"};if p:=gS(o,"padding","");p!=""{sty+="padding:"+p+"px;"}
		acC:="";if gB(o,"accent",false){acC=" g-card-accent"};id:=gS(o,"id",fmt.Sprintf("card%d",len(gui.widgets)));title:=gS(o,"title","");titleH:="";if title!=""{titleH=fmt.Sprintf(`<div class="g-card-title">%s</div>`,he(title))}
		return fmt.Sprintf(`<div id="w_%s" class="g-card%s" style="%s">%s`,id,acC,sty,titleH)
	case "cardEnd":
		return `</div>`
	case "badge":
		return fmt.Sprintf(`<span class="g-badge" style="color:%s;background:%s;border-radius:%s">%s</span>`,gS(o,"color","#fff"),gS(o,"bg","var(--ac)"),gS(o,"radius","999px"),he(w.Text))
	case "alert_box":
		kind:=gS(o,"type","info");id:=gS(o,"id","");icons:=map[string]string{"info":"ℹ","success":"✓","warning":"⚠","error":"✕"};icon:=icons[kind];if icon==""{icon="ℹ"}
		idA:="";if id!=""{idA=fmt.Sprintf(` id="w_%s"`,id)}
		return fmt.Sprintf(`<div class="g-alert g-alert-%s"%s><span>%s</span><span>%s</span></div>`,kind,idA,icon,he(w.Text))
	case "code":
		h:=gF(o,"height",0);sty:="";if h>0{sty=fmt.Sprintf("max-height:%.0fpx;overflow-y:auto;",h)};if bg:=gS(o,"bg","");bg!=""{sty+="background:"+bg+";"}
		return fmt.Sprintf(`<pre class="g-code" style="%s">%s</pre>`,sty,he(w.Text))
	case "tabs":
		grp:=gS(o,"group","default");var sb strings.Builder;sb.WriteString(`<div class="g-tabs">`)
		if list,ok:=o["tabs"].([]interface{});ok{for i,t:=range list{act:="";if i==0{act=" active"};tid:=toStr(t);sb.WriteString(fmt.Sprintf(`<button class="g-tab-btn%s" data-tab="%s" data-group="%s" onclick="_sOpenTab('%s','%s')">%s</button>`,act,tid,grp,tid,grp,he(tid)))}}
		sb.WriteString(`</div>`);return sb.String()
	case "tabPanel":
		grp:=gS(o,"group","default");act:="";if gB(o,"active",false){act=" active"}
		return fmt.Sprintf(`<div class="g-tab-panel%s" id="tab_%s" data-group="%s">`,act,w.ID,grp)
	case "tabPanelEnd":
		return `</div>`
	case "rowStart":
		gap:=gS(o,"gap","8px");align:=gS(o,"align","center");just:=gS(o,"justify","flex-start")
		return fmt.Sprintf(`<div class="g-row" style="gap:%s;align-items:%s;justify-content:%s;">`,gap,align,just)
	case "rowEnd":
		return `</div>`
	case "colStart":
		return fmt.Sprintf(`<div class="g-col" style="width:%s;gap:%s;">`,gS(o,"width","auto"),gS(o,"gap","6px"))
	case "colEnd":
		return `</div>`
	case "sidebar":
		var sb strings.Builder;sb.WriteString(`<div class="g-layout"><div class="g-sidebar">`)
		if items,ok:=o["items"].([]interface{});ok{for i,item:=range items{if m,ok2:=item.(map[string]interface{});ok2{id:=toStr(m["id"]);lbl:=toStr(m["label"]);icon:=toStr(m["icon"]);act:="";if i==0{act=" active"};iconH:="";if icon!=""{iconH=fmt.Sprintf(`<span class="g-sb-icon">%s</span>`,icon)};sb.WriteString(fmt.Sprintf(`<button class="g-sb-item%s" id="sb_%s" onclick="_sSbNav('%s')">%s<span>%s</span></button>`,act,id,id,iconH,he(lbl)))}}}
		sb.WriteString(`</div><div class="g-main">`);return sb.String()
	case "sidebarEnd":
		return `</div></div>`
	case "header":
		title:=gS(o,"title",w.Text);sub:=gS(o,"subtitle","");logo:=gS(o,"logo","");clr:=gS(o,"color","var(--tx)");bg:=gS(o,"bg","")
		sty:=fmt.Sprintf("color:%s;",clr);if bg!=""{sty+="background:"+bg+";"}
		logoH:="";if logo!=""{logoH=fmt.Sprintf(`<img class="g-header-logo" src="%s">`,embedImg(logo))}
		subH:="";if sub!=""{subH=fmt.Sprintf(`<div class="g-header-sub">%s</div>`,he(sub))}
		return fmt.Sprintf(`<div class="g-header" style="%s">%s<div><div class="g-header-title">%s</div>%s</div></div>`,sty,logoH,he(title),subH)
	case "footer":
		return fmt.Sprintf(`<div class="g-footer">%s</div>`,he(w.Text))
	case "html":
		return w.Text
	}
	return ""
}

func embedImg(path string) string {
	if path=="" { return "" }
	abs,_:=filepath.Abs(path); data,err:=os.ReadFile(abs); if err!=nil{return ""}
	ext:=strings.ToLower(filepath.Ext(path)); mime:="image/png"
	switch ext{case ".jpg",".jpeg":mime="image/jpeg";case ".gif":mime="image/gif";case ".svg":mime="image/svg+xml";case ".webp":mime="image/webp"}
	return fmt.Sprintf("data:%s;base64,%s",mime,base64.StdEncoding.EncodeToString(data))
}

func he(s string) string {
	s=strings.ReplaceAll(s,"&","&amp;"); s=strings.ReplaceAll(s,"<","&lt;")
	s=strings.ReplaceAll(s,">","&gt;"); s=strings.ReplaceAll(s,`"`,"&quot;")
	return s
}

func (interp *Interpreter) guiBuiltin(name string, args []interface{}, argExprs []Expr, env *Env) (interface{}, error) {
	aa:=func(idx int,def string)string{if idx<len(args){return toStr(args[idx])};return def}
	om:=func(idx int)map[string]interface{}{if idx<len(args){if m,ok:=args[idx].(map[string]interface{});ok{return m}};return map[string]interface{}{}}
	mg:=func(base map[string]interface{},idx int)map[string]interface{}{if idx<len(args){if m,ok:=args[idx].(map[string]interface{});ok{for k,v:=range m{base[k]=v}}};return base}
	add:=func(w GUIWidget){gui.widgets=append(gui.widgets,w)}

	switch name {
	case "open.window":
		o:=om(0)
		if v,ok:=o["title"];ok{gui.title=toStr(v)};if v,ok:=o["width"];ok{gui.width=int(toFloat(v))};if v,ok:=o["height"];ok{gui.height=int(toFloat(v))}
		if v,ok:=o["bg"];ok{gui.bg=toStr(v)};if v,ok:=o["accent"];ok{gui.accent=toStr(v)};if v,ok:=o["text"];ok{gui.textClr=toStr(v)}
		if v,ok:=o["font"];ok{gui.font=toStr(v)};if v,ok:=o["radius"];ok{gui.radius=toStr(v)};if v,ok:=o["padding"];ok{gui.padding=toStr(v)}
		if v,ok:=o["resizable"];ok{gui.resizable=isTruthy(v)};if v,ok:=o["scrollbar"];ok{gui.scrollbar=isTruthy(v)};if v,ok:=o["css"];ok{gui.customCSS=toStr(v)}
		gui.ready=true; return nil,nil
	case "end":
		if !gui.ready{return nil,fmt.Errorf("call open.window() before end()")}
		wv:=webview.New(true); defer wv.Destroy(); gui.wv=wv
		wv.SetTitle(gui.title)
		wv.SetSize(gui.width,gui.height,webview.HintNone)
		wv.Bind("_goUpdateValue",func(id,val string){gui.mu.Lock();gui.values[id]=val;gui.mu.Unlock()})
		wv.Bind("_goTriggerEvent",func(id string){gui.mu.Lock();fn,ok:=gui.events[id];gui.mu.Unlock();if ok{go fn()}})
		wv.Bind("_goConfirmResult",func(val string){select{case gui.confirm<-val=="true":default:}})
		gui.safeEval=func(js string){wv.Dispatch(func(){wv.Eval(js)})}
		wv.SetHtml(buildPage()); wv.Run(); return nil,nil
	case "GUI.label": if len(args)<1{return nil,nil};add(GUIWidget{Kind:"label",Text:aa(0,""),Opts:om(1)});return nil,nil
	case "GUI.input":
		if len(args)<1{return nil,fmt.Errorf("GUI.input requires id")};id:=aa(0,"");o:=map[string]interface{}{};if len(args)>=2{o["placeholder"]=aa(1,"")};o=mg(o,2);gui.values[id]=gS(o,"value","");add(GUIWidget{ID:id,Kind:"input",Opts:o});return nil,nil
	case "GUI.password":
		if len(args)<1{return nil,fmt.Errorf("GUI.password requires id")};id:=aa(0,"");o:=map[string]interface{}{};if len(args)>=2{o["placeholder"]=aa(1,"")};gui.values[id]="";add(GUIWidget{ID:id,Kind:"password",Opts:o});return nil,nil
	case "GUI.number":
		if len(args)<1{return nil,fmt.Errorf("GUI.number requires id")};id:=aa(0,"");o:=map[string]interface{}{};if len(args)>=2{o["placeholder"]=aa(1,"")};o=mg(o,2);gui.values[id]=gS(o,"value","0");add(GUIWidget{ID:id,Kind:"number",Opts:o});return nil,nil
	case "GUI.button":
		if len(args)<2{return nil,fmt.Errorf("GUI.button requires text, event")};add(GUIWidget{ID:aa(1,""),Kind:"button",Text:aa(0,""),EventID:aa(1,""),Opts:om(2)});return nil,nil
	case "GUI.iconButton":
		if len(args)<2{return nil,fmt.Errorf("GUI.iconButton requires icon, event")};add(GUIWidget{ID:aa(1,""),Kind:"iconButton",Text:aa(0,""),EventID:aa(1,""),Opts:om(2)});return nil,nil
	case "GUI.link":
		if len(args)<2{return nil,fmt.Errorf("GUI.link requires text, event")};add(GUIWidget{ID:aa(1,""),Kind:"link",Text:aa(0,""),EventID:aa(1,""),Opts:om(2)});return nil,nil
	case "GUI.output":
		if len(args)<1{return nil,fmt.Errorf("GUI.output requires id")};id:=aa(0,"");o:=om(1);gui.outputs[id]=[]string{};add(GUIWidget{ID:id,Kind:"output",Opts:o});return nil,nil
	case "GUI.progress":
		if len(args)<1{return nil,fmt.Errorf("GUI.progress requires id")};add(GUIWidget{ID:aa(0,""),Kind:"progress",Opts:om(1)});return nil,nil
	case "GUI.spinner": if len(args)<1{return nil,fmt.Errorf("GUI.spinner requires id")};add(GUIWidget{ID:aa(0,""),Kind:"spinner"});return nil,nil
	case "GUI.checkbox":
		if len(args)<2{return nil,fmt.Errorf("GUI.checkbox requires id, label")};id:=aa(0,"");o:=om(2);gui.values[id]="false";if gB(o,"checked",false){gui.values[id]="true"};add(GUIWidget{ID:id,Kind:"checkbox",Text:aa(1,""),Opts:o});return nil,nil
	case "GUI.toggle":
		if len(args)<2{return nil,fmt.Errorf("GUI.toggle requires id, label")};id:=aa(0,"");o:=om(2);gui.values[id]="false";if gB(o,"checked",false){gui.values[id]="true"};add(GUIWidget{ID:id,Kind:"toggle",Text:aa(1,""),Opts:o});return nil,nil
	case "GUI.radio":
		if len(args)<3{return nil,fmt.Errorf("GUI.radio requires id, name, label")};id:=aa(0,"");o:=map[string]interface{}{"name":aa(1,""),"value":aa(3,aa(2,""))};o=mg(o,4);add(GUIWidget{ID:id,Kind:"radio",Text:aa(2,""),Opts:o});return nil,nil
	case "GUI.dropdown":
		if len(args)<2{return nil,fmt.Errorf("GUI.dropdown requires id, options")};id:=aa(0,"");o:=map[string]interface{}{"options":args[1]};o=mg(o,2);add(GUIWidget{ID:id,Kind:"dropdown",Opts:o});return nil,nil
	case "GUI.slider":
		if len(args)<3{return nil,fmt.Errorf("GUI.slider requires id, min, max")};id:=aa(0,"");o:=map[string]interface{}{"min":args[1],"max":args[2]};o=mg(o,3);gui.values[id]=toStr(args[1]);add(GUIWidget{ID:id,Kind:"slider",Opts:o});return nil,nil
	case "GUI.table":
		if len(args)<1{return nil,fmt.Errorf("GUI.table requires id")};id:=aa(0,"");o:=map[string]interface{}{};if len(args)>=2{o["headers"]=args[1]};if len(args)>=3{o["rows"]=args[2]};o=mg(o,3);gui.tables[id]=[][]string{};add(GUIWidget{ID:id,Kind:"table",Opts:o});return nil,nil
	case "GUI.image": if len(args)<1{return nil,fmt.Errorf("GUI.image requires path")};add(GUIWidget{Kind:"image",Text:aa(0,""),Opts:om(1)});return nil,nil
	case "GUI.space": h:=float64(16);if len(args)>=1{h=toFloat(args[0])};add(GUIWidget{Kind:"space",Opts:map[string]interface{}{"height":h}});return nil,nil
	case "GUI.divider": add(GUIWidget{Kind:"divider",Opts:om(0)});return nil,nil
	case "GUI.card":
		title:="";if len(args)>=1{title=aa(0,"")};o:=map[string]interface{}{"title":title};o=mg(o,1);id:=gS(o,"id",fmt.Sprintf("card%d",len(gui.widgets)));o["id"]=id;add(GUIWidget{ID:id,Kind:"card",Opts:o});return nil,nil
	case "GUI.cardEnd": add(GUIWidget{Kind:"cardEnd"});return nil,nil
	case "GUI.badge": if len(args)<1{return nil,nil};add(GUIWidget{Kind:"badge",Text:aa(0,""),Opts:om(1)});return nil,nil
	case "GUI.alert_box": if len(args)<1{return nil,nil};o:=om(1);if _,ok:=o["type"];!ok{o["type"]="info"};add(GUIWidget{Kind:"alert_box",Text:aa(0,""),Opts:o});return nil,nil
	case "GUI.code": if len(args)<1{return nil,nil};add(GUIWidget{Kind:"code",Text:aa(0,""),Opts:om(1)});return nil,nil
	case "GUI.tabs": if len(args)<1{return nil,fmt.Errorf("GUI.tabs requires tab list")};add(GUIWidget{Kind:"tabs",Opts:map[string]interface{}{"tabs":args[0]}});return nil,nil
	case "GUI.tabPanel": if len(args)<1{return nil,fmt.Errorf("GUI.tabPanel requires id")};add(GUIWidget{ID:aa(0,""),Kind:"tabPanel",Opts:om(1)});return nil,nil
	case "GUI.tabPanelEnd": add(GUIWidget{Kind:"tabPanelEnd"});return nil,nil
	case "GUI.rowStart": add(GUIWidget{Kind:"rowStart",Opts:om(0)});return nil,nil
	case "GUI.rowEnd": add(GUIWidget{Kind:"rowEnd"});return nil,nil
	case "GUI.colStart": add(GUIWidget{Kind:"colStart",Opts:om(0)});return nil,nil
	case "GUI.colEnd": add(GUIWidget{Kind:"colEnd"});return nil,nil
	case "GUI.sidebar": if len(args)<1{return nil,fmt.Errorf("GUI.sidebar requires items")};add(GUIWidget{Kind:"sidebar",Opts:map[string]interface{}{"items":args[0]}});return nil,nil
	case "GUI.sidebarEnd": add(GUIWidget{Kind:"sidebarEnd"});return nil,nil
	case "GUI.header":
		text:="";if len(args)>=1{text=aa(0,"")};o:=map[string]interface{}{"title":text};o=mg(o,1);add(GUIWidget{Kind:"header",Text:text,Opts:o});return nil,nil
	case "GUI.footer": add(GUIWidget{Kind:"footer",Text:aa(0,"")});return nil,nil
	case "GUI.html": if len(args)>=1{add(GUIWidget{Kind:"html",Text:aa(0,"")})};return nil,nil
	case "GUI.on":
		if len(args)<2{return nil,fmt.Errorf("GUI.on requires event, func")};event:=aa(0,"");fn,ok:=args[1].(*UserFunc);if !ok{return nil,fmt.Errorf("GUI.on: second arg must be func")}
		child:=NewEnv(fn.Env);gui.mu.Lock();gui.events[event]=func(){interp.execBlock(fn.Body,child)};gui.mu.Unlock();return nil,nil
	case "GUI.get":
		if len(args)<1{return "",nil};gui.mu.Lock();v:=gui.values[aa(0,"")];gui.mu.Unlock();return v,nil
	case "GUI.set":
		if len(args)<2{return nil,nil};id:=aa(0,"");val:=aa(1,"");gui.mu.Lock();gui.values[id]=val;gui.mu.Unlock()
		if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sSetValue(%q,%q)`,id,val))};return nil,nil
	case "GUI.print","GUI.println":
		if len(args)<2{return nil,nil};id:=aa(0,"");text:=aa(1,"");gui.mu.Lock();gui.outputs[id]=append(gui.outputs[id],text);combined:=strings.Join(gui.outputs[id],"\n");gui.mu.Unlock()
		if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sSetOutput(%q,%q)`,id,combined))};return nil,nil
	case "GUI.clear":
		if len(args)<1{return nil,nil};id:=aa(0,"");gui.mu.Lock();gui.outputs[id]=[]string{};gui.values[id]="";gui.mu.Unlock()
		if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sSetOutput(%q,"")`,id));gui.safeEval(fmt.Sprintf(`_sSetValue(%q,"")`,id))};return nil,nil
	case "GUI.setProgress":
		if len(args)<2{return nil,nil};if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sSetProgress(%q,%.4f)`,aa(0,""),toFloat(args[1])))};return nil,nil
	case "GUI.appendRow":
		if len(args)<2{return nil,nil};id:=aa(0,"");var cells []string;if row,ok:=args[1].([]interface{});ok{for _,c:=range row{cells=append(cells,toStr(c))}};gui.mu.Lock();gui.tables[id]=append(gui.tables[id],cells);gui.mu.Unlock()
		if gui.safeEval!=nil{var jc []string;for _,c:=range cells{jc=append(jc,fmt.Sprintf("%q",c))};gui.safeEval(fmt.Sprintf(`_sAppendRow(%q,[%s])`,id,strings.Join(jc,",")))};return nil,nil
	case "GUI.clearTable":
		if len(args)<1{return nil,nil};id:=aa(0,"");gui.mu.Lock();gui.tables[id]=[][]string{};gui.mu.Unlock();if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sClearTable(%q)`,id))};return nil,nil
	case "GUI.show": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sShow(%q)`,aa(0,"")))};return nil,nil
	case "GUI.hide": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sHide(%q)`,aa(0,"")))};return nil,nil
	case "GUI.enable": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sEnable(%q)`,aa(0,"")))};return nil,nil
	case "GUI.disable": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sDisable(%q)`,aa(0,"")))};return nil,nil
	case "GUI.focus": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sFocus(%q)`,aa(0,"")))};return nil,nil
	case "GUI.showSpinner": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sShowSpin(%q)`,aa(0,"")))};return nil,nil
	case "GUI.hideSpinner": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sHideSpin(%q)`,aa(0,"")))};return nil,nil
	case "GUI.setTitle": if len(args)>=1&&gui.wv!=nil{gui.wv.Dispatch(func(){gui.wv.SetTitle(aa(0,""))})};return nil,nil
	case "GUI.setAccent": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sAccent(%q)`,aa(0,"")))};return nil,nil
	case "GUI.setBg": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sBg(%q)`,aa(0,"")))};return nil,nil
	case "GUI.alert": if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sAlert(%q)`,aa(0,"")))};return nil,nil
	case "GUI.confirm":
		if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sConfirm(%q)`,aa(0,"")))}
		select{case result:=<-gui.confirm:return result,nil}
	case "GUI.notify":
		if gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`if(Notification.permission==="granted"){new Notification(%q,{body:%q})}`,aa(0,"Spectator"),aa(1,"")))}
		return nil,nil
	case "GUI.openTab":
		if len(args)>=1&&gui.safeEval!=nil{grp:="default";if len(args)>=2{grp=aa(1,"")};gui.safeEval(fmt.Sprintf(`_sOpenTab(%q,%q)`,aa(0,""),grp))};return nil,nil
	case "GUI.css": if len(args)>=3&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sCSS(%q,%q,%q)`,aa(0,""),aa(1,""),aa(2,"")))};return nil,nil
	case "GUI.addClass": if len(args)>=2&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sClass(%q,%q,true)`,aa(0,""),aa(1,"")))};return nil,nil
	case "GUI.removeClass": if len(args)>=2&&gui.safeEval!=nil{gui.safeEval(fmt.Sprintf(`_sClass(%q,%q,false)`,aa(0,""),aa(1,"")))};return nil,nil
	case "GUI.eval": if len(args)>=1&&gui.safeEval!=nil{gui.safeEval(aa(0,""))};return nil,nil
	case "GUI.theme": return nil,nil
	}
	return nil,fmt.Errorf("unknown GUI builtin: %q",name)
}
