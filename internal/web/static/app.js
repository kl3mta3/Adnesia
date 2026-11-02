"use strict";

const $ = (id) => document.getElementById(id);

async function getJSON(u){ const r=await fetch(u,{cache:"no-store"}); if(!r.ok) throw new Error(r.status); return r.json(); }
async function postJSON(u,b){ const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:b?JSON.stringify(b):undefined}); if(!r.ok) throw new Error(r.status); return r.json(); }
const fmt = (n)=> (n||0).toLocaleString();
function ago(ts){ const s=Math.max(0,(Date.now()-new Date(ts).getTime())/1000);
  if(s<60) return Math.floor(s)+"s ago"; if(s<3600) return Math.floor(s/60)+"m ago"; return Math.floor(s/3600)+"h ago"; }

const FEATURES = [
  ["ad_blocking",        "🛑","Ad Blocking",        "Ad servers, ad scripts and banners"],
  ["privacy_protection", "🕵️","Privacy Protection", "Trackers and analytics (EasyPrivacy)"],
  ["web_protection",     "🛡️","Web Protection",     "Known malware & phishing domains"],
  ["annoyances_blocking","🧹","Annoyances Blocking","Cookie notices, nags, social widgets"],
  ["ghost_mode",         "👻","Ghost Mode",         "Strip referrers, send DNT, drop tracking params"],
  ["cosmetic_generic",   "✂️","Generic Cosmetics",  "Extra element hiding on every site (heavier)"],
  ["transparent",        "🧬","Kernel Mode",        "Intercept at the network driver level so apps and games that ignore the system proxy are filtered too — experimental, needs admin + WinDivert"],
  ["autostart",          "🚀","Start with Windows", "Launch Adnesia automatically when you sign in"],
];

function buildFeatures(){
  const box=$("features"); box.innerHTML="";
  for(const [key,ic,lbl,hint] of FEATURES){
    const row=document.createElement("div"); row.className="feat";
    row.innerHTML =
      `<div class="ic">${ic}</div>`+
      `<div class="t"><div class="lbl">${lbl}</div><div class="hint" id="hint-${key}">${hint}</div></div>`+
      `<label class="sw"><input type="checkbox" data-feature="${key}"><span class="tr"></span></label>`;
    box.appendChild(row);
  }
  box.querySelectorAll('input[data-feature]').forEach(cb=>{
    cb.addEventListener("change", async ()=>{
      try{ await postJSON("/api/feature",{name:cb.dataset.feature, on:cb.checked}); }
      catch(e){ cb.checked=!cb.checked; }
      refreshStatus();
    });
  });
}

function renderStatus(st){
  const on=!!st.enabled;
  const hero=$("hero"); hero.className="hero "+(on?"on":"off");
  $("heroIcon").textContent = on?"✓":"✕";
  $("heroState").textContent = on?"Protected":"Disabled";
  $("heroDesc").textContent = !st.ca_trusted
    ? "Not active: Windows doesn't trust Adnesia's certificate, so the system proxy is left off to keep your internet working. Restart Adnesia and click Yes when Windows asks to install the certificate."
    : on
    ? `Filtering is active across your system. ${fmt(st.network_rules)} block rules, ${fmt(st.cosmetic_rules)} cosmetic rules loaded.`
    : "Protection is off — ads and trackers are not blocked, and your traffic goes direct.";
  if (!st.ca_trusted) { $("heroState").textContent = "Certificate not trusted"; hero.className = "hero off"; $("heroIcon").textContent = "!"; }
  const m=$("master");
  m.textContent = on?"Turn off":"Turn on";
  m.className = "bigbtn "+(on?"turnoff":"turnon");
  document.body.classList.toggle("masteroff", !on);

  const f=st.features||{};
  document.querySelectorAll('input[data-feature]').forEach(cb=>{ cb.checked=!!f[cb.dataset.feature]; });

  const th=$("hint-transparent");
  if(th && st.transparent_status){ th.textContent = FEATURES.find(f=>f[0]==="transparent")[3]+" · currently "+st.transparent_status; }

  $("b-chrome").textContent = on?"protected":"unprotected";
  $("b-chrome").className = "st "+(on?"ok":"warn");
  $("b-edge").textContent = on?"protected":"unprotected";
  $("b-edge").className = "st "+(on?"ok":"warn");

  $("foot").textContent = "proxy "+(st.proxy_addr||"")+(st.build ? "  ·  build "+st.build : "");
}

function renderStats(s){
  $("s-ads").textContent = fmt(s.ads);
  $("s-trackers").textContent = fmt(s.trackers);
  $("s-annoy").textContent = fmt(s.annoyances);
  $("s-threats").textContent = fmt(s.threats);
  $("s-mb").textContent = (s.saved_mb||0).toFixed(1)+" MB";
  $("s-time").textContent = fmt(s.saved_minutes)+" min";

  const log=$("log"), recent=s.recent||[];
  $("logempty").style.display = recent.length?"none":"block";
  log.innerHTML="";
  for(const e of recent.slice(0,50)){
    const tr=document.createElement("tr");
    const h=document.createElement("td"); h.className="host"; h.textContent=e.host;
    const u=document.createElement("td"); u.className="url"; u.textContent=e.url;
    const t=document.createElement("td"); t.className="time"; t.textContent=ago(e.time);
    tr.append(h,u,t); log.appendChild(tr);
  }
}

function renderBypass(b){
  const list=$("bplist"); list.innerHTML="";
  const sec=(items,tag,rm)=>{ for(const p of items||[]){
    const row=document.createElement("div"); row.className="bprow";
    const n=document.createElement("span"); n.textContent=p;
    const t=document.createElement("span"); t.className="tag"; t.textContent=tag;
    row.append(n,t);
    if(rm){ const x=document.createElement("button"); x.className="x"; x.textContent="remove";
      x.onclick=async()=>{ await postJSON("/api/bypass/remove",{pattern:p}); refreshBypass(); }; row.appendChild(x); }
    list.appendChild(row);
  }};
  sec(b.added,"added",true); sec(b.user,"config",false); sec(b.defaults,"default",false);
}

async function refreshStatus(){ try{ renderStatus(await getJSON("/api/status")); }catch(e){} }
async function refreshStats(){ try{ renderStats(await getJSON("/api/stats")); }catch(e){} }
async function refreshBypass(){ try{ renderBypass(await getJSON("/api/bypass")); }catch(e){} }

$("master").onclick = async ()=>{ try{ await postJSON("/api/toggle"); }catch(e){} refreshStatus(); };
$("bpadd").onclick = async ()=>{ const v=$("bpin").value.trim(); if(!v) return;
  await postJSON("/api/bypass/add",{pattern:v}); $("bpin").value=""; refreshBypass(); };
$("bpin").addEventListener("keydown",(e)=>{ if(e.key==="Enter") $("bpadd").click(); });

(async function init(){
  buildFeatures();
  await refreshStatus(); await refreshBypass(); await refreshStats();
  setInterval(refreshStats, 2000);
  setInterval(refreshStatus, 10000);
})();
