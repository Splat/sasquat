/* ---------- state ---------- */
let RAW = [];
let VIEW = [];
let SORT = {k:"score", dir:"desc"};
let CFG = {
    sinkholes:new Set(),
    indicators:[],
    knownIssuers:new Set(),
    baseDomain:"",
    baseRegistrable:"",
    brandToken:""
};


function defaultLists(){
    // TODO: This needs to be computed from results as opposed to hard coded
    $("parkingIndicators").value = [
        "domaincontrol.com","secureserver.net","godaddy","afternic","dan.com",
        "sedo","parkingcrew","bodis","namecheap","namesilo","googlehosted.com",
        "cloudflare","registrar","whois","for-sale","for sale","buy this domain",
        "coming soon","under construction","this domain is for sale","parked"
    ].join("\n");

    // TODO: This needs to be computed from results as opposed to hard coded
    $("knownIssuers").value = [
        "let's encrypt","digicert","sectigo","comodoca","globalsign","entrust",
        "godaddy","amazon","cloudflare","microsoft"
    ].join("\n");
}
defaultLists();

function updateCfg(){
    CFG.sinkholes = new Set(splitAny($("sinkholeIps").value));
    CFG.indicators = splitAny($("parkingIndicators").value).map(x=>x.toLowerCase());
    CFG.knownIssuers = new Set(splitAny($("knownIssuers").value).map(x=>x.toLowerCase()));

    CFG.baseDomain = $("baseDomain").value.trim().toLowerCase();
    CFG.baseRegistrable = CFG.baseDomain ? registrableHint(CFG.baseDomain) : "";
    const p = parseDomainParts(CFG.baseDomain);
    // brand token: left-most label of SLD, e.g., "comcast" from "comcast.com"
    CFG.brandToken = (p.sld || "").split(".")[0] || "";
}

function normalizeRecord(r){
    const d = (r.domain||"").toLowerCase();
    const dns = r.dns || {};
    const tls = r.tls || {};
    const http = r.http || {};
    const ips = []
        .concat(dns.A||[])
        .concat(dns.AAAA||[])
        .filter(Boolean);

    const cand = parseDomainParts(d);
    const scored = scoreRecord(r, CFG);

    return {
        _raw:r,
        domain:d,
        resolvable: !!r.resolvable,
        variantClass: r.strategy || "unknown",
        tld: cand.tld || "",
        score: scored.score,
        tags: scored.tags,
        ips: ips.join(" "),
        ns: (dns.NS||[]).join(" "),
        mx: (dns.MX||[]).join(" "),
        tlsIssuer: safe(tls.Issuer),
        httpStatus: safe(http.Status) || (http.StatusCode? String(http.StatusCode):""),
        httpStatusCode: Number(http.StatusCode||0),
        location: safe(http.Location),
        server: safe(http.Server),
        finalUrl: safe(http.FinalURL) || safe(http.URL),
        title: safe(http.Title) || safe(http.PageTitle),
        redirectChain: http.RedirectChain || http.Redirects || http.Chain || [],
        contentType: safe(http.ContentType),
        contentLength: Number(http.ContentLength||0),
        bodySHA256: safe(http.BodySHA256) || safe(http.SHA256) || safe(http.BodyHash),
        faviconMMH3: safe(http.FaviconMMH3) || safe(http.FaviconHash) || safe(http.MMH3),
        headers: http.Headers || {},
    };
}

function applyFilters(){
    const q = $("search").value.trim().toLowerCase();
    const vf = $("variantFilter").value;
    const tf = $("tldFilter").value;
    const minS = parseInt($("minScore").value||"0",10);
    const maxS = parseInt($("maxScore").value||"999",10);
    const ro = $("resolvableOnly").value;
    const ha = $("httpAttempted").value;

    VIEW = RAW
        .filter(r=>{
            if(q){
                const hay = (r.domain+" "+r.ips+" "+r.tlsIssuer+" "+r.location+" "+r.ns+" "+r.mx).toLowerCase();
                if(!hay.includes(q)) return false;
            }
            if(vf && r.variantClass !== vf) return false;
            if(tf && r.tld !== tf) return false;
            if(!(r.score >= minS && r.score <= maxS)) return false;
            if(ro){
                const want = (ro==="true");
                if(r.resolvable !== want) return false;
            }
            if(ha){
                const attempted = !!(r._raw.http && r._raw.http.Attempted);
                const want = (ha==="true");
                if(attempted !== want) return false;
            }
            return true;
        });

    render();
    renderKpi();
    renderGroups();
    renderActiveFilters();
}

function sortView(){
    const k = SORT.k;
    const dir = SORT.dir;
    const mul = dir==="asc" ? 1 : -1;

    VIEW.sort((a,b)=>{
        let av = a[k], bv = b[k];
        if(k==="score" || k==="httpStatusCode"){
            av = Number(av||0); bv = Number(bv||0);
            return (av-bv)*mul;
        }
        av = safe(av).toLowerCase();
        bv = safe(bv).toLowerCase();
        if(av<bv) return -1*mul;
        if(av>bv) return 1*mul;
        return 0;
    });
}

function render(){
    sortView();
    const tb = $("tbody");
    tb.innerHTML = "";

    for(const r of VIEW){
        const tr = document.createElement("tr");

        // score cell
        const sc = document.createElement("td");
        const cls = scoreClass(r.score);
        sc.innerHTML = `<span class="score ${cls}">${r.score}</span>`;
        tr.appendChild(sc);

        const dom = document.createElement("td");
        dom.innerHTML = `<div class="mono">${r.domain}</div>
      <div class="tags">${r.tags.slice(0,4).map(t=>`<span class="tag">${t}</span>`).join("")}${r.tags.length>4?`<span class="tag">+${r.tags.length-4}</span>`:""}</div>`;
        tr.appendChild(dom);

        const vc = document.createElement("td");
        vc.innerHTML = `<span class="pill"><strong>${r.variantClass}</strong></span>`;
        tr.appendChild(vc);

        const tld = document.createElement("td");
        tld.innerHTML = `<span class="pill"><strong>${safe(r.tld||"")}</strong></span>`;
        tr.appendChild(tld);

        const dns = document.createElement("td");
        dns.innerHTML = r.resolvable ? `<span class="pill"><strong style="color:var(--good)">resolvable</strong></span>` : `<span class="pill"><strong style="color:var(--bad)">no</strong></span>`;
        tr.appendChild(dns);

        const ip = document.createElement("td");
        ip.innerHTML = `<div class="mono">${safe(r.ips)}</div>`;
        tr.appendChild(ip);

        const ns = document.createElement("td");
        ns.innerHTML = `<div class="mono">${safe(r.ns)}</div>`;
        tr.appendChild(ns);

        const mx = document.createElement("td");
        mx.innerHTML = `<div class="mono">${safe(r.mx)}</div>`;
        tr.appendChild(mx);

        const ti = document.createElement("td");
        ti.innerHTML = `<div class="mono">${safe(r.tlsIssuer).slice(0,140)}${safe(r.tlsIssuer).length>140?"…":""}</div>`;
        tr.appendChild(ti);

        const hs = document.createElement("td");
        hs.innerHTML = `<div class="mono">${safe(r.httpStatus)}</div>`;
        tr.appendChild(hs);

        const loc = document.createElement("td");
        loc.innerHTML = `<div class="mono">${safe(r.location).slice(0,140)}${safe(r.location).length>140?"…":""}</div>`;
        tr.appendChild(loc);

        const links = document.createElement("td");
        const d = encodeURIComponent(r.domain);
        links.innerHTML = `
      <div class="small">
        <a href="https://${r.domain}/" target="_blank" rel="noreferrer">Open</a> ·
        <a href="https://rdap.org/domain/${d}" target="_blank" rel="noreferrer">RDAP</a> ·
        <a href="https://lookup.icann.org/en/lookup?name=${d}" target="_blank" rel="noreferrer">ICANN</a> ·
        <a href="https://www.whois.com/whois/${d}" target="_blank" rel="noreferrer">whois.com</a>
      </div>`;
        tr.appendChild(links);
        tr.addEventListener("click", ()=>{ window.__selected = r.domain; renderInspector(r); });


        tb.appendChild(tr);
    }

    // update variant dropdown
    const variants = Array.from(new Set(RAW.map(r=>r.variantClass).filter(Boolean))).sort();
    const vSel = $("variantFilter");
    const vCurrent = vSel.value;
    vSel.innerHTML = '<option value="">All</option>' + variants.map(v=>`<option value="${v}">${v}</option>`).join("");
    vSel.value = variants.includes(vCurrent) ? vCurrent : "";

    // update TLD dropdown
    const tlds = Array.from(new Set(RAW.map(r=>r.tld).filter(Boolean))).sort();
    const sel = $("tldFilter");
    const current = sel.value;
    sel.innerHTML = '<option value="">All</option>' + tlds.map(t=>`<option value="${t}">${t}</option>`).join("");
    sel.value = tlds.includes(current) ? current : "";

    // keep / set selection
    if(VIEW.length){
        const cur = window.__selected;
        const rec = cur ? VIEW.find(x=>x.domain===cur) : null;
        renderInspector(rec || VIEW[0]);
    } else {
        renderInspector(null);
    }
}

function renderKpi(){
    const total = RAW.length;
    const shown = VIEW.length;
    const resolvable = VIEW.filter(r=>r.resolvable).length;
    const hi = VIEW.filter(r=>r.score>=45).length;
    const med = VIEW.filter(r=>r.score>=25 && r.score<45).length;
    const low = VIEW.filter(r=>r.score<25).length;

    $("kpi").innerHTML = `
    <span class="pill"><strong>${shown}</strong> shown / <strong>${total}</strong> total</span>
    <span class="pill"><strong>${resolvable}</strong> resolvable</span>
    <span class="pill"><strong style="color:var(--bad)">${hi}</strong> high</span>
    <span class="pill"><strong style="color:var(--warn)">${med}</strong> medium</span>
    <span class="pill"><strong style="color:var(--good)">${low}</strong> low</span>
  `;
}


function renderInspector(r){
    const box = $("inspector");
    if(!r){
        box.innerHTML = `<div class="pill">No record selected.</div>`;
        return;
    }

    // Build redirect chain display (supports several shapes)
    const chain = Array.isArray(r.redirectChain) ? r.redirectChain : [];
    const chainRows = chain.map((c, i) => {
        if(typeof c === "string"){
            return `<li class="mono">${escapeHtml(c)}</li>`;
        }
        const url = safe(c.url || c.URL || c.href || c.to || "");
        const status = safe(c.status || c.Status || c.code || c.StatusCode || "");
        const loc = safe(c.location || c.Location || "");
        const title = safe(c.title || c.Title || "");
        return `<li>
      <div class="mono"><strong>${i+1}.</strong> ${escapeHtml(url || "(unknown)")}</div>
      <div class="muted small">${escapeHtml(status)}${loc? " → "+escapeHtml(loc):""}${title? " · "+escapeHtml(title):""}</div>
    </li>`;
    }).join("");

    const hasChain = chain.length > 0;
    const chainHtml = hasChain ? `
    <details open>
      <summary>Redirect chain (${chain.length})</summary>
      <ol style="margin:10px 0 0 20px; padding:0; display:flex; flex-direction:column; gap:8px;">
        ${chainRows}
      </ol>
    </details>` : `
    <details>
      <summary>Redirect chain</summary>
      <div class="muted small" style="margin-top:8px;">
        No redirect-chain data present in this record. If you want this view, have the scanner emit an array like
        <span class="mono">http.RedirectChain</span> containing visited URLs/status/location.
      </div>
    </details>`;

    // Title + metadata
    const title = safe(r.title);
    const finalUrl = safe(r.finalUrl) || ("https://" + r.domain + "/");
    const httpLine = [safe(r.httpStatus), r.httpStatusCode? String(r.httpStatusCode):"", safe(r.server)].filter(Boolean).join(" · ");

    const titleHtml = `
    <details ${title ? "open" : ""}>
      <summary>Page title & HTTP metadata</summary>
      <div style="margin-top:10px; display:grid; grid-template-columns: 140px 1fr; gap:8px 12px; align-items:start;">
        <div class="muted small">Final URL</div><div class="mono"><a href="${escapeAttr(finalUrl)}" target="_blank" rel="noreferrer">${escapeHtml(finalUrl)}</a></div>
        <div class="muted small">HTTP</div><div class="mono">${escapeHtml(httpLine || "—")}</div>
        <div class="muted small">Title</div><div class="mono">${escapeHtml(title || "— (not captured)")}</div>
        <div class="muted small">Content-Type</div><div class="mono">${escapeHtml(safe(r.contentType) || "—")}</div>
        <div class="muted small">Content-Length</div><div class="mono">${r.contentLength ? escapeHtml(String(r.contentLength)) : "—"}</div>
      </div>
    </details>`;

    // Fingerprints and indicators
    const fp = [];
    if(r.bodySHA256) fp.push(`<span class="tag">bodySHA256</span> <span class="mono">${escapeHtml(r.bodySHA256)}</span>`);
    if(r.faviconMMH3) fp.push(`<span class="tag">faviconMMH3</span> <span class="mono">${escapeHtml(r.faviconMMH3)}</span>`);

    const indicators = fingerprintIndicators(r);
    const indHtml = indicators.length
        ? `<ul style="margin:10px 0 0 18px; padding:0; display:flex; flex-direction:column; gap:6px;">
         ${indicators.map(x=>`<li>${x}</li>`).join("")}
       </ul>`
        : `<div class="muted small" style="margin-top:8px;">No fingerprint indicators triggered (or insufficient HTTP capture fields).</div>`;

    const fpHtml = `
    <details open>
      <summary>Content fingerprinting</summary>
      ${fp.length ? `<div style="margin-top:10px; display:flex; flex-direction:column; gap:6px;">${fp.map(x=>`<div>${x}</div>`).join("")}</div>` :
        `<div class="muted small" style="margin-top:8px;">No content hashes present. To enable: have the scanner capture a small body sample or compute hashes server-side.</div>`}
      <div class="group">
        <h3 style="margin:14px 0 6px 0;">Indicators</h3>
        ${indHtml}
      </div>
    </details>`;

    const inv = encodeURIComponent(r.domain);
    const links = `
    <div class="small" style="margin-top:10px;">
      Investigation links:
      <a href="https://${r.domain}/" target="_blank" rel="noreferrer">Open</a> ·
      <a href="https://rdap.org/domain/${inv}" target="_blank" rel="noreferrer">RDAP</a> ·
      <a href="https://lookup.icann.org/en/lookup?name=${inv}" target="_blank" rel="noreferrer">ICANN</a> ·
      <a href="https://www.whois.com/whois/${inv}" target="_blank" rel="noreferrer">whois.com</a>
    </div>`;

    box.innerHTML = `
    <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;">
      <div class="mono" style="font-weight:800;">${escapeHtml(r.domain)}</div>
      <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <span class="pill"><strong>${r.score}</strong> score</span>
        <span class="pill"><strong>${escapeHtml(r.variantClass||"")}</strong></span>
        <span class="pill"><strong>${escapeHtml(r.tld||"")}</strong></span>
      </div>
    </div>
    ${links}
    ${chainHtml}
    ${titleHtml}
    ${fpHtml}
  `;
}

// Very lightweight, data-driven indicators (no network fetch).
// These only work if results.json includes the relevant captured fields.
function fingerprintIndicators(r){
    const out = [];

    // Parking heuristics
    const t = (safe(r.title) || "").toLowerCase();
    const srv = (safe(r.server) || "").toLowerCase();
    const loc = (safe(r.location) || "").toLowerCase();

    const parkingTitle = /(domain\s+for\s+sale|buy\s+this\s+domain|this\s+domain\s+is\s+parked|parked\s+domain|sedo|afternic|dan\.com|hugedomains|bodis|parking)/i;
    if(parkingTitle.test(t) || parkingTitle.test(srv)){
        out.push(`<span class="pill"><strong style="color:var(--warn)">parking-like</strong></span> Title/Server suggests domain parking.`);
    }

    // Redirect-to-brand detection (simple substring match against base domain)
    const base = (CFG.baseDomain||"").toLowerCase();
    if(base && (loc.includes(base) || (safe(r.finalUrl)||"").toLowerCase().includes(base))){
        out.push(`<span class="pill"><strong style="color:var(--good)">redirect-to-brand</strong></span> Redirect/Final URL contains base domain.`);
    }

    // Sinkhole IP indicator
    const sinkholes = splitAny($("sinkholeIps").value);
    if(sinkholes.length && r.ips){
        const hit = sinkholes.find(ip => (" "+r.ips+" ").includes(ip));
        if(hit) out.push(`<span class="pill"><strong style="color:var(--warn)">sinkhole-hit</strong></span> Matches sinkhole IP: <span class="mono">${escapeHtml(hit)}</span>.`);
    }

    // TLS issuer familiarity / entropy heuristic (only if issuer present)
    const issuer = safe(r.tlsIssuer);
    if(issuer){
        const known = splitAny($("knownIssuers").value).some(k => issuer.toLowerCase().includes(k.toLowerCase()));
        if(!known){
            out.push(`<span class="pill"><strong style="color:var(--warn)">unfamiliar-issuer</strong></span> TLS issuer not in known list.`);
        }
        const ent = shannonEntropy(issuer);
        if(ent > 4.2){
            out.push(`<span class="pill"><strong style="color:var(--warn)">issuer-entropy</strong></span> TLS issuer string entropy is high (${ent.toFixed(2)}).`);
        }
    }

    // Presence indicators
    if(r.mx) out.push(`<span class="pill"><strong style="color:var(--good)">mx-present</strong></span> MX records present (phishing surface).`);
    if(r.bodySHA256) out.push(`<span class="pill"><strong style="color:var(--good)">body-hash</strong></span> Body hash captured (supports clustering).`);
    if(r.faviconMMH3) out.push(`<span class="pill"><strong style="color:var(--good)">favicon-hash</strong></span> Favicon hash captured (supports clustering).`);

    return out;
}

function renderGroups(){
    const byVariant = {};
    const byTld = {};
    for(const r of RAW){
        byVariant[r.variantClass] = (byVariant[r.variantClass]||0)+1;
        byTld[r.tld||""] = (byTld[r.tld||""]||0)+1;
    }

    function groupHtml(obj, onClick){
        const keys = Object.keys(obj).sort((a,b)=>obj[b]-obj[a]);
        return keys.map(k=>{
            const label = k || "(none)";
            return `
        <div class="groupItem" role="button" tabindex="0" data-key="${k}">
          <div class="groupKey">${label}</div>
          <div class="groupMeta">
            <span class="pill"><strong>${obj[k]}</strong> rows</span>
          </div>
        </div>`;
        }).join("");
    }

    $("groupVariant").innerHTML = groupHtml(byVariant);
    $("groupTld").innerHTML = groupHtml(byTld);

    // attach click handlers
    for(const el of $("groupVariant").querySelectorAll(".groupItem")){
        el.onclick = ()=>{ $("variantFilter").value = el.dataset.key; applyFilters(); };
    }
    for(const el of $("groupTld").querySelectorAll(".groupItem")){
        el.onclick = ()=>{ $("tldFilter").value = el.dataset.key; applyFilters(); };
    }
}

function renderActiveFilters(){
    const pills = [];
    const add = (k,v)=>{ if(v) pills.push(`<span class="pill"><strong>${k}</strong> <span class="mono">${v}</span></span>`); };

    add("base", CFG.baseDomain || "(none)");
    add("search", $("search").value.trim());
    add("variant", $("variantFilter").value);
    add("tld", $("tldFilter").value);
    add("minScore", $("minScore").value);
    add("maxScore", $("maxScore").value);
    add("resolvable", $("resolvableOnly").value);
    add("http", $("httpAttempted").value);

    $("activeFilters").innerHTML = pills.join("");
}