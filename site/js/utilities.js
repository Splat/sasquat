/* ---------- utilities ---------- */
const $ = (id)=>document.getElementById(id);

function splitAny(s){
    return (s||"")
        .split(/[^0-9A-Za-z\-\.\:]+/g)
        .map(x=>x.trim())
        .filter(Boolean);
}

function shannonEntropy(str){
    if(!str) return 0;
    const s = String(str);
    const freq = {};
    for(const ch of s){ freq[ch] = (freq[ch]||0)+1; }
    let ent = 0;
    const n = s.length;
    for(const k in freq){
        const p = freq[k]/n;
        ent -= p * Math.log2(p);
    }
    // normalize a bit to a 0..8-ish range for typical issuer strings
    return Math.min(8, Math.max(0, ent));
}

function parseDomainParts(d){
    const s = (d||"").trim().toLowerCase();
    const parts = s.split(".").filter(Boolean);
    if(parts.length < 2) return {sld:s, tld:""};
    const tld = parts[parts.length-1];
    const sld = parts.slice(0, parts.length-1).join(".");
    return {sld, tld, parts};
}

function registrableHint(domain){
    // Simple heuristic: last two labels. For many TLDs this is good enough for triage UI.
    const parts = (domain||"").toLowerCase().split(".").filter(Boolean);
    if(parts.length < 2) return domain||"";
    return parts.slice(-2).join(".");
}

function scoreRecord(r, cfg){
    const sinkholes = cfg.sinkholes;
    const indicators = cfg.indicators;
    const knownIssuers = cfg.knownIssuers;

    const dns = r.dns || {};
    const tls = r.tls || {};
    const http = r.http || {};

    const ips = []
        .concat(dns.A || [])
        .concat(dns.AAAA || [])
        .filter(Boolean);

    const ns = (dns.NS || []).filter(Boolean);
    const mx = (dns.MX || []).filter(Boolean);
    const cname = (dns.CNAME || "");
    const loc = (http.Location || "");
    const issuer = (tls.Issuer || "");

    const joined = (ns.join(" ") + " " + mx.join(" ") + " " + cname + " " + loc).toLowerCase();

    let score = 0;
    const tags = [];

    // sinkhole IPs
    const hitIp = ips.find(ip => sinkholes.has(ip));
    if(hitIp){ score += 25; tags.push("sinkhole_ip"); }

    // parking/registrar indicators
    let indicatorHit = null;
    for(const ind of indicators){
        if(joined.includes(ind)){ indicatorHit = ind; break; }
    }
    if(indicatorHit){ score += 15; tags.push("parking_indicator:"+indicatorHit); }

    // redirect-to-brand
    if(cfg.baseRegistrable){
        const locHost = (loc||"").toLowerCase();
        if(locHost.includes(cfg.baseRegistrable)){
            score += 12; tags.push("redirect_to_brand");
        } else if(cfg.brandToken && locHost.includes(cfg.brandToken)){
            score += 12; tags.push("redirect_to_brand_token");
        }
    }

    // HTTP behavior
    const sc = Number(http.StatusCode||0);
    if(http.Attempted){
        if([301,302,303,307,308].includes(sc)){
            score += 10; tags.push("redirect");
        } else if(sc===200){
            score += 8; tags.push("http_200");
        } else if(sc===405){
            score += 4; tags.push("http_405");
        } else if(sc>=400 && sc<500){
            score += 1; tags.push("http_4xx");
        }
    }

    // email surface
    if(r.resolvable && (dns.HasMX || (mx.length>0))){
        score += 8; tags.push("has_mx");
    }

    // TLS issuer heuristics
    if(tls.Connected){
        const issuerLower = issuer.toLowerCase();
        const isKnown = Array.from(knownIssuers).some(k => issuerLower.includes(k));
        if(!isKnown){
            score += 8; tags.push("tls_unfamiliar_issuer");
        } else {
            tags.push("tls_known_issuer");
        }
        const ent = shannonEntropy(issuer);
        const entPoints = Math.min(8, Math.round(ent));
        score += entPoints;
        tags.push("tls_entropy:"+ent.toFixed(2));
    } else if(r.resolvable) {
        // resolvable but no TLS: still might be parking/phish; minor bump
        score += 2; tags.push("no_tls");
    }

    return {score, tags};
}

function scoreClass(score){
    if(score>=45) return "bad";
    if(score>=25) return "warn";
    return "good";
}

function safe(x){ return (x===null || x===undefined) ? "" : String(x); }

function escapeHtml(s){
    return String(s)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}
function escapeAttr(s){
    return escapeHtml(s).replaceAll("`","&#096;");
}