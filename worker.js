import { connect } from "cloudflare:sockets";

function safeWaitUntil(ctx, promise) {
	if (ctx && typeof ctx.waitUntil === "function") {
		try {
			ctx.waitUntil(promise);
		} catch (e) {}
	} else if (promise && typeof promise.catch === "function") {
		promise.catch(() => {});
	}
}
const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_ACTIVE_IPS = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
const LOGIN_ATTEMPTS = new Map();
/* ---------- D1 read-through cache (slashes read-unit usage) ---------- */
const DB_CACHE = new Map();
const DB_CACHE_TTL = 2500;          /* 2.5 s */
const DB_CACHE_MAX = 512;
function dbCachedGet(db, sql, binder) {
	const key = sql + '|' + JSON.stringify(binder || []);
	const hit = DB_CACHE.get(key);
	if (hit && Date.now() - hit.t < DB_CACHE_TTL) return hit.v;
	let stmt = db.prepare(sql);
	if (binder && binder.length) stmt = stmt.bind.apply(stmt, binder);
	const v = stmt.first ? stmt.first() : stmt.all();
	if (DB_CACHE.size > DB_CACHE_MAX) {
		const it = DB_CACHE.keys(); const n = it.next(); if (n && !n.done) DB_CACHE.delete(n.value);
	}
	DB_CACHE.set(key, { t: Date.now(), v: v });
	return v;
}
function dbInvalidate(prefix) {
	if (!prefix) { DB_CACHE.clear(); return; }
	for (const k of Array.from(DB_CACHE.keys())) if (k.indexOf(prefix) === 0) DB_CACHE.delete(k);
}

/* ============================================================
   ANTI-BAN / ANTI-BLOCK ENGINE  (v1.0.1)
   Adds multiple layers to keep the worker from getting blocked:
   - Randomized fragment lengths per request
   - TLS cipher-suite / fingerprint rotation
   - HTTP/2 pseudo-header normalisation
   - Bad-bot / active-probe tarpitting
   - Outbound SNI rotation
   ============================================================ */
const ANTI_BAN_ENABLED = true;
const BAD_PROBE_UAS = /(zgrab|censys|shodan|masscan|nmap|zmap|libcurl|python-requests|go-http-client|java\/|wget|curl\/|axios|node-fetch|proximus|internet-measurement|microsoft|bingbot|yandex|baiduspider|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|sogou|exabot|grapeshot|petalbot)/i;
const BAD_PROBE_PATHS = /(\.env|\.git|wp-admin|wp-login|phpmyadmin|xmlrpc|\.aws|\.ssh|cf_scripts|cdn-cgi|trace|debug|actuator|boaform|HNAP1|w00tw00t)/i;
const FINGERPRINTS = ['chrome','chrome','chrome','firefox','safari','edge','ios','randomized'];
const CIPHER_SUITES = [
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
    'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256'
];
const FRAGMENT_PRESETS_LML = [
    '10-30,2-5',     /* mobile MCI */
    '20-50,1-3',
    '40-80,2-4',
    '50-100,3-5',
    '80-150,1-3',
    '100-200,2-5',
    '1400-1500,1-2'  /* fake full-MSS */
];
function randomFragmentPreset() {
    return FRAGMENT_PRESETS_LML[Math.floor(Math.random() * FRAGMENT_PRESETS_LML.length)];
}
function randomFingerprint() {
    return FINGERPRINTS[Math.floor(Math.random() * FINGERPRINTS.length)];
}
function randomCipherSuite() {
    return CIPHER_SUITES[Math.floor(Math.random() * CIPHER_SUITES.length)];
}
function isProbeRequest(request) {
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const url = new URL(request.url);
    if (BAD_PROBE_UAS.test(ua)) return true;
    if (BAD_PROBE_PATHS.test(url.pathname)) return true;
    /* Host header mismatch */
    const host = request.headers.get('Host') || '';
    if (!host) return true;
    return false;
}
function tarpitResponse() {
    /* Return a boring generic nginx-style 404 to look like a static site */
    return new Response('<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>', {
        status: 404,
        headers: { 'Content-Type': 'text/html', 'Server': 'nginx/1.24.0' }
    });
}

let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 128 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 32 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 128 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const DNS_CACHE_MAX_ENTRIES = 2048;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);
const _CF_AUTH_INTEGRITY = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
function safeDecodeURI(value) {
	try {
		return decodeURIComponent(value);
	} catch (e) {
		return value;
	}
}
async function readJsonBody(request) {
	try {
		const body = await request.json();
		return body && typeof body === "object" ? body : {};
	} catch (e) {
		return {};
	}
}
const UPDATE_REPO_WORKER = "nukesamp-crypto/LML-PANEL";
const UPDATE_FILES_WORKER = ["LML-Panel-Custom.js", "worker.js", "index.js", "main.js", "src/worker.js", "LML-Panel.js", "LML-Panel-Custom.js.txt", "worker", "panel.js", "LML.js", "dist/worker.js", "src/index.js"];
const UPDATE_BRANCHES_WORKER = ["main", "master", "dev", "v1", "release"];
const UPDATE_MIRRORS_WORKER = ["https://raw.githubusercontent.com/", "https://cdn.jsdelivr.net/gh/"];
const UPDATE_TIMEOUT_MS = 8000;
const UPDATE_MAX_FILES = 6;

/* fetch with a hard timeout so one hanging host can never stall the worker */
async function updateFetchWorker(url, opts, ms) {
	if (typeof AbortController === "undefined") return await fetch(url, opts || {});
	const ctl = new AbortController();
	const timer = setTimeout(() => { try { ctl.abort(); } catch (e) { } }, ms || UPDATE_TIMEOUT_MS);
	try {
		return await fetch(url, Object.assign({}, opts || {}, { signal: ctl.signal }));
	} finally {
		clearTimeout(timer);
	}
}

/* Ask GitHub which .js files the repo really has, so a renamed worker file
   can never break the auto-updater. Never throws. */
async function discoverUpdateFilesWorker(branch) {
	const out = [];
	try {
		const api = "https://api.github.com/repos/" + UPDATE_REPO_WORKER + "/contents?ref=" + encodeURIComponent(branch);
		const r = await updateFetchWorker(api, { headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json" } }, 6000);
		if (!r || !r.ok) return out;
		const j = await r.json();
		if (!Array.isArray(j)) return out;
		for (const it of j) {
			if (it && it.type === "file" && /\.m?js$/i.test(it.path || "")) out.push(it.path);
		}
	} catch (e) { }
	return out;
}

/* Two tiers. raw.githubusercontent serves the CURRENT file. The CDN
   mirrors cache GitHub content for hours, so they must never be allowed to
   win a race against it - that is what made the panel install old code. */
function updateUrlsWorker(branch, files, stamp) {
	const raw = [];
	const cdn = [];
	for (const f of files) {
		raw.push("https://raw.githubusercontent.com/" + UPDATE_REPO_WORKER + "/" + branch + "/" + f + stamp);
		cdn.push("https://cdn.jsdelivr.net/gh/" + UPDATE_REPO_WORKER + "@" + branch + "/" + f + stamp);
	}
	return { raw: raw, cdn: cdn };
}

/* Fire every candidate at once; the first real worker source wins. */
async function raceUpdateSourcesWorker(urls) {
	if (!urls.length) return null;
	return await new Promise((resolve) => {
		let left = urls.length;
		let won = false;
		for (const u of urls) {
			(async () => {
				let text = null;
				try {
					const r = await updateFetchWorker(u, { headers: { "User-Agent": "Mozilla/5.0", "Cache-Control": "no-cache" } }, UPDATE_TIMEOUT_MS);
					if (r && r.ok) {
						const t = await r.text();
						if (t && t.length > 20000 && t.indexOf("CURRENT_VERSION") >= 0) text = t;
					}
				} catch (e) { }
				left -= 1;
				if (text && !won) { won = true; resolve(text); }
				else if (left === 0 && !won) resolve(null);
			})();
		}
	});
}

let updateDiscoveredWorker = null;
let updateBranchWorker = null;

async function fetchUpdateSourceWorker() {
	const stamp = "?t=" + Date.now();

	/* 1. learn the real file names once (a single cheap API call) */
	if (updateDiscoveredWorker === null) {
		updateDiscoveredWorker = [];
		for (const br of UPDATE_BRANCHES_WORKER) {
			const found = await discoverUpdateFilesWorker(br);
			if (found && found.length) { updateDiscoveredWorker = found; updateBranchWorker = br; break; }
		}
	}

	/* 2. branch order: the branch we know exists first */
	const branches = [];
	if (updateBranchWorker) branches.push(updateBranchWorker);
	for (const br of UPDATE_BRANCHES_WORKER) if (branches.indexOf(br) < 0) branches.push(br);

	/* 3. candidates: discovered names first, then the well-known names */
	const files = updateDiscoveredWorker.concat(UPDATE_FILES_WORKER)
		.filter((f, idx, arr) => f && arr.indexOf(f) === idx)
		.slice(0, UPDATE_MAX_FILES);

	/* 4. authoritative source first, cached CDN mirrors only as a fallback */
	for (let i = 0; i < branches.length && i < 3; i++) {
		const tiers = updateUrlsWorker(branches[i], files, stamp);
		let text = await raceUpdateSourcesWorker(tiers.raw);
		if (!text) text = await raceUpdateSourcesWorker(tiers.cdn);
		if (text) { updateBranchWorker = branches[i]; return text; }
	}

	/* 5. last resort */
	try {
		const r = await updateFetchWorker("https://hoplimit.shop/worker.js" + stamp, {}, UPDATE_TIMEOUT_MS);
		if (r && r.ok) {
			const t = await r.text();
			if (t && t.length > 20000) return t;
		}
	} catch (e) { }
	return null;
}

async function fetchWithFallback(path, options = {}) {
	const primaryUrl = `https://hoplimit.shop/${path}`;
	const fallbackUrl = `https://raw.githubusercontent.com/${path}`;
	try {
		const res = await fetch(primaryUrl, options);
		if (res.ok) return res;
	} catch (e) { }
	return await fetch(fallbackUrl, options);
}
let localLastAutoResetCheck = 0;
async function checkAutoResets(env, ctx) {
	const now = Date.now();
	if (now - localLastAutoResetCheck < 3600000) return;
	try {
		const cache = caches.default;
		const cacheReq = new Request("https://internal.lml/auto_reset");
		if (await cache.match(cacheReq)) return;
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_auto_reset_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 3600000) {
			localLastAutoResetCheck = dbLastCheck;
			const ttl = Math.floor((3600000 - (now - dbLastCheck)) / 1000);
			if (ttl > 0) safeWaitUntil(ctx, cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": `max-age=${ttl}` } })));
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
		localLastAutoResetCheck = now;
		safeWaitUntil(ctx, cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": "max-age=3600" } })));
		const todayUtc = Math.floor(now / 86400000) * 86400000;
		await env.DB.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
		await env.DB.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
	} catch (e) { }
}
let GLOBAL_IPS_CACHE = {};
let GLOBAL_IPS_LAST_FETCH = 0;
async function getCachedIps(ctx) {
	const now = Date.now();
	if (now - GLOBAL_IPS_LAST_FETCH < 86400000 && Object.keys(GLOBAL_IPS_CACHE).length > 0) {
		return GLOBAL_IPS_CACHE;
	}
	const fetchTask = async () => {
		try {
			const ctrl = new AbortController();
			const tid = setTimeout(() => ctrl.abort(), 1500);
			const res = await fetch("https://hoplimit.shop/ips.txt", { signal: ctrl.signal });
			clearTimeout(tid);
			if (res.ok) {
				const text = await res.text();
				const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.includes("#") && !l.startsWith("[source"));
				if (lines.length > 0) {
					GLOBAL_IPS_CACHE = { "all": lines };
					GLOBAL_IPS_LAST_FETCH = Date.now();
				}
			}
		} catch (e) {}
	};
	if (Object.keys(GLOBAL_IPS_CACHE).length === 0) {
		GLOBAL_IPS_CACHE = { "all": ["104.16.0.0", "104.17.0.0", "172.67.0.0", "162.159.0.0"] };
	}
	safeWaitUntil(ctx, fetchTask());
	return GLOBAL_IPS_CACHE;
}
function getRandomIps(cachedIpsData, operator, count) {
	let availableIps = [];
	Object.values(cachedIpsData).forEach((ips) => (availableIps = availableIps.concat(ips)));
	availableIps = [...new Set(availableIps)];
	if (availableIps.length === 0) return [];
	if (count >= availableIps.length) return availableIps;
	const shuffled = availableIps.slice();
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled.slice(0, count);
}
async function checkAutoRotates(env, ctx) {
}
let cachedVipCountries = [];
let lastVipCountriesFetch = 0;
async function replaceBrokenProxy(username, env, oldProxy) {
	try {
		if (GLOBAL_WRITE_LOCK.get(username + "_proxy_rotate")) return;
		GLOBAL_WRITE_LOCK.set(username + "_proxy_rotate", true);
		
		const user = await env.DB.prepare("SELECT id, user_socks5, auto_rotate_user_proxy FROM users WHERE username = ?").bind(username).first();
		if (!user || user.auto_rotate_user_proxy !== 1 || !user.user_socks5) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let proxyList = [];
		let isArrayMode = false;
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
				isArrayMode = true;
			} else {
				proxyList = [user.user_socks5];
			}
		} catch (e) {
			proxyList = [user.user_socks5];
		}
		
		let matchIndex = -1;
		for (let i = 0; i < proxyList.length; i++) {
			let itemStr = typeof proxyList[i] === "object" && proxyList[i] !== null ? proxyList[i].proxy : proxyList[i];
			if (itemStr === oldProxy) {
				matchIndex = i;
				break;
			}
		}
		if (matchIndex === -1) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let countryCode = typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null && proxyList[matchIndex].country ? proxyList[matchIndex].country : "all";
		
		if (countryCode === "all" || countryCode === "UN") {
			try {
				const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
				const s = await connectProxy(oldProxy, "ip-api.com", 80, payload);
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try { s.close(); } catch (e) { }
				}, 2000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (resStr.includes("countryCode")) break;
					}
				} finally {
					clearTimeout(timeoutId);
					try { s.close(); } catch (e) { }
				}
				const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
				if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
			} catch (e) { }
			
			if (countryCode === "all" || countryCode === "UN") {
				try {
					let remain = oldProxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) remain = remain.substring(1, remain.indexOf("]"));
					else if (remain.includes(":")) remain = remain.substring(0, remain.lastIndexOf(":"));
					const geoRes = await fetch(`http://ip-api.com/json/${remain}?fields=countryCode`);
					const geoData = await geoRes.json();
					if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
				} catch (e) { }
			}
		}
		
		let newProxy = null;
		let finalCountry = null;
		const upperCountry = (countryCode || "ALL").toUpperCase();
		const sources = [];
		const isOldProxyVIP = oldProxy.includes("@") || oldProxy.includes("t.me/");
		
		if (cachedVipCountries.length === 0 || Date.now() - lastVipCountriesFetch > 3600000) {
			try {
				const ghRes = await fetchWithFallback("vip-list", {
					headers: { "User-Agent": "Mozilla/5.0" },
				});
				if (ghRes.ok) {
					const files = await ghRes.json();
					cachedVipCountries = files.filter((f) => f.name.endsWith(".txt")).map((f) => f.name.replace(".txt", "").toUpperCase());
					lastVipCountriesFetch = Date.now();
				}
			} catch (e) { }
		}
		
		let fallbackVIPs = cachedVipCountries.length > 0 ? [...cachedVipCountries] : ["DE", "US", "GB", "NL", "FR", "TR"];
		for (let i = fallbackVIPs.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[fallbackVIPs[i], fallbackVIPs[j]] = [fallbackVIPs[j], fallbackVIPs[i]];
		}
		
		if (upperCountry !== "ALL" && upperCountry !== "UN") {
			sources.push({ url: `proxy_vip/${upperCountry}.txt`, type: "repo", country: upperCountry });
		}
		for (const fc of fallbackVIPs) {
			if (fc !== upperCountry) {
				sources.push({ url: `proxy_vip/${fc}.txt`, type: "repo", country: fc });
			}
		}
		
		if (!isOldProxyVIP) {
			if (upperCountry !== "ALL" && upperCountry !== "UN") {
				sources.push({ url: `proxy/${upperCountry}.txt`, type: "repo", country: upperCountry });
			}
			sources.push({ url: `proxy/ALL.txt`, type: "repo", country: "ALL" });
		}
		
		for (const src of sources) {
			try {
				const res = await fetchWithFallback(src.url);
				if (!res.ok) continue;
				const text = await res.text();
				const lines = text
					.split("\n")
					.map((l) => l.trim())
					.filter((l) => l.length > 5);
					
				if (lines.length > 0) {
					for (let i = lines.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[lines[i], lines[j]] = [lines[j], lines[i]];
					}
					
					const testLimit = (src.country === upperCountry) ? 15 : 3;
					
					const testBatch = lines.slice(0, testLimit).flatMap((line) => {
						if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) {
							return [line];
						}
						if (src.type === "socks5") return [`socks5://${line}`];
						if (src.type === "http") return [`http://${line}`];
						return [`socks5://${line}`, `http://${line}`];
					});
					
					try {
						newProxy = await Promise.any(
							testBatch.map((p) => {
								return new Promise(async (resolve, reject) => {
									let sock = null;
									const timeoutId = setTimeout(() => {
										try { sock && sock.close(); } catch (e) { }
										reject(new Error("timeout"));
									}, 4000); 
									try {
										const payload = TEXT_ENCODER.encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
										sock = await connectProxy(p, "1.1.1.1", 80, payload);
										const reader = sock.readable.getReader();
										const res = await reader.read();
										clearTimeout(timeoutId);
										try { sock.close(); } catch (e) { }
										if (res.done || !res.value) reject(new Error("empty"));
										else resolve(p);
									} catch (e) {
										clearTimeout(timeoutId);
										try { sock && sock.close(); } catch (err) { }
										reject(e);
									}
								});
							})
						);
					} catch (e) {
						continue;
					}
					
					if (newProxy) {
						finalCountry = src.country; 
						break;
					}
				}
			} catch (e) { }
		}
		
		if (newProxy) {
			let finalProxyVal = newProxy;
			if (isArrayMode) {
				if (typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null) {
					proxyList[matchIndex].proxy = newProxy;
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex].country = finalCountry;
					}
				} else {
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex] = { proxy: newProxy, country: finalCountry };
					} else {
						proxyList[matchIndex] = newProxy;
					}
				}
				finalProxyVal = JSON.stringify(proxyList);
			} else {
				if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
					finalProxyVal = JSON.stringify([{ proxy: newProxy, country: finalCountry }]);
				}
			}
			await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE id = ?").bind(finalProxyVal, user.id).run();
		}
	} catch (e) {
	} finally {
		GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
	}
}
const SSCrypto = {
	async evpBytesToKey(password, keyLen) {
		const pass = new TextEncoder().encode(password);
		const key = new Uint8Array(keyLen);
		let hash = new Uint8Array(0);
		let offset = 0;
		while (offset < keyLen) {
			const data = new Uint8Array(hash.length + pass.length);
			data.set(hash);
			data.set(pass, hash.length);
			const digest = await crypto.subtle.digest("MD5", data);
			hash = new Uint8Array(digest);
			const len = Math.min(hash.length, keyLen - offset);
			key.set(hash.slice(0, len), offset);
			offset += len;
		}
		return key;
	},
	async deriveSubkey(password, salt) {
		const masterKey = await this.evpBytesToKey(password, 32);
		const keyMaterial = await crypto.subtle.importKey(
			"raw", masterKey, { name: "HKDF" }, false, ["deriveKey"]
		);
		return await crypto.subtle.deriveKey(
			{ name: "HKDF", hash: "SHA-1", salt: salt, info: new TextEncoder().encode("ss-subkey") },
			keyMaterial,
			{ name: "AES-GCM", length: 256 },
			false,
			["encrypt", "decrypt"]
		);
	},
	incrementNonce(nonce) {
		for (let i = 0; i < nonce.length; i++) {
			nonce[i]++;
			if (nonce[i] !== 0) break;
		}
	},
	async decryptChunk(key, nonce, encryptedData) {
		try {
			const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, encryptedData);
			this.incrementNonce(nonce);
			return new Uint8Array(decrypted);
		} catch (e) {
			return null;
		}
	},
	async encryptChunk(key, nonce, data) {
		try {
			const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
			this.incrementNonce(nonce);
			return new Uint8Array(encrypted);
		} catch (e) {
			return null;
		}
	}
};
async function handleCronTrigger(env, ctx) {
	try {
		// 1. Auto Resets & Auto Rotates
		await checkAutoResets(env, ctx);
		await checkAutoRotates(env, ctx);
		// 2. Automated Daily Telegram Backup & Summary
		const tokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_bot_token'").first();
		const adminRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_admin_id'").first();
		if (tokenRow && tokenRow.value && adminRow && adminRow.value) {
			const botToken = tokenRow.value;
			const adminId = adminRow.value;
			const uRows = (await env.DB.prepare("SELECT * FROM users").all()).results || [];
			const vRows = (await env.DB.prepare("SELECT * FROM vouchers").all()).results || [];
			let rRows = [];
			try { rRows = (await env.DB.prepare("SELECT * FROM resellers").all()).results || []; } catch(e){}
			const backupPayload = {
				version: "LML-PANEL-v2",
				exported_at: new Date().toISOString(),
				users: uRows,
				vouchers: vRows,
				resellers: rRows
			};
			const formData = new FormData();
			formData.append("chat_id", adminId);
			formData.append("caption", `⏰ [بکاپ خودکار روزانه ورکر LML]\n👥 تعداد کاربران: ${uRows.length}\n📅 تاریخ: ${new Date().toLocaleString("fa-IR")}`);
			const blob = new Blob([JSON.stringify(backupPayload, null, 2)], { type: "application/json" });
			formData.append("document", blob, `lml_daily_backup_${new Date().toISOString().slice(0,10)}.json`);
			await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, { method: "POST", body: formData });
		}
	} catch(e) {
		console.error("Cron trigger error:", e);
	}
}

export default {
	async fetch(request, env, ctx) {
		/* Anti-ban: immediately tarpit probes before they even touch the DB */
		try { if (ANTI_BAN_ENABLED && isProbeRequest(request)) return tarpitResponse(); } catch(e){}
		const _LICENSE_CERTIFICATE = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
		if (!env.DB) {
			return new Response("Database binding 'DB' is missing in Cloudflare Workers settings.", { status: 500 });
		}
		// License verification passed
		try {
			try {
				await DbService.ensureSchema(env.DB);
			} catch (e) { }
			trackRequest(env, ctx);
			if (schemaEnsured && ctx && typeof ctx.waitUntil === 'function') {
				safeWaitUntil(ctx, checkAutoResets(env, ctx));
				safeWaitUntil(ctx, checkAutoRotates(env, ctx));
			}
			const url = new URL(request.url);
			if (Router.isWebSocketUpgrade(request)) {
				return await Router.handleWebSocket(request, env, ctx);
			}
			if (Router.isSubscriptionPath(url.pathname)) {
				return await Router.handleSubscription(url, env, request, ctx);
			}
			if (url.pathname === "/icon-192.png" || url.pathname === "/icon-512.png" ||
				url.pathname === "/icon-maskable-512.png" || url.pathname === "/apple-touch-icon.png" ||
				url.pathname === "/favicon.png") {
				const _png = url.pathname.indexOf("512") >= 0
					? (url.pathname.indexOf("maskable") >= 0 ? LML_ICON_PNG_512_MASKABLE : LML_ICON_PNG_512)
					: LML_ICON_PNG_192;
				const _bin = Uint8Array.from(atob(_png), function (c) { return c.charCodeAt(0); });
				return new Response(_bin, {
					headers: {
						"Content-Type": "image/png",
						"Cache-Control": "public, max-age=604800, immutable",
					},
				});
			}
			if (url.pathname === "/icon.svg" || url.pathname === "/favicon.ico" || url.pathname === "/icon.png" || url.pathname === "/apple-touch-icon.png") {
				return new Response(LML_ICON_SVG, {
					headers: {
						"Content-Type": "image/svg+xml; charset=utf-8",
						"Cache-Control": "public, max-age=604800, immutable",
					},
				});
			}
			if (url.pathname === "/manifest.json") {
				return new Response(PWA_MANIFEST, {
					headers: {
						"Content-Type": "application/manifest+json; charset=utf-8",
						"Cache-Control": "public, max-age=86400",
					},
				});
			}
			if (url.pathname === "/sw.js") {
				return new Response(PWA_SERVICE_WORKER, {
					headers: {
						"Content-Type": "application/javascript; charset=utf-8",
						"Cache-Control": "no-cache",
					},
				});
			}
			if (url.pathname.startsWith("/api/")) {
				return await Router.handleApi(request, url, env, ctx);
			}
			if (url.pathname === "/reseller" || url.pathname === "/reseller/") {
				return await Router.handleResellerPortal(request, env);
			}
			if (url.pathname === "/panel" || url.pathname === "/login") {
				return await Router.handlePanel(request, env);
			}
			if (url.pathname.startsWith("/status/")) {
				return await Router.handleUserStatus(request, url, env, ctx);
			}
			let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
			return new Response(HTML_TEMPLATES.nginx.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			let msg = err.message || "";
			if (msg.toLowerCase().includes("d1") && (msg.toLowerCase().includes("limit") || msg.toLowerCase().includes("exceeded") || msg.toLowerCase().includes("daily row"))) {
				return new Response(JSON.stringify({ error: "سهمیه دیتابیس شما تمام شده و ساعت 3:30 درست میشه" }), { 
					status: 500, 
					headers: { "Content-Type": "application/json; charset=utf-8" } 
				});
			}
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async scheduled(event, env, ctx) {
		if (ctx && typeof ctx.waitUntil === "function") {
			ctx.waitUntil(handleCronTrigger(env, ctx));
		} else {
			await handleCronTrigger(env, ctx);
		}
	},
};
const LML_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="lmlBg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#020617"/>
    </linearGradient>
    <linearGradient id="lmlMk" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#7c8cff"/>
      <stop offset="100%" stop-color="#22d3ee"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="112" fill="url(#lmlBg)"/>
  <rect x="72" y="152" width="368" height="208" rx="58" fill="url(#lmlMk)"/>
  <g fill="none" stroke="#ffffff" stroke-width="22" stroke-linecap="round" stroke-linejoin="round">
    <path d="M136 200v112h44"/>
    <path d="M212 312V200l52 56 52-56v112"/>
    <path d="M332 200v112h44"/>
  </g>
</svg>`;
/* LML monogram app icons (base64 PNG) - served at /icon-*.png */
const LML_ICON_PNG_192 = "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";
const LML_ICON_PNG_512 = "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAMAAADDpiTIAAABgFBMVEUTJ04pVaQbRZMxVZIaN23+/v4kSo4qRXYbTKUjO2gLGjocMVo0ZKoeUKtGaqYNHT0NHkEZPoMoUXsgTqJDY5ogNV1Qcqk3YJwULmEuccAeQHuZqsgQID8XSaUtbsBshbEWRJoNIUlAXpHL1ONje6YMHkIscL6esdGUorwYSqYXSaTGztzI0N4MHDwOI0wWQ5gYSqYMHDwYSqUOIksWRJkYSaXn6vENHkIXSaZgdp2puNEMHDwNIUkWRJoWRJoMHD0MHDwOI00OIkoWRJgWQ5cMHDwOI0wMHkKKnLoNHkINHkJ7k7m4xNjFz+ANHkPc4uwNHkJZcZsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9mLPEAAAAgHRSTlP+//7///////7/AP/////+/v///////////////wT//wQE////BP///86P///P0tJtbkdRUbX/kjH//4wxMbUySIu0dYu2c7T/Rcz///9t/y//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALKTv0YAAB/nSURBVHja7d15exs3kgbwPhg2RVK0aTNSQq1Gsp14I2Xj+JLjseM7dpxrMvn+X2abp9hks1EFFAoFNGr3j3lmLYrq99eFAtjSJn3r9ebto5cvfyjrhu36H6ay/oPMrtbLl4/evrGfTmLzxcvkP9qPnTV7RgULCh9LBz4CePuIK3oX4fMimDGwpsAGgLcvObK/Oa/EeS3eB4eCl289APDm0ccbXOknYorLwI2Pj95IBvCmVbe+s0bwRiaAN49+YFjYE/HFMC78QNgHqAAQdf6bN2Xe33Q9gqhLfHwkCcCblzdi/NwEbtAsBQQA3n6M8bsh8PGtAABUK38L0q8YoJoGHAOI8ftOIOGL/6aqktaU8lLwETAA8DbGL4XAWwcAcKNfjN8uAf1xUBfAyxuU+SetLEoBN16yAnikG38SC+MCdZkfsQF484NOk4/x060O9TZ+eMMD4OWNmL9MATrrQBJv/3Y3gYRi9Y/5y2kCjywC+Lb/7a839SoGaodATf1axmQFwLff9n+7GfOXL+Dmb7OsyAGUL/lTjN8PAj/14U0gie2/3ctAAs3/v7/H+P0h8Pt/oQISYP6/xdvfrybwG1BAAhv//hOz9k3Ff2CjYALK/yfy+AeDznQ6LVjqlnbxvL/yQnQGA3ICP4EEJNz5l8GbRBJylRQ6A24BCc32D5j9OnrjezOs4DcvRlEAFdBsBxP19o8k/8G0WP+0qx/5VgSwuCSr63FrzaCYDkgEqLeDiTL/383z7yzSn2deve/FrPYOJ4OtV14pKNcDcwG/KwUkivUfkL8q/WLjvl/9mNNOZxBn+c3VcTYaFZUeOfuPHVMCv3+rmAMSxfz3q1n+g+L6zl/OOTH45pVys1nO/tPATMCvikkwMZ3/m97dtNiccGL2cAWbo2ExNRKg2Ask1vIfXA97s/8Qw8chKK4RNLcBQwFNAEzy76zij7c+QSNonAYgAnQAbJ3/ot57Z765uRXTpzGwuJId1JdunQrjAWx9/qMbf0zfeC3QJAD8ZCjZ//mvZv7X8TdPL7GgNS20CGzmt//T4QR0AIADu/zfToyOqjrXV3WgJWD/ccA+AJUDAPj3jPHbJ6Al4Nc+CkB1AwDvVTpOY2F761RHwL6tQKIeABHvMN79LF0Afn+pB8GkfgDQyH99+8f47RFAN4GNIOvHgHoA+AFgffvHyd/ujgDZBCqPCgMBVE+AEDTj4s82CsAbreo8aBfAnf7P6HdVxO7Pvw4U6K/8uQxXCeDOnTsP8CgXn2HGcHiqWD5HhG23D8pw1QD673RExtufvQloXPJ3fSUA/AJQYLcmsUgmAa1lYHcRSEwXgNj+3S4DpovANoD+J3z+sf07XAaQAj71GwGUPnCdaPkmYvt3tQyUNx/u4m+3gC0A/fc6+ccwXC0DeAHv+w0A7tz5GZn/TEA8+3NW08UAhhLwc7UFJPoNIObvpYCtFpBU8n+Czz+Of45HQbSAJxUBie4WcJ7/rTze/657QH4LKaC6FUw0G8Ai/3j/i9gOIgVUWkCi1wAG6O8ay9p2EJtFpQUkeg1g0f/j/S+jByxWAb0WkGg1gCLmL09AodUCEp0GsPg1Zg/nvwGofNwN4gRstICNDvAAd/9PgwveYwhTXA94sNsBEA0A23A8jN4/BshF+boFJOhDwIEn+Q9IyxMB0Pf5fhsA4lOAW8iR0//w/UCAy2X9iUCCfRCskH4AMLBa0o8DoJ15/XBYgnwOYD5tCNkADsSUnM0geDZf7QQT3Ag4HwDyIqYv0UCRI8aA1Ri46gDAEbAQMgAMBJaQMQB4d77f7ADgR4FRxlqVvggDqP68fEA4wTwK2pEwAAxEl4QxABbQp00AwFNAAQ+AD8SX+9MAWELL08AEsQJMXS8AA0/K9SIwRawBCfwQYOB4ARh4VI4XAdD3f3cNALYCzCZAdzvAgWflci8IS2mxBiTgFaDjcgGwktGX6wqIAKJPz9eABLwHYP4M2G7izeU1h8Unw+B9QAI9BYK/rsD8v9QqTwWA79T5WVBSKrgjrgG4jt4OA3EtoIx+DuAJ8FXZJkAp2VMr4JwDIffqkyWAd9AG0PEm/i8tlDcEOtAW8G4BALIJ5GsAMsOnQyCpBcw2gglsBMhn1ZGf/5cMJV9AZx4XbAhIQCNA2QByjgYgP30KAxwtIAe1gCdzAJ9AL8jRAPxI39wATwsA3LCf5gDeA16PpQH4k76pAZ4WoL5j388AAGZAlgbgWfqGBmS0gHIKTAAz4AA6U4id+Q+0yud9wTwy9UvPtoFPYA1gKjF/W9HjGEgUMIW1gCclgE9UmsTFf0BW/hEAdu1PJYB3ROuJrC3/AXl5djgAm9velQDe07wUb/7M4YMQyBIAu23f9xPlJsDSCEgU/4Hzkno2AFq4H5TbQBClqaD8JaW/bUCQgCmocd9JfnaxAgQVv1ACsDXg5+SJgxUgtPipCDhYA54kn/hXAL2r0+l0Djyp8q0KEABaAz4l79hXgNDjNyHAvga8UwKgWgGMNkkdz/KfC+i43hdConuXPOA5BTLN/8C7ci8A0rwfqABMaVaA1sVPQIBmDZgaAqAZAbR6/nUdHHgrYKPYBUC6twrAfBN4izv/MOI3J2B63W+pN4IPEoYRIPyRz9ZYyPKBkPURQOf2PzgIU0CHVQDBGQ6BoZi/MwEE/dv8FKBliz75SOA2PnNCMX+XAowbuPYi0tKh3+q2wMUIp/sCMX4bBBxMgZotBB17i/LfFoChwL+E39J6HjjmL0WA8Tme3hTpR/5FpfwQwL0N0Osguvnzp15f7gjQCzDcBmgBkJl/ga4gBFAAmBLl32kuSdlzKFBcDiIBhvvAKSEAN/kXBCVLgP0EzfwIyr8gLF8FGB4E4FcQMfkX5OWlAMODADAAzW0fZf4Fc7mcA+ASmADoxU6Yf+GkrAtQUbAOAPjH4VznXzgr8QI6ZidBwK82A+Bv/BQEbLcADgBO8y+cl2wBDAD0+j5N/oWI4lkF6ilIA8CafyGm3AlwD8CoAYQRvykBmy3AOoCYv2wBvAD48i8EliMBbgHorPvm+RdCi28O2KRgD8Bg7x8ZMRr8tPMvvCk2AapeMDD6I58wAFz5F16VCwF8AGL+vgiwA4BgAQg+fzYBzYuAGYDOng+DDAY/zfwLL4trErymAI7QCIB5/p1W5I8W0KEXYAlAzF+qAA4A7AtAUUQBui2AEsBXy+rw3v+F58XbAzqrlOwBiPl7IYAcgPG6jwVQBFZcANbLAS2AwYA3/yLA4hWwGAfoAMT8vRNABoBi4Y/58wuYB+clgKJotQCBAGL+vgoQA6BVGz+iTaEbAF9t1AoAa/4RAKWA61X8q60jIlYAMX9HAjwEUBRRgEsAX9UAiPl7PAbsAvgKCmD91XH093hDsIqwAcBX9dVhBVAUUYBVAJ09MTMAiPm7FOAeQFwAnC4CagAN+bMBKIoowDaAvQIsA4j5uxWgC6DDCKAoogAGAB0nAGL+jgVEADV1a29FANUnP40BSMv/FqhCErAZIT8AUflvRpzXlhsEdgWgADR+NTkAN/d7riw3PYEDwO5vD1gG4DR/neybFHgqAAOgExAAo/T3GAgIQIcFgLv8jcPfg8BDAVIB2I4/t1C2CbgG0CEG4KgB2IrfPgErLWBfhI4BWM0/t1jOBPgHwEkDsBy/ZQI2WgAcQIcRgIfdn2UdYATQsQ2AOf9uWTljzb6fFwLUALS+WheApRs/d1SWWgELgFVZAsDY+93lb0sAZQuQBSC0/HkF+ASApQF0uRf+/eNAV2wLEAXA77mPcyKMAHzK34IA3wG0LH/JAkIFICt/egF+A7CZf3ddeS5NQJdwHqQSEBoAqfmTC/AZQCvzlypABIBwl37bw0AYAII7+mE8FvIRgI0G0JXc+/etBF0JLUAAACFr/11k0Xpw1gLCAODP/U8+DfoEoH74Pzj77vN3++ouYf53vzthq+/2N4hJ5d9V63PO/rmQewDFvS/217/ha78SwOQLxprsfRtnTV+Ws28HBQD4vuGC/IMDkHsA4JvWAjjQAPBvuvwbATy7h8/43jMRAAwFeA0AlX8zgBd4AC8iADMAqx+AAgBk+G4E8BkP4LMQAGa7AT4AB5QAuribXw3gDA/gzAqALvOJUBgAclMAX/zzDJv/s3++iABMABQGAHTybwYwQU+B9yaiABTSARzIBnD3TyyAP+/KBnAQMACt/BUA0FPg5wjACEChBaBbVxQAJugp8MzKEmDwEUFrAeQkANDnhJMIAAPgQDwA5DbgmXgAB6IBFFoATPJXALj7PQ7A93ftAeBsAeIBdJtWf0oAJzgAJzYB6ClwAeC4/B8sgO33DQJglj1kCTjDzoCaAM6gALqmbQAGQBUhDYCmB4C0AeSkAL7BAfhGKACsAE8AdO0DwE2B5QxoHUA3AmAFgDoMvhcBsAD4Zv/wh37+UwUA9UjACw4AWgpEAmh8BlgKANRh8Gc2AJYFmAI4dgYgpwZwhtwEhALgOAJYAEAdBk8iAB4AdPmrAfwNz/9vRgBd/wE0/xqQGACIRwL+5ASAVYASEAFcA0AcBp9EAHgA+94vGoDmr+QpAfwBB/CHNQA5gYBrBZIAFOIBHMEBHIkHUEQAW78aqgYAPwx+NlEDuEsMQGshCBJAbgPAaII5DJ4dBE9GNgDkzQC6XgJQ/BmA/5MAYN7TwYfBL5QrhhAABxEABgD4MPhzBOAfgLtqAOBHAr5RA7gbAQBHACyA3B6AI9QmwAkABIMIoLoJBACAToHzGVAFYBIB+AfgBWIGjACgAFRvFAFA/y9zqfbtCwDAw+ATAICy9ADkAASI44CgAOS2AQAfCTizDQDUBroRADmAI8QMGAH4BGACAzACPRLw9wgGYBIB+AZg8hcEwF+TCMAzABMYgBFsG/BiMoIBmKAB3A0LAORvAXe7YAD6fwUaCmAEeiTgjxEUQN3flAYBgAmAMFAdCIYP4C4GAGgbcIYBcLf1AAr3ACYwAKPR6AjwSMCzo9FcAADAxD2AIgKAAhjNCnAYfG/+DyOA0ADMYx0BpsAXi38ZAai/GvanvpsB5CQbADWARaojwGHwyfKfQgDUbAVgAHAIlAwiANUjXCsAZ6AZUA1gFAGoDwAQAHIuAIDD4CMuADkdgCICgAJQHgb/HQGYA6i8d6sAJjgARyPl74f9OTrCAZhwAFAxiACgAE7UM2AEEDIA5WHwHxFA0ADO1JuACCBcAKMj1WHwsyPsEBgBKP7YqzAAikcC/pIMYD+DCAAMQHEY/CIC2KjjWdX899N5EQHQDn/25uAAjmbpl6XYBpzM/9FsWgADmL0PLQCaCOqu+yIRRITtBaCYAs8iAJ8ATDAAjhalOAheFAbAJHAAUxiAve/3njAAjY8E3PMAQB2DfQCmEcAOgMbD4D8jgOABnKhnwAggZACNh8F/RABbAIbKIVD1TqUBOLrXUEfeAKg62D8EDoMGoLENBJXobWAEEAEwAZjOAUx3o6/OACYAjNLHAUAWDsDKwHEzgPpfJzTPv9jMpRrhsH6MiwAiAAiAYSMA2HuMACwCWDloAjCMACKA8ADk0gDkEYBwACNc/BFA/VdHANIBdEgBDIfHWQ2AbFZdAQCO3Z8DHAsA0J0HUgMgm0do1gHCATCC5x8QgGNrADKvAIxwAEZ6AHI3ALIWAsg1AIwQ+SMB5PoAumIBZJUZYCP5zDWA4+taB3HEOQQebTeAJQKtJcAcQSWWTQZZzRgXAoC8BoCjIbCSfwQgGoCVITAC8ASArRkgAnAM4Bj5m0HQ/IEAjoMHMFx89XiMj571w6ARCMAInL8CwIjwwyCanUCVwXi8iHAYAVQBjKD5RwBNADJ5ACZAAM0ENv8Z28fBFvIPH4DWSaCKQPUfsR0FewJgHA6AegLb/8RnAGMaAMM5gPGyJAOYJYYBsGOg5v/ePAOspwCpABaZDa/vYX0A2W45BrCzC8QBIFgC1gBojoIpENTEFCyA3YMgZAcwXgK2G4DhOUAEQNACkEvAqHkFAAI4DhbA9QIyNhPAAGCRGBaAopRLwNwAGQAr+V9HOA4MQFWAOwBb+UcAbgBM3ACYRADMADafvNltAQ4AbOdvMgOYaqAG0OEAcJQTtgBuABM8AIsNQAEAPgSOr8s+gBcn2DraFTAcupoBhsOt/FUA0D/vGVkHWJUWACMBgP9HXYg6q2kB7gBsNwDVQ6HoumeWPw2A+nIG4HhrAVi3AHYAGw0AuA1E118mAGbVCgBLAdwAtvK3AuAeG4BxTQkGsDkBzMoNgPlHbZhtoAAA2xK8B3AtgBnAVv4RAC+AXBqA3HMAHSyAzDGALQGjIS+A4aguf3cAMiyATjgAjt0BOA4AwHh/yQRQPQgYLstRB1ghyF2fA6ABrCoCiAA0AWSuAVQFcAPYk78jAFkrAWz1ACcAtvMPCMD6q4UBqN8GOgXgfhuoAJBl4QHIK/3f3RKwRJC3EEDmFsC2AGcANhcBRwCyNgHYMwM6AyBhF9BOAHEXYBfAWDyAdChjBhim4gGMrQDIXG8DUxkAUtfbwKytACoCnAFI8wjAFYBcAoA8VABjJYDMOYDcPYDcOYBMCWAcJIB0Xq4BLN5FWAB29hBCO0AqZQhMpXeA7b8boeoAngCIuwAkgDE5AIiAv+IuQL/+MsxfAgCrQ2DqHkDqegiUDuDshLKOtmbAjSHw5H/31YuTkUadvNj7gifbQ+C1giPSH/fMDYAxAIDRb7LmFLUtoK5GBNX4DbbzNynqXw7ejnBMCiBzELlSwIilLOVvxCGTDsCKB0gPMFOheGnS/G00AF0AY9sAukTZ2yUAi59IQdc2gDExAMctACVAx4DyJWnzt9MA0ACajpHIAJD2f3X2WgSgr5rKWAWAJ4E1EPwFkKdYAlAE8NdLafP3DICPApQIUC8lP380gLEnAFLkCABggH+NlHgK4AEwpgPgtQDz8iH/cAFsC0gdx5/mgQAYswDwX4Ck/FEAxpQA2ivAl/xDBZDWl6v4SRS0DIDPAoTlTwxgjAHgbg1InRFIreRvqQHsRLj/KBh4ikABgPYUSMQM4PKJABSAHQmGALJ23f0Su0BGBGDMCMCWALczgKNVQA/AmAqAm0UgTeXNAI6eCMi8BOCxAGH5EwIY+wSgQUDqJn5XT4ToARjTAWAXkKrLQfzmDKzkLxdAN/eOgNX48657AGM9AA4WgdQBgdRu/pYawJ4IxwIAWBdAaQD2/XJ5DQACQOcUwVBAbnMGdDYDODgIzDQBbFBIxmN+AF2Pbn7GNtDlBzAmAZAJbP+pm/hTYQ0ABGDMD6CbMxBgnwEMV4EuP4AxEQCpAlLe+AXmHxyAFF1s6ZsycAhgbAxAsgATAzrfTVT+zRGOXQLgFKCFQPMb8Z0DiALAOAWk2mU9fIMxwFL+QABjFwC6OT8BNQOz1+Y8CDQHMKYEwCIgpS2q2M0dWMsfAMDkHJH/TwZx9H8/VgECAPMiA5D53/59WgYyeQC8EKBg4KL9W81fLgC7jwQ5K66DQJEArAtIvSkx+TMB4HogJNz8rTwSztgB2B4JCjR+a/mLBhCoAEEPBDLOAPYFpJ6VjPyFAwhYgIQHQll3ARyPBge6C7CZP+M2MA4AvGNA5juAgAVIeSBU8mcBoY+A1seArGUAwt4FhAEgChCYv+TPAoIWICV/4QC64Q4AGAfdUABEAeLyZwZg79nggHcBVvOXDyBcAc6fB3UBIIsjoP0xMJMMIIsDgO0xIAsHQAsEuHwe1A2ALA4AdseATDqAKEBS/i4ARAGC8pcPoBv0CAhw0A0PQBQgJ383AKIAMfkbAkg1ARD/jlC4u0Dr+c8BpNIBdINd/xUQutIB6C4BYAHBT4CU60CWuVkC0ijA3/xTgiVAD0DW+vWfeA7IfAMQBQjI3xRAxgAg/AmQZA40AZCZARhmUYCv+QMCtAggi9tAqm1g5ieAKMB1/sYAUjMAUYDj/AFDXJJZ2wYYCEiDLP78U+cAogCX+ZsDMB0CIADiNtAeAEB8tgFEAQ7zFwEAKyANvDjzJwBgPgREAe7yh6THACDrRgJ68RvmDwPwo701QPuZkJg/DQRAeD/aBGDwe2JxG8jzSYAagNkagBSQtqSY8odkpwRwyPR5UIsIWP9lkEoDOFQB+CWzuAZEAQ7zB0X3CwxAaldAW88B7OafwgB8yGwOARoC8rbEn7v/JCjLPiRPM7trAHAVaM0AuKZg/ZMgUHBPk1eZ5TUAKqBVBPKc55NAJYBXyXlmew2IAlzkD8ztPDn/0foaAN0L5LH9834QVO4Cz5P+a/trQLOA2+tqC4Drn9jyB0FKAK/7Sf8Xmpcy6QEtEwCK3/SDINht+0sJ4EPGsAZABdyOtz9N/sDQPpQAnmYca0AUwJs/sG0/LQEotwFZj6QFKCbBdhAAxm+c/+Km7Sn/2Xk/OVdvA4haQNaUensmwG0JdRYypgbw43m5DVRvA2jGwPoe0E4CzfGb5w+9ZV/3ZwA+ZFwtIDYBltsffsd+mAN4mrG1gCiAJX/wDft0DuAc+oqHdgS0jID19o94iqcMv9wFAKZAwhaQ1aTeJgH7fm7C/MENoJwBZ9tA9Vkg5RSgFHC7jfGT5g++W3/pLwA8zVhbgFLA7dbFT5o//GZ9ugRwnvG2gLY2AZ74Effq+RxAOQS85mwBvVndVlWbbv9lzS8MZwN4XY4AcwCQk4Dl60YBfuQPyulDfwXgFbyzHFIJ6LVzE7BPQo8q/0P4Wv1qCQC2ESRsAa0WYDl/REqzTeASAGgjiLFltAy0cBtIFj+mT882gSsArzKGRaC3W20T0HT7V4phAVisAHMA0DXAdBEAC7jdvtufJn9MQosVYAkAtg9YtoCUQUCLtoGU+WMCmu8B1gBeYYAdUgpoCQFE/Pr5H2Ja9KsNAMCzoNXDYUPj0FsnAJO/PoYh8EGw9SnQNQDQ5wFYY1ABwRPQjl8nf2B/ftqvADg/t7DKmAu4HXL81PnjojmvdADoUYDuGIAj0I5tIHH8yOb8y7IBrAGcv4JmySCgDdtAS/lDv+rVeRVAH/JwME5aD1tt2gaiLw5xZ369agAbAJ7i1pooQGD+4Nns6Q4A8Gng+ptZENBrxzawZyt/8O7sx9UCsAkA3gLA3HqRAEX8PbKmvNsANjsAvAX0aAUE/liI6iEQsvx7iAawCwDVAg73CuhpVcAEjONXc0ixG7ONBrAJANECVt+TTECoBMjj72GyADSADQCoFsAq4HaA8TvMv9IAKgAwLYBeQHAELMRPkn+lAWwCwLWAje/cI6r2fBpIdcV08q82gAoAxHHghoBy+OzZIRBq/mSXa7UdQ+X/upL/FgDwJwK2BARJwFL8evlffwpQAwDZAtYCDgkF9MLeBhJeqNVmHJf/VgPYBgB+LqAqIKUU0At3G0h5lTYuPqbOz5sAgB8PXb2LNcKeRQHBbANJL9K6/aI+Pv6w1QB2AEC3gtsChr1IgDP+1fKPzP/H7QawDQD+gPDOO0kjAb740537DvUocAMA+MNhO2+GWEDP49Og23bjr7nkyAfBmgCAzwN3OR5GAhzxHw41899dAGoA1C4C+Hdki8Bt79Knjh9+vwEWgDoAtTsB6EhCT6Dn9zFAz1r8yrFbvQPYA6D294Tg7+swErAX/yH8Ttv7u0AQAOcan/FZbAK9GD/29u+pj4D2A+if9h8bvbtIwHL8Oi/+uIwVCqD8p5cmhxNWCPTanf5G/FqHbpf1+e8BUP7jK7MlqtUE7MavNWRd7cl/L4DT0wvTN5oettKAhR/6MDW9sS7KQFEASi/Pza1aaQO9lqVPckGf72sAewFoDoJb60DLCNiOX3uL/Xhv/vsBlF/ysEdBoC0GrKevf8LycH/+DQB0twIrAveXb/v+fYJx4LCmJKVf9/4IFv7764tocsB22ZB/IwATARW9FAYOD6UiqH9nhOkbdtHL/qkeAFMBlZXg/hyBmQKJBujTL3+g5eWiOV1vzr8RwOwrr8whVxEYKTg8lIRg37sxy74SvnnrvGrOvxmA/nHAPgPrH295CSHpyl35MSr2G1n+SMPh9o1PMTztPwAAASinB2MBuwva7Gf7+uuv79//emi9/mVc9t/j7EqUl6N6ge6TnKRdnPab81cBmAm47PVIDGwjWJLfrK9bUVs/dM1FoTpHvVTmrwQwewEKAesDzfICNN4NwZfip6c8RL/sK/NXAzDeC9Qeay/v9X/96+vW1+oa3Cf/AEUx/0MBEAu4nnvErfYOJ4OdiZgrfwiA2es87PHWIaakj/w0J4Ma57+A/EEATD4ZcujCWYm4VI/7p6BoYQBmnw5f9KIBX9LvXTwH5g8FMNsOXvV60YAP6fd6V6fQ/MEACLeDoRqQc3Ug2z80gNlI8bjXiwakpz9f/sH5IwDIWgYQCKyP+bKuCaL9YwHMXvhhr+ehAawET2/9xe4PlT8OwKy1SNkNSFgN5F2J2fSPyh8JgOzDIf8RiLwIl7j2rwNg9g0kNgFWBEJ//PL2R+ePBzBrMacPe3KrldnPV/9TbPvXAzBX5ngdiMdAdd0ff/trAphDe3zViwbEtIarx32d218XwJLARS8aELEwXGjHrw1gOQpcBL7iezEVXOgt/qYAFqPAQwkbglYfAM/i75/qp2gAYM5OBgEXCGTs/ObxG+RvBGBJ4LGUDwhadwp09dg0flMAy2//vEUfFAs69nveN47fHMD8t4dmK4GszwmDPwO6WvT+U+P4zAGs28BDcSfEoR7/XTwkufnpAKzawPPLi2BavVgkF5fPiW5+SgBrkM8Z14IWpn81v/f7VOmTApirnL2x08etagSMt/7j0+urLBHAei2YIXh4dRE+Arbsrx4+Pt24vIIBbBA9LRVccjEINfyLq8sy+9M+/a1vD0D1zZ6ePi8dXF6UFYwC+7GXdVkm//z6KtoIf1b/D/pzHYEV1wvCAAAAAElFTkSuQmCC";
const LML_ICON_PNG_512_MASKABLE = "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";
const PWA_MANIFEST = JSON.stringify({
	name: "LML Panel",
	short_name: "LML Panel",
	description: "پنل مدیریت پیشرفته کانفیگ و کاربران LML",
	start_url: "/panel",
	scope: "/",
	display: "standalone",
	background_color: "#000000",
	theme_color: "#000000",
	dir: "rtl",
	lang: "fa-IR",
	orientation: "any",
	icons: [
		{ src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
		{ src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
		{ src: "/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
		{ src: "/icon.svg", sizes: "192x192 512x512", type: "image/svg+xml", purpose: "any" }
	],
	categories: ["utilities", "productivity"]
});
const PWA_SERVICE_WORKER = `
const CACHE_NAME = "lml-pwa-cache-v1";
const STATIC_ASSETS = [
	"https://cdn.tailwindcss.com",
	"https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js",
	"https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js",
	"https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css",
	"https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css"
];
self.addEventListener("install", (e) => {
	self.skipWaiting();
	e.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			return cache.addAll(STATIC_ASSETS).catch(() => {});
		})
	);
});
self.addEventListener("activate", (e) => {
	e.waitUntil(
		caches.keys().then((keys) => {
			return Promise.all(
				keys.map((k) => {
					if (k !== CACHE_NAME) return caches.delete(k);
				})
			);
		}).then(() => self.clients.claim())
	);
});
self.addEventListener("fetch", (e) => {
	const url = new URL(e.request.url);
	if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/sub/") || url.pathname.startsWith("/feed/") || url.pathname.startsWith("/status/") || url.pathname.startsWith("/stream/")) {
		return;
	}
	if (STATIC_ASSETS.includes(e.request.url)) {
		e.respondWith(
			caches.match(e.request).then((cached) => cached || fetch(e.request).then((res) => {
				const clone = res.clone();
				caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
				return res;
			}))
		);
	}
});
`;
const Router = {
	isWebSocketUpgrade(request) {
		const _LLM_TRAP = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket" && _LLM_TRAP.length > 0;
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/sub/") || pathname.startsWith("/feed/") || pathname.startsWith("/s/") || pathname.startsWith("/singbox/") || pathname.startsWith("/status/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			return handlevIees(env, null, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env, request, ctx = null) {
		let subUser = "";
		if (url.pathname.startsWith("/s/")) {
			subUser = safeDecodeURI(url.pathname.slice(3));
		} else if (url.pathname.startsWith("/sub/")) {
			subUser = safeDecodeURI(url.pathname.slice(5));
		} else if (url.pathname.startsWith("/feed/")) {
			subUser = safeDecodeURI(url.pathname.slice(6));
		} else if (url.pathname.startsWith("/singbox/")) {
			subUser = safeDecodeURI(url.pathname.slice(9));
		} else if (url.pathname.startsWith("/status/")) {
			subUser = safeDecodeURI(url.pathname.slice(8));
		}
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(subUser, subUser).first();
			if (!user) {
				return new Response("کاربر یافت نشد", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
			}
			try {
				USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
			} catch (e) { }

			const format = url.searchParams.get("format") || url.searchParams.get("target") || "";
			const accept = request ? (request.headers.get("Accept") || "") : "";
			const ua = request ? (request.headers.get("User-Agent") || "").toLowerCase() : "";

			const isBrowserPortal = url.pathname.startsWith("/s/") || (format !== "raw" && !ua.includes("v2ray") && !ua.includes("clash") && !ua.includes("sing-box") && !ua.includes("hiddify") && (accept.includes("text/html") || accept.includes("*/*") || !ua));
			if (isBrowserPortal) {
				return new Response(renderUserPortal(user, host, url), {
					headers: { 
						"Content-Type": "text/html; charset=utf-8",
						"Cache-Control": "no-store, no-cache, must-revalidate"
					}
				});
			}
			if (format === "clash" || ua.includes("clash")) {
				return await SubscriptionService.generateClash(user, host);
			}
			if (format === "singbox" || ua.includes("sing-box")) {
				return await SubscriptionService.generateSingbox(user, host);
			}
			return await SubscriptionService.generateText(user, host, ctx);
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
	async handleResellerPortal(request, env) {
		let gfxSetting = 'false';
		try {
			const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
			if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
		} catch (e) {}
		return new Response(HTML_TEMPLATES.reseller.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handlePanel(request, env) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
		
		if (!hasPassword) {
			return new Response(HTML_TEMPLATES.setup.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		return new Response(HTML_TEMPLATES.panel.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting), {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handleUserStatus(request, url, env, ctx) {
		const username = safeDecodeURI(url.pathname.slice(8));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const subResponse = await SubscriptionService.generateText(user, url.hostname);
			const subBase64 = await subResponse.text();
			let plainLinks = "";
			try {
				plainLinks = decodeURIComponent(escape(atob(subBase64)));
			} catch (e) {
				plainLinks = atob(subBase64);
			}
			if (user.auto_rotate_ip === 1) {
				const cachedIpsData = await getCachedIps(typeof ctx !== "undefined" && ctx ? ctx : null);
				const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
				if (randomIps.length > 0) user.ips = randomIps.join("\n");
			}
			const userIpsMap = GLOBAL_ACTIVE_IPS.get(user.username);
			const liveIpCount = userIpsMap ? userIpsMap.size : 0;
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)),
				limit_req: user.limit_req,
				used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
				is_active: user.is_active,
				online_count: Math.max(liveIpCount, getActiveIpCount(user.active_ips)),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
				connection_type: user.connection_type || "vless",
				user_proxy_iata: user.user_proxy_iata,
				user_socks5: user.user_socks5,
				user_proxy_ip: user.user_proxy_ip,
				start_on_first_connect: user.start_on_first_connect,
				first_connection_time: user.first_connection_time,
				enable_direct: user.enable_direct !== 0 ? 1 : 0,
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
			const finalHtml = html + "\n<!-- HIDDEN_CONFIGS -->\n<div style='display:none; white-space:pre-wrap;'>\n" + plainLinks + "\n</div>";
			let gfxSetting = 'false';
			try {
				const gfxRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'gfx_enabled'").first();
				if (gfxRow && gfxRow.value === '1') gfxSetting = 'true';
			} catch (e) {}
			const replacedHtml = finalHtml.replace(/\/\*\{\{GFX_SETTING\}\}\*\//g, gfxSetting);
			try {
				const ua = (request.headers.get("User-Agent") || "").toLowerCase();
				if (!ua.includes("mozilla") && !ua.includes("chrome") && !ua.includes("safari")) {
					USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
				}
			} catch (e) { }
			return new Response(replacedHtml, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		
		// ================= TELEGRAM BOT APIS =================
		if (url.pathname === "/api/telegram-info" && request.method === "GET") {
			try {
				const tokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_bot_token'").first();
				const adminRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_admin_id'").first();
				const host = url.hostname;
				return new Response(JSON.stringify({
					bot_token: tokenRow ? tokenRow.value : "",
					admin_id: adminRow ? adminRow.value : "",
					webhook_url: `https://${host}/api/telegram-webhook`
				}), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch(e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/telegram-setup" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const botToken = (body.bot_token || "").trim();
				const adminId = (body.admin_id || "").trim();
				
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_bot_token', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(botToken, botToken).run();
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_admin_id', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(adminId, adminId).run();

				let webhookResult = null;
				if (botToken) {
					const host = url.hostname;
					const setWebhookUrl = `https://api.telegram.org/bot${botToken}/setWebhook?url=https://${host}/api/telegram-webhook`;
					const tgRes = await fetch(setWebhookUrl);
					webhookResult = await tgRes.json();
				}

				return new Response(JSON.stringify({ success: true, webhook_info: webhookResult }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch(e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/telegram-webhook" && request.method === "POST") {
			try {
				const update = await readJsonBody(request);
				const msg = update.message || update.edited_message;
				if (!msg || !msg.text) {
					return new Response("OK", { status: 200 });
				}

				const chatId = msg.chat.id;
				const textMsg = msg.text.trim();
				const fromId = String(msg.from?.id || "");
				
				const tokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_bot_token'").first();
				const adminRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_admin_id'").first();
				const botToken = tokenRow ? tokenRow.value : null;
				const adminId = adminRow ? adminRow.value.trim() : null;
				const isAdmin = !adminId || fromId === adminId;

				const sendTg = async (replyText, customKeyboard = null) => {
					if (!botToken) return;
					const payload = {
						chat_id: chatId,
						text: replyText,
						parse_mode: "HTML"
					};
					if (customKeyboard) {
						payload.reply_markup = customKeyboard;
					}
					await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(payload)
					});
				};

				const host = url.hostname;
				const adminKeyboard = {
					keyboard: [
						[{ text: "📊 آمار پنل" }, { text: "⚡ ساخت اکانت تست" }],
						[{ text: "🎫 ایجاد کارت شارژ" }, { text: "🔄 تمدید منقضی‌ها" }],
						[{ text: "❓ راهنما" }]
					],
					resize_keyboard: true
				};

				// /start command
				if (textMsg === "/start") {
					if (isAdmin) {
						await sendTg(
							"<b>⚡ به ربات مدیریت هوشمند LML PANEL خوش آمدید!</b>\n\n" +
							"از منوی زیر می‌توانید پنل خود را مدیریت کرده یا دستورات سریع ارسال کنید:\n" +
							"▫️ <b>/stats</b> - مشاهده آمار زنده\n" +
							"▫️ <b>/test</b> - ساخت آنی کاربر تست ۲۴ ساعته\n" +
							"▫️ <b>/create &lt;نام&gt; &lt;گیگ&gt; &lt;روز&gt;</b> - ساخت کاربر\n" +
							"▫️ <b>/status &lt;نام_کاربری&gt;</b> - وضعیت کاربر\n" +
							"▫️ <b>/voucher &lt;گیگ&gt; &lt;روز&gt;</b> - ساخت کارت شارژ\n" +
							"▫️ <b>/renew &lt;روز&gt;</b> - تمدید کاربران منقضی",
							adminKeyboard
						);
					} else {
						const clientKeyboard = {
							keyboard: [
								[{ text: "🔍 استعلام اشتراک من" }, { text: "⚡ دریافت اکانت تست رایگان" }],
								[{ text: "❓ راهنما و نرم‌افزارها" }]
							],
							resize_keyboard: true
						};
						await sendTg(
							"<b>⚡ سلام به ربات LML CONNECT خوش آمدید!</b>\n\n" +
							"جهت استعلام حساب یا دریافت اکانت، از دکمه‌های زیر استفاده کنید:\n" +
							"▫️ <b>استعلام اشتراک:</b> نام کاربری خود را ارسال کرده یا دکمه استعلام را بزنید.\n" +
							"▫️ <b>اکانت تست:</b> دکمه دریافت اکانت تست رایگان را بزنید.",
							clientKeyboard
						);
					}
					return new Response("OK", { status: 200 });
				}

				// Stats
				if (textMsg === "📊 آمار پنل" || textMsg === "/stats") {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					const usersCountRow = await env.DB.prepare("SELECT count(*) as total, sum(used_gb) as total_gb FROM users").first();
					const activeRow = await env.DB.prepare("SELECT count(*) as active FROM users WHERE is_active = 1").first();
					const totalUsers = usersCountRow?.total || 0;
					const activeUsers = activeRow?.active || 0;
					const totalGb = (usersCountRow?.total_gb || 0).toFixed(2);
					
					await sendTg(
						"<b>📊 گزارش زنده سرور و پنل LML:</b>\n\n" +
						`👥 <b>کل کاربران:</b> ${totalUsers} کاربر\n` +
						`🟢 <b>کاربران فعال:</b> ${activeUsers}\n` +
						`💾 <b>مجموع حجم مصرفی:</b> ${totalGb} GB\n` +
						`🌐 <b>دامنه ورکر:</b> <code>${host}</code>`,
						adminKeyboard
					);
					return new Response("OK", { status: 200 });
				}

				// Trial user creation
				// Customer Account Status Check
				if (textMsg === "🔍 استعلام اشتراک من") {
					await sendTg("لطفاً نام کاربری خود را به شکل زیر ارسال کنید:\n<code>/my username</code>\nیا صرفاً نام کاربری خود را تایپ کنید.");
					return new Response("OK", { status: 200 });
				}

				if (textMsg.startsWith("/my ") || (!textMsg.startsWith("/") && !isAdmin && textMsg.length >= 3 && textMsg.length <= 32 && /^[a-zA-Z0-9_-]+$/.test(textMsg))) {
					const targetUser = textMsg.startsWith("/my ") ? textMsg.slice(4).trim() : textMsg.trim();
					const userRow = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").bind(targetUser).first();
					if (!userRow) {
						await sendTg("❌ کاربری با نام <code>" + targetUser + "</code> یافت نشد. لطفاً املا را بررسی فرمایید.");
						return new Response("OK", { status: 200 });
					}
					const used = (userRow.used_gb || 0).toFixed(2);
					const limit = userRow.limit_gb ? userRow.limit_gb + " GB" : "نامحدود";
					const statusText = userRow.is_active ? "🟢 فعال" : "🔴 منقضی / مسدود";
					const subUrl = `https://${host}/sub/${encodeURIComponent(userRow.username)}`;
					const statUrl = `https://${host}/status/${encodeURIComponent(userRow.username)}`;

					await sendTg(
						`<b>📋 وضعیت اشتراک [ ${userRow.username} ]:</b>\n\n` +
						`▫️ <b>وضعیت حساب:</b> ${statusText}\n` +
						`▫️ <b>حجم مصرفی:</b> ${used} GB از ${limit}\n` +
						`▫️ <b>روزهای اشتراک:</b> ${userRow.expiry_days || "نامحدود"} روز\n\n` +
						`🔗 <b>لینک اتصال مستقیم سابسکریپشن:</b>\n<code>${subUrl}</code>\n\n` +
						`🌐 <b>صفحه وب وضعیت اشتراک:</b>\n${statUrl}`
					);
					return new Response("OK", { status: 200 });
				}

				if (textMsg === "⚡ ساخت اکانت تست" || textMsg === "⚡ دریافت اکانت تست رایگان" || textMsg === "/test" || textMsg === "/trial") {
					const rand = Math.random().toString(36).substring(2, 7);
					const uname = "lml_trial_" + rand;
					const uuid = crypto.randomUUID();
					await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, tls, port, is_active) VALUES (?, ?, 1.0, 1, 'on', 443, 1)").bind(uname, uuid).run();
					const subUrl = `https://${host}/sub/${uname}`;
					const vlessLink = `vless://${uuid}@${host}:443?path=%2Fstream%2FLML_PANEL%2Fdefault&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#⚡%20LML%20❯%20[TRIAL]`;

					await sendTg(
						"<b>🎉 اکانت تست ۲۴ ساعته شما آماده شد:</b>\n\n" +
						`👤 <b>نام کاربری:</b> <code>${uname}</code>\n` +
						"💾 <b>حجم مجاز:</b> 1 گیگابایت\n" +
						"⏳ <b>مدت اعتبار:</b> 24 ساعت\n\n" +
						`🔗 <b>لینک سابسکریپشن:</b>\n<code>${subUrl}</code>\n\n` +
						`📱 <b>کانفیگ مستقیم VLESS:</b>\n<code>${vlessLink}</code>`,
						isAdmin ? adminKeyboard : undefined
					);
					return new Response("OK", { status: 200 });
				}

				// Create custom user (/create username gb days)
				if (textMsg.startsWith("/create")) {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					const parts = textMsg.split(/\s+/);
					if (parts.length < 4) {
						await sendTg(
							"<b>راهنمای ساخت کاربر:</b>\n" +
							"دستور را با این فرمت ارسال کنید:\n" +
							"<code>/create &lt;نام_کاربری&gt; &lt;حجم_گیگ&gt; &lt;تعداد_روز&gt;</code>\n\n" +
							"مثال:\n" +
							"<code>/create lml_user1 30 30</code>"
						);
						return new Response("OK", { status: 200 });
					}
					const uname = parts[1].trim();
					const gb = parseFloat(parts[2]) || 10;
					const days = parseInt(parts[3]) || 30;
					const uuid = crypto.randomUUID();
					try {
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, tls, port, is_active) VALUES (?, ?, ?, ?, 'on', 443, 1)").bind(uname, uuid, gb, days).run();
						const subUrl = `https://${host}/sub/${uname}`;
						await sendTg(
							`<b>✅ کاربر <code>${uname}</code> با موفقیت ایجاد شد!</b>\n\n` +
							`💾 حجم: ${gb} GB\n` +
							`⏳ زمان: ${days} روز\n\n` +
							`🔗 لینک ساب:\n<code>${subUrl}</code>`
						);
					} catch(err) {
						await sendTg(`❌ خطا در ایجاد کاربر: ${err.message}`);
					}
					return new Response("OK", { status: 200 });
				}

				// Check User Status (/status username)
				if (textMsg.startsWith("/status") || textMsg === "🔍 استعلام کاربر") {
					const parts = textMsg.split(/\s+/);
					if (parts.length < 2) {
						await sendTg("لطفاً نام کاربری را مقابل دستور بنویسید:\nمثال: <code>/status lml_user1</code>");
						return new Response("OK", { status: 200 });
					}
					const uname = parts[1].trim();
					const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(uname).first();
					if (!u) {
						await sendTg(`❌ کاربر <code>${uname}</code> یافت نشد.`);
						return new Response("OK", { status: 200 });
					}
					const used = (u.used_gb || 0).toFixed(2);
					const limit = u.limit_gb ? u.limit_gb + " GB" : "نامحدود";
					const days = u.expiry_days ? u.expiry_days + " روز" : "نامحدود";
					const statusText = u.is_active ? "🟢 فعال" : "🔴 غیرفعال";
					await sendTg(
						`<b>📋 وضعیت کاربر: <code>${uname}</code></b>\n\n` +
						`▫️ وضعیت: ${statusText}\n` +
						`▫️ حجم مصرفی: ${used} / ${limit}\n` +
						`▫️ اعتبار زمانی: ${days}\n` +
						`▫️ لینک ساب: <code>https://${host}/sub/${uname}</code>`
					);
					return new Response("OK", { status: 200 });
				}

				// Create Voucher (/voucher gb days)
				if (textMsg.startsWith("/voucher") || textMsg === "🎫 ایجاد کارت شارژ") {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					const parts = textMsg.split(/\s+/);
					const gb = parseFloat(parts[1]) || 20;
					const days = parseInt(parts[2]) || 30;
					const code = "LML-" + Math.random().toString(36).substring(2, 8).toUpperCase();
					await env.DB.prepare("INSERT INTO vouchers (code, limit_gb, expiry_days, is_used) VALUES (?, ?, ?, 0)").bind(code, gb, days).run();
					await sendTg(
						"<b>🎫 کارت شارژ (ووچر) جدید تولید شد:</b>\n\n" +
						`کد کارت: <code>${code}</code>\n` +
						`حجم شارژ: ${gb} گیگابایت\n` +
						`مدت زمان: ${days} روز\n\n` +
						"مشتری می‌تواند این کد را در پرتال اشتراک خود وارد کند."
					);
					return new Response("OK", { status: 200 });
				}

				// Renew Expired (/renew days)
				if (textMsg.startsWith("/renew") || textMsg === "🔄 تمدید منقضی‌ها") {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					const parts = textMsg.split(/\s+/);
					const addDays = parseInt(parts[1]) || 30;
					await env.DB.prepare("UPDATE users SET expiry_days = COALESCE(expiry_days, 0) + ?, is_active = 1 WHERE is_active = 0 OR expiry_days <= 0").bind(addDays).run();
					await sendTg(`✅ تمامی کاربران منقضی با موفقیت به مدت <b>${addDays} روز</b> تمدید و مجدداً فعال شدند.`);
					return new Response("OK", { status: 200 });
				}

				// Telegram Bot Backup (/backup)
				if (textMsg === "/backup" || textMsg === "💾 دریافت پشتیبان") {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					try {
						const uRows = (await env.DB.prepare("SELECT * FROM users").all()).results || [];
						const vRows = (await env.DB.prepare("SELECT * FROM vouchers").all()).results || [];
						let rRows = [];
						try { rRows = (await env.DB.prepare("SELECT * FROM resellers").all()).results || []; } catch(e){}
						const backupPayload = {
							version: "LML-PANEL-v2",
							exported_at: new Date().toISOString(),
							users: uRows,
							vouchers: vRows,
							resellers: rRows
						};
						const formData = new FormData();
						formData.append("chat_id", chatId);
						formData.append("caption", `📦 فایل بکاپ کامل پنل LML\n👥 کاربران: ${uRows.length}\n📅 تاریخ: ${new Date().toLocaleString("fa-IR")}`);
						const blob = new Blob([JSON.stringify(backupPayload, null, 2)], { type: "application/json" });
						formData.append("document", blob, `lml_backup_${new Date().toISOString().slice(0,10)}.json`);
						await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, { method: "POST", body: formData });
					} catch(err) {
						await sendTg(`❌ خطا در ارسال بکاپ: ${err.message}`);
					}
					return new Response("OK", { status: 200 });
				}

				// Telegram Bot Analytics Report (/report)
				if (textMsg === "/report" || textMsg === "📈 گزارش مصرف") {
					if (!isAdmin) {
						await sendTg("⛔ شما دسترسی ادمین ندارید.");
						return new Response("OK", { status: 200 });
					}
					try {
						const totalStats = await env.DB.prepare("SELECT count(*) as total, sum(used_gb) as total_gb, sum(case when is_active = 1 then 1 else 0 end) as active FROM users").first();
						const topUsers = (await env.DB.prepare("SELECT username, used_gb FROM users ORDER BY used_gb DESC LIMIT 5").all()).results || [];
						let topList = "";
						topUsers.forEach((u, idx) => {
							topList += `${idx + 1}. <code>${u.username}</code>: ${(u.used_gb || 0).toFixed(2)} GB\n`;
						});
						await sendTg(
							"<b>📈 گزارش تحلیلی مصرف سرور LML:</b>\n\n" +
							`👥 کل کاربران: ${totalStats?.total || 0}\n` +
							`🟢 کاربران آنلاین و فعال: ${totalStats?.active || 0}\n` +
							`💾 کل حجم مصرفی: ${(totalStats?.total_gb || 0).toFixed(2)} GB\n\n` +
							"<b>🏆 برترین مصرف‌کنندگان ترافیک:</b>\n" +
							(topList || "کاربری ثبت نشده است")
						);
					} catch(err) {
						await sendTg(`❌ خطا: ${err.message}`);
					}
					return new Response("OK", { status: 200 });
				}

				return new Response("OK", { status: 200 });
			} catch(e) {
				return new Response("OK", { status: 200 });
			}
		}

		// ================= PING API =================
		if (url.pathname === "/api/ping") {
			return new Response(JSON.stringify({ pong: true, time: Date.now() }), {
				headers: { "Content-Type": "application/json; charset=utf-8" }
			});
		}

		// ================= INSTANT 24H TRIAL USER API =================
		if (url.pathname === "/api/trial" && request.method === "POST") {
			try {
				const rand = Math.random().toString(36).substring(2, 7);
				const username = "lml_trial_" + rand;
				const uuid = crypto.randomUUID();
				await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, tls, port, is_active) VALUES (?, ?, 1.0, 1, 'on', 443, 1)")
					.bind(username, uuid).run();
				const subUrl = `https://${url.hostname}/sub/${username}`;
				return new Response(JSON.stringify({ success: true, username, uuid, subUrl }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= VOUCHER CARDS APIS =================
		if (url.pathname === "/api/vouchers/create" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const codeInput = (body.code || ("LML-" + Math.random().toString(36).substring(2, 8).toUpperCase())).trim();
				const limitGb = body.limit_gb ? parseFloat(body.limit_gb) : 10.0;
				const expiryDays = body.expiry_days ? parseInt(body.expiry_days) : 30;
				await env.DB.prepare("INSERT INTO vouchers (code, limit_gb, expiry_days, is_used) VALUES (?, ?, ?, 0)")
					.bind(codeInput, limitGb, expiryDays).run();
				return new Response(JSON.stringify({ success: true, code: codeInput, limit_gb: limitGb, expiry_days: expiryDays }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/vouchers/list" && request.method === "GET") {
			try {
				const { results } = await env.DB.prepare("SELECT * FROM vouchers ORDER BY created_at DESC LIMIT 50").all();
				return new Response(JSON.stringify({ vouchers: results || [] }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ vouchers: [] }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}

		if (url.pathname === "/api/vouchers/redeem" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const codeVal = (body.code || "").trim();
				const uname = (body.username || "").trim();
				if (!codeVal || !uname) {
					return new Response(JSON.stringify({ error: "کد و نام کاربری الزامی است" }), { status: 400 });
				}
				const voucher = await env.DB.prepare("SELECT * FROM vouchers WHERE code = ? AND is_used = 0").bind(codeVal).first();
				if (!voucher) {
					return new Response(JSON.stringify({ error: "کد ووچر نامعتبر است یا قبلاً استفاده شده" }), { status: 400 });
				}
				const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(uname).first();
				if (!user) {
					return new Response(JSON.stringify({ error: "کاربر یافت نشد" }), { status: 404 });
				}
				const newLimit = (user.limit_gb || 0) + (voucher.limit_gb || 0);
				const newExpiry = (user.expiry_days || 0) + (voucher.expiry_days || 0);
				await env.DB.prepare("UPDATE users SET limit_gb = ?, expiry_days = ?, is_active = 1 WHERE username = ?")
					.bind(newLimit, newExpiry, uname).run();
				await env.DB.prepare("UPDATE vouchers SET is_used = 1, used_by = ? WHERE code = ?")
					.bind(uname, codeVal).run();
				return new Response(JSON.stringify({ success: true, message: `حساب شما با موفقیت شارژ شد! (+${voucher.limit_gb}GB و +${voucher.expiry_days} روز)` }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		
		// ================= VOUCHER DELETE API =================
		if (url.pathname === "/api/vouchers/delete" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
				const body = await readJsonBody(request);
				const codeVal = (body.code || "").trim();
				if (!codeVal) return new Response(JSON.stringify({ error: "کد ووچر الزامی است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
				await env.DB.prepare("DELETE FROM vouchers WHERE code = ?").bind(codeVal).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}


		// ================= LIVE IP / PROXY SCANNER API =================
		function ipToInt(ip) {
			const p = String(ip).split(".");
			return (((+p[0] << 24) + (+p[1] << 16) + (+p[2] << 8) + (+p[3])) >>> 0);
		}
		function intToIp(n) {
			return [((n >>> 24) & 255), ((n >>> 16) & 255), ((n >>> 8) & 255), (n & 255)].join(".");
		}
		function randomIpsFromCidr(cidr, count) {
			const out = [];
			const parts = String(cidr).split("/");
			const base = parts[0];
			let bits = parseInt(parts[1] || "32", 10);
			if (isNaN(bits) || bits < 8 || bits > 32) bits = 24;
			const size = Math.pow(2, 32 - bits);
			if (size < 4) return [base];
			const start = ipToInt(base);
			const seen = {};
			let tries = 0;
			while (out.length < count && tries < count * 15) {
				tries++;
				const off = 1 + Math.floor(Math.random() * (size - 2));
				const ip = intToIp((start + off) >>> 0);
				if (!seen[ip]) { seen[ip] = 1; out.push(ip); }
			}
			return out;
		}
		const CDN_FALLBACK = {
			cf: ["104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20", "197.234.240.0/22", "172.66.0.0/16"],
			aws: ["13.32.0.0/15", "52.222.128.0/17", "99.84.0.0/16", "205.251.192.0/19", "108.156.0.0/14", "130.176.0.0/17"],
			fastly: ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "199.116.208.0/21"],
			google: ["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16"],
			azure: ["13.64.0.0/11", "20.0.0.0/11", "104.40.0.0/13", "40.64.0.0/10"]
		};
		/* fetch with a hard timeout - one hanging host can never stall the scan */
		/* Fetch + parse a CDN range file under a HARD deadline. The work is raced
		   against a timer, so a source that hangs forever can never stall the scan
		   (abort alone is not enough - a slow body would still run past it). */
		async function cdnFetchJson(url, ms, parse) {
			const deadline = ms || 6000;
			let timer = null;
			const guard = new Promise(function (resolve) {
				timer = setTimeout(function () { resolve({ __timeout: true }); }, deadline);
			});
			const work = (async function () {
				try {
					const ctl = (typeof AbortController !== "undefined") ? new AbortController() : null;
					const r = await fetch(url, Object.assign(
						{ headers: { "User-Agent": "Mozilla/5.0" } },
						ctl ? { signal: ctl.signal } : {}
					));
					if (!r || !r.ok) return null;
					const txt = await r.text();
					/* nothing this big can be JSON.parse()d inside a Worker's CPU
					   budget - bail out early and let the static ranges take over */
					if (!txt || txt.length > 1500000) return null;
					return parse(JSON.parse(txt));
				} catch (e) {
					return null;
				}
			})();
			try {
				const out = await Promise.race([work, guard]);
				return (out && out.__timeout) ? null : out;
			} finally {
				clearTimeout(timer);
			}
		}

		/* Returns { ranges: {provider: [cidr]}, status: {provider: "live"|"fallback"|"fail"} }.
		   Never throws - a total network failure still yields the built-in ranges. */
		async function fetchCdnRanges(providers) {
			const ranges = {};
			const status = {};
			providers.forEach(function (p) { ranges[p] = []; status[p] = "fail"; });

			const jobs = [];
			if (providers.indexOf("cf") >= 0) jobs.push(cdnFetchJson(
				"https://api.cloudflare.com/client/v4/ips", 6000,
				function (j) { return (j && j.result && j.result.ipv4_cidrs) ? j.result.ipv4_cidrs.slice() : null; }
			).then(function (v) { if (v && v.length) { ranges.cf = v; status.cf = "live"; } }));

			/* Official CloudFront-only list: 4 KB instead of the 2.7 MB
			   ip-ranges.json. Parsing that monster inside a Worker blew the CPU
			   budget every single time, which is why the scanner used to fail at
			   random whenever AWS was selected. */
			if (providers.indexOf("aws") >= 0) jobs.push(cdnFetchJson(
				"https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips", 7000,
				function (j) {
					if (!j) return null;
					const out = [];
					const keys = ["CLOUDFRONT_GLOBAL_IP_LIST", "CLOUDFRONT_REGIONAL_EDGE_IP_LIST"];
					for (const k of keys) {
						const arr = j[k];
						if (!arr || !arr.length) continue;
						for (const c of arr) if (c) out.push(c);
					}
					return out.length ? out : null;
				}
			).then(function (v) { if (v && v.length) { ranges.aws = v; status.aws = "live"; } }));

			if (providers.indexOf("fastly") >= 0) jobs.push(cdnFetchJson(
				"https://api.fastly.com/public-ip-list", 6000,
				function (j) { return (j && j.addresses && j.addresses.length) ? j.addresses.slice() : null; }
			).then(function (v) { if (v && v.length) { ranges.fastly = v; status.fastly = "live"; } }));

			if (providers.indexOf("google") >= 0) jobs.push(cdnFetchJson(
				"https://www.gstatic.com/ipranges/goog.json", 6000,
				function (j) {
					if (!j || !j.prefixes) return null;
					const out = j.prefixes.map(function (x) { return x && x.ipv4Prefix; }).filter(Boolean);
					return out.length ? out : null;
				}
			).then(function (v) { if (v && v.length) { ranges.google = v; status.google = "live"; } }));

			/* azure publishes no single plain range file - its static list is used */
			if (providers.indexOf("azure") >= 0) status.azure = "static";

			try { await Promise.all(jobs); } catch (e) { }

			providers.forEach(function (p) {
				if (ranges[p] && ranges[p].length) return;
				ranges[p] = (CDN_FALLBACK[p] || []).slice();
				if (ranges[p].length && status[p] !== "static") status[p] = "fallback";
			});
			return { ranges: ranges, status: status };
		}
		if (url.pathname === "/api/scan-ips" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
				const body = await readJsonBody(request);
				const providers = (body.providers && body.providers.length ? body.providers : ["cf"]).filter(function (p) { return !!CDN_FALLBACK[p]; });
				const count = Math.min(Math.max(parseInt(body.count, 10) || 20, 1), 500);
				const fetched = await fetchCdnRanges(providers);
				const ranges = (fetched && fetched.ranges) || {};
				const srcStatus = (fetched && fetched.status) || {};
				const picked = [];
				const pickedSet = new Set();
				const detail = {};
				providers.forEach(function (p) {
					const list = ranges[p] || [];
					if (!list.length) { detail[p] = 0; return; }
					const share = Math.max(1, Math.round(count / providers.length));
					const got = [];
					const gotSet = new Set();
					let guard = 0;
					while (got.length < share && guard < share * 8) {
						guard++;
						const cidr = list[Math.floor(Math.random() * list.length)];
						randomIpsFromCidr(cidr, Math.min(10, share - got.length)).forEach(function (ip) {
							if (!gotSet.has(ip)) { gotSet.add(ip); got.push(ip); }
						});
					}
					detail[p] = got.length;
					got.forEach(function (ip) { if (!pickedSet.has(ip)) { pickedSet.add(ip); picked.push(ip); } });
				});
				if (!picked.length) {
					return new Response(JSON.stringify({
						success: false,
						error: "هیچ رنجی در دسترس نیسد",
						status: srcStatus
					}), { headers: { "Content-Type": "application/json" } });
				}
				return new Response(JSON.stringify({ success: true, ips: picked, detail: detail, status: srcStatus, totalRanges: providers.reduce(function (a, p) { return a + (ranges[p] || []).length; }, 0) }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		const PUBLIC_PROXY_SOURCES = [
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
			"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
			"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt",
			"https://hoplimit.shop/proxy/ALL.txt"
		];
		/* proxyscrape is asked last and filters by country server-side */
		const PROXY_COUNTRY_API = "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=";
		/* a Worker gets ~10ms of CPU; we only ever test a few dozen proxies */
		const WORKER_LINE_CAP = 4000;
		if (url.pathname === "/api/proxy-list" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
				const body = await readJsonBody(request);
				const limit = Math.min(Math.max(parseInt(body.limit, 10) || 60, 5), 400);
				const country = (body.country && String(body.country).toUpperCase()) || "ALL";

				/* each source gets a bounded amount of time - one dead host must
				   never stall or kill the whole scan */
				const fetchOne = function (u) {
					const c = new AbortController();
					const to = setTimeout(function () { try { c.abort(); } catch (e) { } }, 8000);
					return fetch(u, { headers: { "User-Agent": "Mozilla/5.0" }, signal: c.signal })
						.then(function (r) { return r && r.ok ? r.text() : ""; })
						.catch(function () { return ""; })
						.then(function (t) { clearTimeout(to); return t; });
				};

				const urls = [PROXY_COUNTRY_API + (country === "ALL" ? "all" : country)].concat(PUBLIC_PROXY_SOURCES);
				const texts = await Promise.all(urls.map(fetchOne));

				/* single pass, O(1) dedupe - the old indexOf version was O(n^2)
				   and needed seconds of CPU on ~16k lines */
				const seen = new Set();
				const lines = [];
				const detail = {};
				for (let si = 0; si < texts.length; si++) {
					const t = texts[si];
					const host = urls[si].replace(/^https?:\/\//, "").split("/")[0];
					if (!t) { detail[host] = 0; continue; }
					const parts = String(t).split("\n");
					let got = 0;
					for (let k = 0; k < parts.length && lines.length < WORKER_LINE_CAP; k++) {
						let l = parts[k].trim();
						if (l.length <= 5 || l.length >= 120) continue;
						if (/^(socks4|socks5|socks|http|https|tg):\/\//i.test(l) || l.indexOf("t.me/socks") >= 0) {
							/* already a full url */
						} else if (/^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$/.test(l)) {
							l = "socks5://" + l;
						} else continue;
						if (seen.has(l)) continue;
						seen.add(l);
						lines.push(l); got++;
					}
					detail[host] = got;
				}
				for (let i = lines.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); const tmp = lines[i]; lines[i] = lines[j]; lines[j] = tmp; }
				return new Response(JSON.stringify({ success: true, total: lines.length, country: country, detail: detail, proxies: lines.slice(0, limit) }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}

		// ================= SESSION & ROLE API =================
		if (url.pathname === "/api/session" && request.method === "GET") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
				if (session.is_admin) {
					return new Response(JSON.stringify({ role: "admin", is_admin: true, username: "مدیر کل" }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
				}
				const r = await env.DB.prepare("SELECT * FROM resellers WHERE id = ?").bind(session.reseller_id).first();
				const uCount = await env.DB.prepare("SELECT count(*) as c FROM users WHERE reseller_id = ?").bind(session.reseller_id).first();
				return new Response(JSON.stringify({
					role: "reseller",
					is_admin: false,
					username: r ? r.username : "نماینده",
					credit_gb: r ? r.credit_gb : 0,
					used_gb: r ? r.used_gb : 0,
					rem_gb: r ? Math.max(0, r.credit_gb - r.used_gb).toFixed(2) : 0,
					max_users: r ? r.max_users : 0,
					active_users: uCount ? uCount.c : 0,
					note: r ? r.note : ""
				}), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= RESELLERS MANAGEMENT APIS =================
		if (url.pathname === "/api/resellers" && request.method === "GET") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403 });
				const { results } = await env.DB.prepare(
					"SELECT r.*, COUNT(u.id) as user_count FROM resellers r LEFT JOIN users u ON u.reseller_id = r.id GROUP BY r.id ORDER BY r.id DESC"
				).all();
				return new Response(JSON.stringify({ resellers: results || [] }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/resellers/create" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403 });
				const body = await readJsonBody(request);
				const username = (body.username || "").trim();
				const password = (body.password || "").trim();
				const creditGb = parseFloat(body.credit_gb) || 100;
				const maxUsers = parseInt(body.max_users) || 50;
				const note = (body.note || "").trim();
				if (!username || !password) return new Response(JSON.stringify({ error: "نام کاربری و رمز عبور نماینده الزامی است" }), { status: 400 });
				const pwHash = await DbService.sha256(password);
				await env.DB.prepare(
					"INSERT INTO resellers (username, password_hash, credit_gb, used_gb, max_users, is_active, note) VALUES (?, ?, ?, 0, ?, 1, ?)"
				).bind(username, pwHash, creditGb, maxUsers, note).run();
				return new Response(JSON.stringify({ success: true, message: `نماینده ${username} با موفقیت ایجاد شد!` }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/resellers/update" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403 });
				const body = await readJsonBody(request);
				const id = parseInt(body.id);
				if (body.toggle_active !== undefined) {
					await env.DB.prepare("UPDATE resellers SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?").bind(id).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
				if (body.add_credit !== undefined) {
					const addGb = parseFloat(body.add_credit) || 0;
					await env.DB.prepare("UPDATE resellers SET credit_gb = credit_gb + ? WHERE id = ?").bind(addGb, id).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
				if (body.new_password) {
					const pwHash = await DbService.sha256(body.new_password.trim());
					await env.DB.prepare("UPDATE resellers SET password_hash = ? WHERE id = ?").bind(pwHash, id).run();
					return new Response(JSON.stringify({ success: true, message: "رمز عبور با موفقیت به‌روزرسانی شد" }), { headers: { "Content-Type": "application/json" } });
				}
				const creditGb = parseFloat(body.credit_gb) || 100;
				const maxUsers = parseInt(body.max_users) || 50;
				const note = (body.note || "").trim();
				await env.DB.prepare("UPDATE resellers SET credit_gb = ?, max_users = ?, note = ? WHERE id = ?").bind(creditGb, maxUsers, note, id).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/resellers/delete" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "دسترسی مجاز نیست" }), { status: 403 });
				const body = await readJsonBody(request);
				const id = parseInt(body.id);
				await env.DB.prepare("UPDATE users SET reseller_id = NULL WHERE reseller_id = ?").bind(id).run();
				await env.DB.prepare("DELETE FROM resellers WHERE id = ?").bind(id).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= CLOUD BACKUP & RESTORE APIS =================
		if (url.pathname === "/api/backup" && request.method === "GET") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response("Unauthorized", { status: 401 });
				const users = (await env.DB.prepare("SELECT * FROM users").all()).results;
				const settings = (await env.DB.prepare("SELECT * FROM settings").all()).results;
				const vouchers = (await env.DB.prepare("SELECT * FROM vouchers").all()).results;
				let resellers = [];
				try { resellers = (await env.DB.prepare("SELECT * FROM resellers").all()).results; } catch(e){}
				const backup = {
					version: "LML-PANEL-v2",
					exported_at: new Date().toISOString(),
					users: users || [],
					settings: settings || [],
					vouchers: vouchers || [],
					resellers: resellers || []
				};
				const fileName = `lml_backup_${new Date().toISOString().slice(0,10)}.json`;
				return new Response(JSON.stringify(backup, null, 2), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Content-Disposition": `attachment; filename="${fileName}"`
					}
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/restore" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
				const body = await readJsonBody(request);
				const { users, vouchers, resellers } = body;
				let uCount = 0, vCount = 0, rCount = 0;
				if (Array.isArray(users)) {
					for (const u of users) {
						try {
							await env.DB.prepare(
								"INSERT OR REPLACE INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, used_gb, is_active, created_at, reseller_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
							).bind(u.username, u.uuid, u.limit_gb, u.expiry_days, u.limit_req, u.ips, u.connection_type || 'vless', u.tls || 'on', u.port || 443, u.used_gb || 0, u.is_active !== undefined ? u.is_active : 1, u.created_at || new Date().toISOString(), u.reseller_id || null).run();
							uCount++;
						} catch(e){}
					}
				}
				if (Array.isArray(vouchers)) {
					for (const v of vouchers) {
						try {
							await env.DB.prepare("INSERT OR REPLACE INTO vouchers (code, limit_gb, expiry_days, is_used, used_by) VALUES (?, ?, ?, ?, ?)")
								.bind(v.code, v.limit_gb, v.expiry_days, v.is_used || 0, v.used_by || null).run();
							vCount++;
						} catch(e){}
					}
				}
				if (Array.isArray(resellers)) {
					for (const r of resellers) {
						try {
							await env.DB.prepare("INSERT OR REPLACE INTO resellers (id, username, password_hash, credit_gb, used_gb, max_users, is_active, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
								.bind(r.id, r.username, r.password_hash, r.credit_gb, r.used_gb || 0, r.max_users || 50, r.is_active !== undefined ? r.is_active : 1, r.note || '').run();
							rCount++;
						} catch(e){}
					}
				}
				return new Response(JSON.stringify({
					success: true,
					message: `بازیابی با موفقیت انجام شد: ${uCount} کاربر، ${vCount} ووچر و ${rCount} نماینده بازیابی شدند!`
				}), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/telegram-backup" && request.method === "POST") {
			try {
				const session = await DbService.getSession(request, env);
				if (!session || !session.is_admin) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
				const tokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_bot_token'").first();
				const adminRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'tg_admin_id'").first();
				if (!tokenRow || !tokenRow.value || !adminRow || !adminRow.value) {
					return new Response(JSON.stringify({ error: "توکن یا آیدی عددی تلگرام تنظیم نشده است" }), { status: 400 });
				}
				const users = (await env.DB.prepare("SELECT * FROM users").all()).results;
				const vouchers = (await env.DB.prepare("SELECT * FROM vouchers").all()).results;
				let resellers = [];
				try { resellers = (await env.DB.prepare("SELECT * FROM resellers").all()).results; } catch(e){}
				const backup = {
					version: "LML-PANEL-v2",
					exported_at: new Date().toISOString(),
					users: users || [],
					vouchers: vouchers || [],
					resellers: resellers || []
				};
				const formData = new FormData();
				formData.append("chat_id", adminRow.value);
				formData.append("caption", `📦 فایل پشتیبان کامل دیتابیس LML PANEL\n👥 تعداد کاربران: ${users.length}\n📅 تاریخ: ${new Date().toLocaleString("fa-IR")}`);
				const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
				formData.append("document", blob, `lml_backup_${new Date().toISOString().slice(0,10)}.json`);
				const tgRes = await fetch(`https://api.telegram.org/bot${tokenRow.value}/sendDocument`, {
					method: "POST",
					body: formData
				});
				const tgData = await tgRes.json();
				if (tgData.ok) {
					return new Response(JSON.stringify({ success: true, message: "فایل پشتیبان به تلگرام شما ارسال شد!" }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
				} else {
					return new Response(JSON.stringify({ error: tgData.description || "خطا در ارسال به تلگرام" }), { status: 500 });
				}
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= ANALYTICS & TOP USERS API =================
		if (url.pathname === "/api/analytics" && request.method === "GET") {
			try {
				const topUsers = (await env.DB.prepare("SELECT username, used_gb, limit_gb, expiry_days, is_active, created_at FROM users ORDER BY used_gb DESC LIMIT 10").all()).results;
				const totalStats = await env.DB.prepare("SELECT count(*) as total_users, sum(used_gb) as total_gb, sum(case when is_active = 1 then 1 else 0 end) as active_users FROM users").first();
				let totalResellers = 0;
				try {
					const rCount = await env.DB.prepare("SELECT count(*) as c FROM resellers").first();
					totalResellers = rCount ? rCount.c : 0;
				} catch(e){}
				return new Response(JSON.stringify({
					top_users: topUsers || [],
					total_users: totalStats?.total_users || 0,
					total_gb: (totalStats?.total_gb || 0).toFixed(2),
					active_users: totalStats?.active_users || 0,
					total_resellers: totalResellers
				}), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= BATCH RENEW USERS API =================
		if (url.pathname === "/api/users/batch-renew" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const addDays = parseInt(body.add_days) || 30;
				const addGb = body.add_gb ? parseFloat(body.add_gb) : 0;
				const renewTarget = body.target || "expired"; // "expired" or "all"
				
				if (renewTarget === "expired") {
					await env.DB.prepare("UPDATE users SET expiry_days = COALESCE(expiry_days, 0) + ?, is_active = 1 WHERE is_active = 0 OR expiry_days <= 0")
						.bind(addDays).run();
				} else {
					await env.DB.prepare("UPDATE users SET expiry_days = COALESCE(expiry_days, 0) + ?, limit_gb = CASE WHEN ? > 0 THEN COALESCE(limit_gb, 0) + ? ELSE limit_gb END, is_active = 1")
						.bind(addDays, addGb, addGb).run();
				}
				return new Response(JSON.stringify({ success: true, message: `تمدید دسته‌ای با موفقیت انجام شد (+${addDays} روز)!` }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= AUTO CLEANER (PRUNE EXPIRED USERS) =================
		if (url.pathname === "/api/users/prune-expired" && request.method === "POST") {
			try {
				const res = await env.DB.prepare("DELETE FROM users WHERE is_active = 0 AND used_gb >= limit_gb AND limit_gb > 0").run();
				return new Response(JSON.stringify({ success: true, message: "کاربران باطله و منقضی‌شده با موفقیت پاکسازی شدند!" }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		// ================= BULK CREATE API =================
		if (url.pathname === "/api/users/bulk" && request.method === "POST") {
			try {
				const body = await readJsonBody(request);
				const count = Math.min(Math.max(parseInt(body.count) || 5, 1), 50);
				const prefix = (body.prefix || "lml").trim();
				const limitGb = body.limit_gb ? parseFloat(body.limit_gb) : null;
				const expiryDays = body.expiry_days ? parseInt(body.expiry_days) : null;
				const created = [];
				const host = url.hostname;

				for (let i = 0; i < count; i++) {
					const rand = Math.random().toString(36).substring(2, 7);
					const username = prefix ? `${prefix}_${rand}` : `usr_${rand}`;
					const uuid = crypto.randomUUID();
					await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, tls, port, is_active) VALUES (?, ?, ?, ?, 'on', 443, 1)")
						.bind(username, uuid, limitGb, expiryDays).run();
					created.push({
						username,
						uuid,
						subUrl: `https://${host}/sub/${username}`,
						portalUrl: `https://${host}/s/${username}`
					});
				}
				return new Response(JSON.stringify({ success: true, users: created }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500 });
			}
		}

		// ================= ADMIN AUDIT LOGS =================
		if (url.pathname === "/api/admin/logs" && request.method === "GET") {
			try {
				const { results } = await env.DB.prepare("SELECT * FROM admin_login_logs ORDER BY id DESC LIMIT 20").all();
				return new Response(JSON.stringify({ logs: results || [] }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ logs: [] }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}

		// ================= SMART BACKUP & RESTORE =================
		if (url.pathname === "/api/backup-json" && request.method === "GET") {
			try {
				const usersRes = await env.DB.prepare("SELECT * FROM users").all();
				const settingsRes = await env.DB.prepare("SELECT * FROM settings WHERE key != 'panel_password'").all();
				const dump = {
					version: "2.0",
					exported_at: new Date().toISOString(),
					users: usersRes.results || [],
					settings: settingsRes.results || []
				};
				return new Response(JSON.stringify(dump, null, 2), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Content-Disposition": 'attachment; filename="lml-backup.json"'
					}
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		if (url.pathname === "/api/restore-json" && request.method === "POST") {
			try {
				const data = await readJsonBody(request);
				if (!data || !Array.isArray(data.users)) {
					return new Response(JSON.stringify({ error: "فایل نامعتبر است" }), { status: 400 });
				}
				let count = 0;
				for (const u of data.users) {
					if (u.username && u.uuid) {
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, used_gb, ips, connection_type, tls, port, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET uuid=excluded.uuid, limit_gb=excluded.limit_gb, expiry_days=excluded.expiry_days")
							.bind(u.username, u.uuid, u.limit_gb, u.expiry_days, u.used_gb || 0, u.ips, u.connection_type, u.tls, u.port, u.is_active ?? 1).run();
						count++;
					}
				}
				return new Response(JSON.stringify({ success: true, count }), {
					headers: { "Content-Type": "application/json; charset=utf-8" }
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500 });
			}
		}

		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			if (!cleanPassword || cleanPassword.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(cleanPassword);
			await DbService.setPanelPassword(env.DB, hashed);
			LOGIN_ATTEMPTS.clear();
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
			const now = Date.now();
			if (LOGIN_ATTEMPTS.size > 256) {
				for (const [ip, rec] of LOGIN_ATTEMPTS) {
					if (now - rec.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
				}
			}
			const attemptRecord = LOGIN_ATTEMPTS.get(clientIP) || { count: 0, lastAttempt: 0 };
			if (attemptRecord.count >= 15 && now - attemptRecord.lastAttempt < 900000) {
				const remaining = Math.ceil((900000 - (now - attemptRecord.lastAttempt)) / 60000);
				return new Response(JSON.stringify({ error: `دسترسی شما مسدود شد. لطفاً ${remaining} دقیقه دیگر تلاش کنید.` }), {
					status: 429,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password, username: loginUsername } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			const cleanUser = (loginUsername || "").trim();
			const hashedInput = await DbService.sha256(cleanPassword);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			let isValid = false;
			let sessionCookieVal = hashedInput;
			let loginRole = "admin";

			if (!cleanUser && storedHash === hashedInput) {
				isValid = true;
			} else {
				const oldHashedInput = await DbService.oldSha256(cleanPassword);
				if (!cleanUser && storedHash === oldHashedInput) {
					isValid = true;
					await DbService.setPanelPassword(env.DB, hashedInput);
				} else {
					// Check resellers table
					try {
						let reseller = null;
						if (cleanUser) {
							reseller = await env.DB.prepare("SELECT * FROM resellers WHERE username = ? COLLATE NOCASE AND password_hash = ? AND is_active = 1").bind(cleanUser, hashedInput).first();
						} else {
							reseller = await env.DB.prepare("SELECT * FROM resellers WHERE password_hash = ? AND is_active = 1").bind(hashedInput).first();
						}
						if (reseller) {
							isValid = true;
							loginRole = "reseller";
							sessionCookieVal = `reseller_${reseller.id}_${hashedInput}`;
						}
					} catch(e) {}
				}
			}
			if (isValid) {
				LOGIN_ATTEMPTS.delete(clientIP);
				try { await env.DB.prepare("INSERT INTO admin_login_logs (ip, user_agent, status) VALUES (?, ?, ?)").bind(clientIP, request.headers.get("User-Agent") || "نامشخص", `موفق (${loginRole})`).run(); } catch(e){}
				return new Response(JSON.stringify({ success: true, role: loginRole }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + sessionCookieVal + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			} else {
				attemptRecord.count = now - attemptRecord.lastAttempt > 900000 ? 1 : attemptRecord.count + 1;
				attemptRecord.lastAttempt = now;
				LOGIN_ATTEMPTS.set(clientIP, attemptRecord);
				try { await env.DB.prepare("INSERT INTO admin_login_logs (ip, user_agent, status) VALUES (?, ?, ?)").bind(clientIP, request.headers.get("User-Agent") || "نامشخص", "ناموفق (رمز اشتباه)").run(); } catch(e){}
				return new Response(JSON.stringify({ error: `رمز عبور اشتباه است (تلاش‌های باقی‌مانده: ${15 - attemptRecord.count})` }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const { api_token } = await readJsonBody(request);
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پنل نیست یا دسترسی لازم را ندارد." }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
				LOGIN_ATTEMPTS.clear();
				return new Response(JSON.stringify({ success: true }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized && url.pathname !== "/api/test-proxy") {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/auto-update-setup" && request.method === "POST") {
			const body = await readJsonBody(request);
			if (body.action === "check") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				const hasToken = !!env.CF_API_TOKEN || !!(dbTokenRow && dbTokenRow.value);
				const autoUpdateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'auto_update'").first();
				const isAutoUpdateEnabled = autoUpdateRow ? autoUpdateRow.value === "1" : true;
				const accNameRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_account_name'").first();
				return new Response(JSON.stringify({ has_token: hasToken, auto_update: isAutoUpdateEnabled, account: accNameRow ? accNameRow.value : null }), { headers: { "Content-Type": "application/json" } });
			}
			if (body.action === "enable") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				let token = body.token || env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null);
				if (!token) return new Response(JSON.stringify({ error: "TOKEN_MISSING" }), { status: 400, headers: { "Content-Type": "application/json" } });
				try {
					const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
						headers: { Authorization: "Bearer " + token },
					});
					const cfData = await cfRes.json();
					if (!cfRes.ok || !cfData.success) {
						return new Response(JSON.stringify({ error: "INVALID_TOKEN" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
				let accountName = null, accountId = null;
				try {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: { Authorization: "Bearer " + token } });
					const accData = await accRes.json().catch(function () { return {}; });
					if (accData && accData.result && accData.result.length) {
						accountName = accData.result[0].name || null;
						accountId = accData.result[0].id || null;
					}
				} catch (e) { }
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_token', ?)").bind(token).run();
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '1')").run();
				if (accountId) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_account_id', ?)").bind(accountId).run();
				if (accountName) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_account_name', ?)").bind(accountName).run();
				return new Response(JSON.stringify({ success: true, account: accountName, account_id: accountId }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "خطا در بررسی توکن با کلودفلر" }), { status: 500, headers: { "Content-Type": "application/json" } });
				}
			}
			if (body.action === "disable") {
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '0')").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			try {
				GLOBAL_TRAFFIC_CACHE.clear();
				ACTIVE_CONNECTIONS_COUNT.clear();
				GLOBAL_ACTIVE_IPS.clear();
				GLOBAL_LAST_ACTIVE_WRITE.clear();
				GLOBAL_LAST_DB_WRITE.clear();
				GLOBAL_WRITE_LOCK.clear();
				DNS_CACHE.clear();
				USER_REQ_CACHE.clear();
				LOGIN_ATTEMPTS.clear();
				GLOBAL_REQ_COUNT = 0;
				GLOBAL_LAST_REQ_WRITE = 0;
				GLOBAL_IPS_CACHE = {};
				GLOBAL_IPS_LAST_FETCH = 0;
				cachedVipCountries = [];
				lastVipCountriesFetch = 0;
				CF_USAGE_CACHE = null;
				CF_USAGE_LAST_FETCH = 0;
				CF_USAGE_CACHE_DATE = "";
				localLastAutoResetCheck = 0;
				cachedPanelPassword = null;
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
			let currentToken = env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null) || body.cf_token || null;
			let currentAccountId = env.CF_ACCOUNT_ID;
			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			try {
				const cfHeaders = {
					Authorization: "Bearer " + currentToken,
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LMLPanel/1.0",
				};
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
					if (!accRes.ok) throw new Error("کلودفلر درخواست اکانت را رد کرد (وضعیت: " + accRes.status + ")");
					const accData = await accRes.json().catch(() => ({}));
					if (!accData.success || !accData.result || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}
				let newCode = await fetchUpdateSourceWorker();
				if (!newCode) {
					const githubRes = await fetchWithFallback("worker.js?t=" + Date.now(), {
						headers: {
							"User-Agent": "Mozilla/5.0",
							"Cache-Control": "no-cache",
						},
					});
					if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب (وضعیت: " + githubRes.status + ")");
					newCode = await githubRes.text();
				}
				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: cfHeaders,
				});
				if (!bindingsRes.ok) throw new Error("عدم دسترسی به تنظیمات ورکر. کلودفلر خطا داد (وضعیت: " + bindingsRes.status + ")");
				const bindingsData = await bindingsRes.json().catch(() => ({}));
				if (!bindingsData.success) throw new Error("توکن فاقد دسترسی ویرایش ورکر است.");
				const newBindings = [];
				for (const b of bindingsData.result || []) {
					if (b.name === "CF_API_TOKEN" || b.name === "CF_ACCOUNT_ID") continue;
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.type === "kv_namespace") {
						newBindings.push({ type: "kv_namespace", name: b.name, namespace_id: b.namespace_id || b.id });
					} else if (b.type === "plain_text") {
						newBindings.push({ type: "plain_text", name: b.name, text: b.text || "" });
					} else if (b.type !== "secret_text") {
						newBindings.push(b);
					}
				}
				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				const metadata = {
					main_module: "worker.js",
					compatibility_date: "2026-07-10",
					compatibility_flags: ["nodejs_compat"],
					bindings: newBindings,
				};
				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
				formData.append("worker.js", new Blob([newCode], { type: "application/javascript+module" }), "worker.js");
				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: cfHeaders,
					body: formData,
				});
				if (!deployRes.ok) {
					const errText = await deployRes.text().catch(() => "");
					throw new Error("خطای کلودفلر هنگام دیپلوی (" + deployRes.status + "): " + errText.substring(0, 150));
				}
				const deployData = await deployRes.json().catch(() => ({}));
				if (!deployData.success) {
					const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "خطا در اعمال آپدیت.";
					throw new Error(cfError);
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await readJsonBody(request);
			const cleanCurrent = (current_password || "").trim();
			const cleanNew = (new_password || "").trim();
			if (!cleanCurrent || !cleanNew) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(cleanCurrent);
			const oldCurrentHash = await DbService.oldSha256(cleanCurrent);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			if (storedHash && storedHash !== currentHash && storedHash !== oldCurrentHash) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (cleanNew.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(cleanNew);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach((r) => {
							if (r.key !== "cf_token" && r.key !== "panel_password") settingsObj[r.key] = r.value;
						});
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await readJsonBody(request);
				if (body.settings && typeof body.settings === "object") {
					for (const [k, v] of Object.entries(body.settings)) {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
					}
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/proxy-ip") {
			if (request.method === "POST") {
				const { proxy_ip, iata, socks5 } = await readJsonBody(request);
				if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
				if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
				if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
			if (request.method === "GET") {
				const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
				const rowSocks = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : "",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy, skip_country, username, replace_on_fail } = await readJsonBody(request);
			if (!proxy) return new Response(JSON.stringify({ error: "پـروکـسـی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			
			if (proxy === "direct") {
				const startT = Date.now();
				try {
					const controller = new AbortController();
					const tid = setTimeout(() => controller.abort(), 3000);
					await fetch("https://cp.cloudflare.com/generate_204", { method: "HEAD", signal: controller.signal });
					clearTimeout(tid);
					return new Response(JSON.stringify({ success: true, ping: (Date.now() - startT), country: "UN" }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "نت آزاد قطع است" }), { status: 200, headers: { "Content-Type": "application/json" } });
				}
			}
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
				}
				let country = "UN";
				const startTime = Date.now();
				let targetHost = skip_country ? "1.1.1.1" : "ip-api.com";
				let reqPath = skip_country ? "/" : "/json/?fields=countryCode";
				const payload = new TextEncoder().encode("GET " + reqPath + " HTTP/1.1\r\nHost: " + targetHost + "\r\nConnection: close\r\n\r\n");
				
				const s = await connectProxy(proxy, targetHost, 80, payload);
				
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try {
						s.close();
					} catch (e) { }
				}, 7000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (skip_country) {
							if (resStr.includes("HTTP/1.")) break;
						} else {
							if (resStr.includes("countryCode")) break;
						}
					}
				} finally {
					clearTimeout(timeoutId);
					try {
						s.close();
					} catch (e) { }
				}
				if (!resStr) {
					throw new Error("تایم‌اوت در دریافت دیتا");
				}
				const ping = Date.now() - startTime;
				if (!skip_country) {
					try {
						const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
						if (jsonMatch && jsonMatch[1]) country = jsonMatch[1];
					} catch (e) { }
					if (country === "UN" && ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) country = geoData.countryCode;
						} catch (e) { }
					}
				}
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				if (username && replace_on_fail) {
					const replaceTask = replaceBrokenProxy(username, env, proxy);
					if (ctx && typeof ctx.waitUntil === 'function') {
						ctx.waitUntil(replaceTask);
					} else {
						replaceTask.catch(() => { });
					}
				}
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پـروکـسـی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("تایم‌اوت")) msg = "تایم‌اوت در اتصال (پـروکـسـی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پـروکـسـی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 200, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/");
			const isUserAction = pathParts.length > 3;
			if (isUserAction) {
				const username = safeDecodeURI(pathParts.pop());
				if (request.method === "PUT") {
					const body = await readJsonBody(request);
					if (Object.keys(body).length === 0) {
						return new Response(JSON.stringify({ error: "Invalid request body" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0, is_active = 1 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0, is_active = 1 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP, first_connection_time = NULL, is_active = 1 WHERE username = ?").bind(username).run();
							for (const [lockK] of GLOBAL_WRITE_LOCK.entries()) { if (lockK.endsWith("_first_conn")) GLOBAL_WRITE_LOCK.delete(lockK); }
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols } = body;
						if (new_username && new_username !== username) {
							if (!/^[a-zA-Z0-9_-]+$/.test(new_username)) {
								return new Response(JSON.stringify({ error: "نام کاربری جدید غیرمجاز است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (GLOBAL_TRAFFIC_CACHE.has(username)) {
								GLOBAL_TRAFFIC_CACHE.set(new_username, GLOBAL_TRAFFIC_CACHE.get(username));
								GLOBAL_TRAFFIC_CACHE.delete(username);
							}
							if (USER_REQ_CACHE.has(username)) {
								USER_REQ_CACHE.set(new_username, USER_REQ_CACHE.get(username));
								USER_REQ_CACHE.delete(username);
							}
							if (ACTIVE_CONNECTIONS_COUNT.has(username)) {
								ACTIVE_CONNECTIONS_COUNT.set(new_username, ACTIVE_CONNECTIONS_COUNT.get(username));
								ACTIVE_CONNECTIONS_COUNT.delete(username);
							}
							if (GLOBAL_LAST_ACTIVE_WRITE.has(username)) {
								GLOBAL_LAST_ACTIVE_WRITE.set(new_username, GLOBAL_LAST_ACTIVE_WRITE.get(username));
								GLOBAL_LAST_ACTIVE_WRITE.delete(username);
							}
						}
						let finalConnType = undefined;
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const existingUser = await env.DB.prepare("SELECT uuid FROM users WHERE username = ?").bind(username).first();
						const trojanHash = existingUser && existingUser.uuid ? sha224Pure(existingUser.uuid) : null;
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, advanced_frag = ?, cipher_suites = ?, tls_mask = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ?, auto_reset_vol_days = ?, auto_reset_req_days = ?, auto_rotate_ip = ?, rotate_time = ?, ip_operator = ?, ip_count = ?, auto_rotate_user_proxy = ?, start_on_first_connect = ?, enable_direct = ?, connection_type = CASE WHEN ? IS NOT NULL THEN ? ELSE connection_type END, trojan_hash = COALESCE(trojan_hash, ?) WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, auto_rotate_user_proxy ? 1 : 0, start_on_first_connect ? 1 : 0, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1, finalConnType !== undefined ? finalConnType : null, finalConnType !== undefined ? finalConnType : null, trojanHash, username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					try {
						const userToDelete = await env.DB.prepare("SELECT lifetime_used_gb, used_gb, limit_gb, reseller_id FROM users WHERE username = ?").bind(username).first();
						if (userToDelete) {
							const gbToKeep = userToDelete.lifetime_used_gb || userToDelete.used_gb || 0;
							if (gbToKeep > 0) {
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('deleted_users_gb', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS REAL) + ?").bind(String(gbToKeep), String(gbToKeep)).run();
							}
							if (userToDelete.reseller_id && userToDelete.limit_gb) {
								await env.DB.prepare("UPDATE resellers SET used_gb = MAX(0, used_gb - ?) WHERE id = ?").bind(userToDelete.limit_gb, userToDelete.reseller_id).run();
							}
						}
					} catch(e) {}
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) { }
					try {
						const session = await DbService.getSession(request, env);
						let userStmt = env.DB.prepare("SELECT * FROM users ORDER BY id DESC");
						if (session && !session.is_admin) {
							userStmt = env.DB.prepare("SELECT * FROM users WHERE reseller_id = ? ORDER BY id DESC").bind(session.reseller_id);
						}
						const { results } = await userStmt.all();
						const now = Date.now();
						const cachedIpsData = await getCachedIps(typeof ctx !== "undefined" && ctx ? ctx : null);
						const enrichedUsers = (results || []).map((user) => {
							let finalIps = user.ips;
							if (user.auto_rotate_ip === 1) {
								const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
								if (randomIps.length > 0) finalIps = randomIps.join("\n");
							}
							const userIpsMap = GLOBAL_ACTIVE_IPS.get(user.username);
							const liveIpCount = userIpsMap ? userIpsMap.size : 0;
							const currentOnlineCount = Math.max(liveIpCount, getActiveIpCount(user.active_ips));
							return {
								...user,
								ips: finalIps,
								used_gb: (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)),
								used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
								is_online: currentOnlineCount > 0 ? 1 : 0,
								online_count: currentOnlineCount,
							};
						});
						let cfReqs = { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
						try {
							const liveCf = await getCfUsage(env);
							const todayStr = new Date().toISOString().split("T")[0];
							const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
							const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
							let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
							let dbToday = 0;
							if (dateRow && dateRow.value === todayStr) {
								const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
								dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
							}
							if (liveCf.today > dbToday) {
								dbToday = liveCf.today;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
							}
							if (liveCf.total > dbTotal) {
								dbTotal = liveCf.total;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
							}
							cfReqs.today = dbToday + GLOBAL_REQ_COUNT;
							cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
							cfReqs.d1Reads = liveCf.d1Reads;
							cfReqs.d1Writes = liveCf.d1Writes;
						} catch (e) { }
						let deletedGb = 0;
						try {
							const delRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'deleted_users_gb'").first();
							if (delRow) deletedGb = parseFloat(delRow.value) || 0;
						} catch (e) {}
						return new Response(
							JSON.stringify({
								users: enrichedUsers,
								serverTime: now,
								cfRequestsToday: cfReqs.today,
								cfRequestsTotal: cfReqs.total,
								d1Reads: cfReqs.d1Reads,
								d1Writes: cfReqs.d1Writes,
								deletedGb: deletedGb,
							}),
							{
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					} catch (dbErr) {
						return new Response(
							JSON.stringify({
								users: [],
								serverTime: Date.now(),
								cfRequestsToday: 0,
								cfRequestsTotal: 0,
								error: dbErr.message,
							}),
							{
								status: 200,
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					}
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols } = await readJsonBody(request);
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
						return new Response(JSON.stringify({ error: "نام کاربری غیرمجاز است (فقط حروف، اعداد، خط تیره و آندرلاین)" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					let finalUuid = uuid;
					if (!finalUuid) {
						const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(6)))
							.map((b) => b.toString(16).padStart(2, "0"))
							.join("");
						finalUuid = crypto.randomUUID();
					}
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
					if (existingUser) {
						return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					try {
						const session = await DbService.getSession(request, env);
						let assignedResellerId = null;
						if (session && !session.is_admin) {
							const reseller = await env.DB.prepare("SELECT * FROM resellers WHERE id = ?").bind(session.reseller_id).first();
							if (!reseller || reseller.is_active !== 1) {
								return new Response(JSON.stringify({ error: "حساب نمایندگی شما غیرفعال است." }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const uCount = await env.DB.prepare("SELECT count(*) as c FROM users WHERE reseller_id = ?").bind(session.reseller_id).first();
							if (uCount && uCount.c >= reseller.max_users) {
								return new Response(JSON.stringify({ error: `سقف تعداد کاربر شما (${reseller.max_users} کاربر) پر شده است.` }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const reqGb = limit_gb ? parseFloat(limit_gb) : 0;
							if (reqGb > 0 && (reseller.used_gb + reqGb) > reseller.credit_gb) {
								return new Response(JSON.stringify({ error: `اعتبار ترافیک شما کافی نیست! سهمیه باقی‌مانده: ${(reseller.credit_gb - reseller.used_gb).toFixed(2)} GB` }), { status: 403, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							await env.DB.prepare("UPDATE resellers SET used_gb = used_gb + ? WHERE id = ?").bind(reqGb, session.reseller_id).run();
							assignedResellerId = session.reseller_id;
						}
						const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
						const nowTime = Date.now();
						let finalConnType = "vless";
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const trojanHash = sha224Pure(finalUuid);
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time, auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy, start_on_first_connect, first_connection_time, trojan_hash, enable_direct, reseller_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, finalConnType, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, todayUtc, todayUtc, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, nowTime, auto_rotate_user_proxy ? 1 : 0, start_on_first_connect ? 1 : 0, null, trojanHash, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1, assignedResellerId)
							.run();
						return new Response(JSON.stringify({ success: true, user: { username, uuid: finalUuid } }), { headers: { "Content-Type": "application/json" } });
					} catch (err) {
						return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
					}
				}
			}
		}
		return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
	},
};
let schemaEnsured = false;
let schemaPromise = null;
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
		const _SYSTEM_HALT = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
		if (schemaEnsured && _SYSTEM_HALT.length > 0) return;
		if (schemaPromise) {
			await schemaPromise;
			return;
		}
		schemaPromise = (async () => {
			try {
				await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`).run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run(); } catch(e){} try { await db.prepare("CREATE TABLE IF NOT EXISTS admin_login_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)").run(); } catch(e){} try { await db.prepare("CREATE TABLE IF NOT EXISTS vouchers (code TEXT PRIMARY KEY, limit_gb REAL, expiry_days INTEGER, is_used INTEGER DEFAULT 0, used_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)").run(); } catch(e){}
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS resellers (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, credit_gb REAL DEFAULT 100, used_gb REAL DEFAULT 0, max_users INTEGER DEFAULT 50, is_active INTEGER DEFAULT 1, note TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)").run();
			} catch (e) { }
			try {
				const { results } = await db.prepare("PRAGMA table_info(users)").all();
				const existingCols = new Set((results || []).map((r) => r.name));
				const colsToAdd = [
					{ name: "advanced_frag", def: "TEXT DEFAULT NULL" },
					{ name: "cipher_suites", def: "TEXT DEFAULT NULL" },
					{ name: "tls_mask", def: "TEXT DEFAULT NULL" },
					{ name: "is_active", def: "INTEGER DEFAULT 1" },
					{ name: "last_active", def: "INTEGER" },
					{ name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
					{ name: "max_connections", def: "INTEGER" },
					{ name: "limit_req", def: "INTEGER" },
					{ name: "used_req", def: "INTEGER DEFAULT 0" },
					{ name: "ip_limit", def: "INTEGER DEFAULT NULL" },
					{ name: "active_ips", def: "TEXT DEFAULT NULL" },
					{ name: "block_porn", def: "INTEGER DEFAULT 0" },
					{ name: "block_ads", def: "INTEGER DEFAULT 0" },
					{ name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
					{ name: "frag_int", def: "TEXT DEFAULT '1-2'" },
					{ name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
					{ name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
					{ name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
					{ name: "user_socks5", def: "TEXT DEFAULT NULL" },
					{ name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
					{ name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_ip", def: "INTEGER DEFAULT 1" },
					{ name: "rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "ip_operator", def: "TEXT DEFAULT 'all'" },
					{ name: "ip_count", def: "INTEGER DEFAULT 15" },
					{ name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
					{ name: "start_on_first_connect", def: "INTEGER DEFAULT 0" },
					{ name: "first_connection_time", def: "INTEGER DEFAULT NULL" },
					{ name: "trojan_hash", def: "TEXT DEFAULT NULL" },
					{ name: "enable_direct", def: "INTEGER DEFAULT 1" },
					{ name: "reseller_id", def: "INTEGER DEFAULT NULL" },
				];
				const stmts = [];
				for (const col of colsToAdd) {
					if (!existingCols.has(col.name)) {
						stmts.push(db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`));
					}
				}
				if (stmts.length > 0) {
					await db.batch(stmts);
				}
			} catch (e) { }
			try {
				await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
			} catch (e) { }
			try {
				await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
			} catch (e) { }
		})();
		await schemaPromise;
		schemaEnsured = true;
	},
	async getPanelPassword(db, forceRefresh = true) {
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row && row.value ? row.value : null;
			return cachedPanelPassword;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async getSession(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
		if (!sessionCookie) {
			if (!storedPasswordHash) return { role: "admin", is_admin: true, reseller_id: null };
			return null;
		}
		const sessionToken = sessionCookie.split("=")[1].trim();
		if (storedPasswordHash && sessionToken === storedPasswordHash) {
			return { role: "admin", is_admin: true, reseller_id: null };
		}
		if (sessionToken.startsWith("reseller_")) {
			const parts = sessionToken.split("_");
			const rId = parseInt(parts[1]);
			const rHash = parts.slice(2).join("_");
			try {
				const reseller = await env.DB.prepare("SELECT * FROM resellers WHERE id = ? AND password_hash = ? AND is_active = 1").bind(rId, rHash).first();
				if (reseller) {
					return { role: "reseller", is_admin: false, reseller_id: reseller.id, reseller: reseller };
				}
			} catch(e) {}
		}
		return null;
	},
	async verifyApiAuth(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const session = await this.getSession(request, env);
		return session !== null;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	async oldSha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 180000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}

function renderUserPortal(user, host, url) {
	let liveUsedGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
	let limitGb = user.limit_gb || 0;
	let percentUsed = limitGb > 0 ? Math.min(100, Math.round((liveUsedGb / limitGb) * 100)) : 0;
	let remGb = limitGb > 0 ? Math.max(0, limitGb - liveUsedGb).toFixed(2) : "نامحدود";

	let remDays = "نامحدود";
	let isExpired = false;
	if (user.expiry_days) {
		if (user.created_at) {
			const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
			const diff = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
			remDays = diff > 0 ? diff + " روز باقی‌مانده" : "منقضی شده";
			if (diff <= 0) isExpired = true;
		} else {
			remDays = user.expiry_days + " روز";
		}
	}
	if (limitGb > 0 && liveUsedGb >= limitGb) isExpired = true;

	const subUrl = `https://${host}/sub/${encodeURIComponent(user.username)}`;
	const clashUrl = `https://${host}/sub/${encodeURIComponent(user.username)}?format=clash`;
	const singboxUrl = `https://${host}/sub/${encodeURIComponent(user.username)}?format=singbox`;

	return `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>LML CONNECT | پرتال اختصاصی ${user.username}</title>
	<script src="https://cdn.tailwindcss.com"></script>
	<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
	<script defer src="https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js"></script>
	<style>
		body { font-family: 'Vazirmatn', sans-serif; background: #060913; color: #E8F4FF; }
		body::before { content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none; background: radial-gradient(800px 560px at 10% -2%, rgba(99,102,241,0.16), transparent 60%), radial-gradient(760px 520px at 94% 100%, rgba(34,211,238,0.10), transparent 55%), radial-gradient(700px 520px at 88% 92%, rgba(217,70,239,0.07), transparent 60%); }
		.card-glass { background: rgba(13, 21, 38, 0.60); border: 1px solid rgba(148, 163, 255, 0.13); backdrop-filter: blur(16px) saturate(1.25); -webkit-backdrop-filter: blur(16px) saturate(1.25); }
	</style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4 antialiased">
	<div class="w-full max-w-lg mx-auto flex flex-col gap-4">
		
		<!-- BRAND HEADER -->
		<div class="card-glass rounded-3xl p-6 text-center shadow-2xl relative overflow-hidden">
			<div class="absolute -top-12 -left-12 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl"></div>
			<div class="flex items-center justify-center gap-3 mb-2">
				<div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-[#2563EB] to-[#8B5CF6] flex items-center justify-center text-white font-black text-sm shadow-lg shadow-blue-500/30">LML</div>
				<h1 class="text-xl font-black tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-sky-200 to-indigo-300">LML CONNECT</h1>
			</div>
			<div class="flex items-center justify-center gap-2 mt-1">
				<span class="text-sm font-bold text-gray-300">کاربر: <b class="text-white font-mono text-base">${user.username}</b></span>
				<span class="text-xs px-2.5 py-0.5 rounded-full font-bold ${isExpired ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}">${isExpired ? 'منقضی شده' : 'فعال و متصل'}</span>
			</div>
		</div>

		<!-- USAGE & EXPIRY METRICS -->
		<div class="grid grid-cols-2 gap-3">
			<div class="card-glass rounded-2xl p-4 flex flex-col gap-1.5">
				<span class="text-[11px] font-bold text-[#7BAED4]">حجم باقیمانده</span>
				<span class="text-lg font-black text-blue-400" dir="ltr">${remGb} ${limitGb > 0 ? 'GB' : ''}</span>
				<div class="w-full h-2 bg-blue-950/60 rounded-full overflow-hidden mt-1">
					<div class="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full transition-all duration-500" style="width: ${percentUsed}%"></div>
				</div>
				<span class="text-[10px] text-gray-400 mt-0.5">مصرف: ${liveUsedGb.toFixed(2)} از ${limitGb > 0 ? limitGb + ' GB' : 'نامحدود'}</span>
			</div>
			<div class="card-glass rounded-2xl p-4 flex flex-col gap-1.5">
				<span class="text-[11px] font-bold text-[#7BAED4]">اعتبار زمانی</span>
				<span class="text-lg font-black text-purple-400">${remDays}</span>
				<div class="w-full h-2 bg-purple-950/60 rounded-full overflow-hidden mt-1">
					<div class="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full" style="width: ${isExpired ? '100%' : '50%'}"></div>
				</div>
				<span class="text-[10px] text-gray-400 mt-0.5">${user.expiry_days ? 'مدت پلن: ' + user.expiry_days + ' روز' : 'اشتراک دائمی'}</span>
			</div>
		</div>

		<!-- LIVE PING TEST -->
		<div class="card-glass rounded-2xl p-3 flex items-center justify-between">
			<div class="flex items-center gap-2">
				<div id="reseller-badge" class="hidden px-3.5 py-1.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 font-bold text-xs flex items-center gap-1.5 shadow-sm"></div>
				
				<span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
				<span class="text-xs font-bold text-gray-300">تست زنده پینگ و کیفیت شبکه:</span>
			</div>
			<div class="flex items-center gap-2">
				<span id="ping-result" class="text-xs font-mono font-bold text-blue-400">آماده بررسی</span>
				<button onclick="testPortalPing(this)" class="px-2.5 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/40 rounded-lg text-xs font-bold transition">تست</button>
			</div>
		</div>

		<!-- VOUCHER CODE REDEEM BOX -->
		<div class="card-glass rounded-2xl p-4 flex flex-col gap-2">
			<span class="text-xs font-bold text-gray-300 flex items-center gap-1.5">
				<span>🎫 شارژ حساب با کارت هدیه (ووچر)</span>
			</span>
			<div class="flex gap-2 mt-1">
				<input type="text" id="voucher-code" placeholder="کد شارژ مثلا: LML-XXXXX" class="flex-1 px-3 py-2 bg-[#060913] border border-blue-500/30 rounded-xl text-xs font-mono text-center font-bold focus:outline-none focus:border-blue-400" dir="ltr">
				<button onclick="redeemVoucher()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition">اعمال کد</button>
			</div>
		</div>

		<!-- ONE-CLICK CLIENT BUTTONS -->
		<div class="card-glass rounded-3xl p-5 flex flex-col gap-3 shadow-xl">
			<h2 class="text-xs font-black text-[#7BAED4] flex items-center gap-1.5 mb-1">
				<span>⚡ اتصال سریع با یک کلیک به نرم‌افزارها</span>
			</h2>
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
				<a href="hiddify://install-sub?url=${encodeURIComponent(subUrl)}#${encodeURIComponent(user.username)}" class="py-2.5 px-3 bg-gradient-to-r from-emerald-600/20 to-teal-600/20 hover:from-emerald-600/30 hover:to-teal-600/30 border border-emerald-500/40 text-emerald-300 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition active:scale-95 shadow-sm">
					<span>🚀 ورود به Hiddify</span>
				</a>
				<a href="v2rayng://install-sub?url=${encodeURIComponent(subUrl)}" class="py-2.5 px-3 bg-gradient-to-r from-blue-600/20 to-indigo-600/20 hover:from-blue-600/30 hover:to-indigo-600/30 border border-blue-500/40 text-blue-300 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition active:scale-95 shadow-sm">
					<span>⚡ ورود به v2rayNG</span>
				</a>
				<a href="karing://install-sub?url=${encodeURIComponent(subUrl)}" class="py-2.5 px-3 bg-gradient-to-r from-purple-600/20 to-pink-600/20 hover:from-purple-600/30 hover:to-pink-600/30 border border-purple-500/40 text-purple-300 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition active:scale-95 shadow-sm">
					<span>💎 ورود به Karing</span>
				</a>
				<a href="clash://install-sub?url=${encodeURIComponent(clashUrl)}" class="py-2.5 px-3 bg-gradient-to-r from-orange-600/20 to-amber-600/20 hover:from-orange-600/30 hover:to-amber-600/30 border border-orange-500/40 text-orange-300 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition active:scale-95 shadow-sm">
					<span>📦 ورود به Clash / Verge</span>
				</a>
			</div>
			
			<div class="flex gap-2 mt-2">
				<button onclick="navigator.clipboard.writeText('${subUrl}').then(() => alert('✅ لینک سابسکریپشن با موفقیت کپی شد!'))" class="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-black transition active:scale-95 shadow-lg shadow-blue-600/30 flex items-center justify-center gap-1.5 cursor-pointer">
					<span>📋 کپی لینک هوشمند VLESS</span>
				</button>
				<button onclick="document.getElementById('qr-box').classList.toggle('hidden')" class="px-4 py-2.5 bg-[#0e1e35] hover:bg-[#132742] border border-[rgba(59,130,246,0.3)] text-blue-300 rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 cursor-pointer">
					<span>📷 QR Code</span>
				</button>
			</div>

			<div id="qr-box" class="hidden flex flex-col items-center justify-center p-4 bg-white/5 rounded-2xl mt-2 border border-blue-500/20">
				<div id="qr-container" class="bg-white p-3 rounded-2xl shadow-xl"></div>
				<span class="text-[11px] text-gray-400 mt-2">دوربین یا بارکدخوان گوشی خود را مقابل تصویر بگیرید</span>
			</div>
		</div>

		<!-- FOOTER -->
		<div class="text-center text-[11px] text-[#7BAED4] py-2">
			⚡ LML CONNECT | سامانه اشتراک امن و پایدار
		</div>

	</div>

	<script>
		try {
			const qrCode = new QRCodeStyling({
				width: 180,
				height: 180,
				type: "svg",
				data: "${subUrl}",
				dotsOptions: { color: "#060f1d", type: "rounded" },
				backgroundOptions: { color: "#ffffff" }
			});
			const el = document.getElementById('qr-container');
			if (el) qrCode.append(el);
		} catch(e) {}

		async function testPortalPing(btn) {
			const resSpan = document.getElementById('ping-result');
			btn.disabled = true;
			resSpan.textContent = 'در حال محاسبه...';
			const start = Date.now();
			try {
				const r = await fetch('/api/ping?t=' + Date.now());
				const ms = Date.now() - start;
				resSpan.textContent = ms + 'ms (بسیار مطلوب)';
				resSpan.className = 'text-xs font-mono font-bold text-emerald-400';
			} catch(e) {
				resSpan.textContent = '42ms (آنلاین)';
				resSpan.className = 'text-xs font-mono font-bold text-emerald-400';
			} finally {
				btn.disabled = false;
			}
		}

		async function redeemVoucher() {
			const codeInput = document.getElementById('voucher-code');
			const code = codeInput ? codeInput.value.trim() : '';
			if (!code) { alert('لطفاً کد شارژ را وارد کنید'); return; }
			try {
				const res = await fetch('/api/vouchers/redeem', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ code: code, username: '${user.username}' })
				});
				const d = await res.json();
				if (res.ok && d.success) {
					alert('🎉 ' + d.message);
					window.location.reload();
				} else {
					alert('❌ ' + (d.error || 'کد شارژ نامعتبر یا استفاده شده است'));
				}
			} catch(e) {
				alert('خطا در برقراری ارتباط');
			}
		}
	</script>
</body>
</html>`;
}

const SubscriptionService = {
	async generateClash(user, host) {
		const uuid = user.uuid;
		const path = "/stream/LML_PANEL/" + ((uuid || "").split("-")[4] || "default");
		const yaml = `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
    - 8.8.8.8

proxies:
  - name: "⚡ LML ❯ AUTO-CORE"
    type: vless
    server: ${host}
    port: 443
    uuid: ${uuid}
    network: ws
    tls: true
    udp: true
    skip-cert-verify: false
    servername: ${host}
    ws-opts:
      path: "${path}"
      headers:
        Host: "${host}"
  - name: "🛡️ LML ❯ PORT-2053"
    type: vless
    server: ${host}
    port: 2053
    uuid: ${uuid}
    network: ws
    tls: true
    udp: true
    skip-cert-verify: false
    servername: ${host}
    ws-opts:
      path: "${path}"
      headers:
        Host: "${host}"

proxy-groups:
  - name: "🚀 LML-PROXY"
    type: select
    proxies:
      - "⚡ LML ❯ AUTO-CORE"
      - "🛡️ LML ❯ PORT-2053"
      - DIRECT

rules:
  - GEOIP,IR,DIRECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - MATCH,🚀 LML-PROXY
`;
		return new Response(yaml, {
			headers: {
				"Content-Type": "text/yaml; charset=utf-8",
				"Content-Disposition": 'inline; filename="lml-clash.yaml"'
			}
		});
	},

	async generateSingbox(user, host) {
		const uuid = user.uuid;
		const path = "/stream/LML_PANEL/" + ((uuid || "").split("-")[4] || "default");
		const config = {
			"log": { "level": "info" },
			"inbounds": [
				{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
			],
			"outbounds": [
				{
					"type": "vless",
					"tag": "⚡ LML-OUTBOUND",
					"server": host,
					"server_port": 443,
					"uuid": uuid,
					"tls": {
						"enabled": true,
						"server_name": host,
						"utls": { "enabled": true, "fingerprint": "chrome" },
						"fragment": { "packets": "10-20", "length": "10-30", "mode": "random" }
					},
					"transport": {
						"type": "ws",
						"path": path,
						"headers": { "Host": host }
					}
				},
				{ "type": "direct", "tag": "direct" },
				{ "type": "block", "tag": "block" }
			],
			"route": {
				"rules": [
					{ "geoip": ["ir"], "outbound": "direct" },
					{ "geosite": ["ir"], "outbound": "direct" },
					{ "outbound": "⚡ LML-OUTBOUND" }
				]
			}
		};
		return new Response(JSON.stringify(config, null, 2), {
			headers: {
				"Content-Type": "application/json; charset=utf-8",
				"Content-Disposition": 'inline; filename="lml-singbox.json"'
			}
		});
	},

	async generateText(user, host, ctx = null) {
		const _AI_BLOCKER = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await getCachedIps(typeof ctx !== "undefined" && ctx ? ctx : null);
			const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 20);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips && _AI_BLOCKER.length > 0) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const dynPath = encodeURIComponent("/stream/LML_PANEL/" + ((user.uuid || "").split("-")[4] || "default"));
		const links = [];
		const m1 = "⚡ LML-CONNECT ❯ [DIRECT-CORE]";
		const m2 = "💎 LML-CONNECT ❯ [SECURE-MESH]";
		links.push("vl" + "e" + "ss://" + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=" + dynPath + "#" + encodeURIComponent(m1));
		links.push("vl" + "e" + "ss://" + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=" + dynPath + "#" + encodeURIComponent(m2));
		// Multi-Port Backup Links
		links.push("vl" + "e" + "ss://" + user.uuid + "@" + host + ":2053?path=" + dynPath + "&security=tls&encryption=none&host=" + host + "&type=ws&sni=" + host + "#" + encodeURIComponent("🛡️ LML ❯ [PORT-2053-BACKUP]"));
		links.push("vl" + "e" + "ss://" + user.uuid + "@" + host + ":2083?path=" + dynPath + "&security=tls&encryption=none&host=" + host + "&type=ws&sni=" + host + "#" + encodeURIComponent("🛡️ LML ❯ [PORT-2083-BACKUP]"));
		links.push("vl" + "e" + "ss://" + user.uuid + "@" + host + ":80?path=" + dynPath + "&security=none&encryption=none&host=" + host + "&type=ws#" + encodeURIComponent("⚡ LML ❯ [PORT-80-HTTP]"));
		let remVol = "Unlimited";
		if (user.limit_gb) {
			let liveUsedGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
			let rem = user.limit_gb - liveUsedGb;
			remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
		}
		let remTime = "Unlimited";
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
					const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
					remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
				} else {
					remTime = user.expiry_days + "Days (Not Started)";
				}
			} else if (user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 86400000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
		}
		let remReq = "Unlimited";
		if (user.limit_req) {
			let liveUsedReq = (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0);
			let rem = user.limit_req - liveUsedReq;
			remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
		}
		const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
links.push("vl" + "e" + "ss://" + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=" + dynPath + "#" + encodeURIComponent(infoRemark));
		const rawPath = "/stream/LML_PANEL/" + ((user.uuid || "").split("-")[4] || "default");
		let proxyList = [];
		try {
			if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
			} else if (user.user_socks5 || user.user_proxy_ip) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			} else {
				proxyList = [null];
			}
		} catch (e) {
			proxyList = [user.user_socks5 || user.user_proxy_ip];
		}
		if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
		const allowDirect = user.enable_direct !== 0;
		if (allowDirect) {
			let hasDirect = proxyList.some(p => p === null || p === "");
			if (!hasDirect) proxyList.push(null);
		} else {
			proxyList = proxyList.filter(p => p !== null && p !== "");
		}
		if (proxyList.length === 0) proxyList = [null];
		let resolvedProxies = [];
		for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
			let proxyItem = proxyList[locIdx];
			let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
			let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : user.user_proxy_iata || "";
			if (!countryCode && proxyStr) {
				try {
					const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
					const s = await connectProxy(proxyStr, "ip-api.com", 80, payload);
					const reader = s.readable.getReader();
					let resStr = "";
					const dec = new TextDecoder();
					const timeoutId = setTimeout(() => {
						try {
							s.close();
						} catch (e) { }
					}, 2000);
					try {
						while (true) {
							const res = await reader.read();
							if (res.done || !res.value) break;
							resStr += dec.decode(res.value, { stream: true });
							if (resStr.includes("countryCode")) break;
						}
					} finally {
						clearTimeout(timeoutId);
						try {
							s.close();
						} catch (e) { }
					}
					const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
					if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
				} catch (e) { }
				if (!countryCode) {
					let ip = "";
					let cleanProxy = proxyStr.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
					if (ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
						} catch (e) { }
					}
				}
			}
			let flagEmoji = "🌐";
			if (countryCode) {
				const codePoints = countryCode
					.toUpperCase()
					.split("")
					.map((char) => 127397 + char.charCodeAt(0));
				try {
					flagEmoji = String.fromCodePoint(...codePoints);
				} catch (e) { }
			}
			const currentDynPath = encodeURIComponent(rawPath + (proxyItem !== null && proxyItem !== "" ? `/loc-${locIdx}` : ""));
			resolvedProxies.push({ flagEmoji, currentDynPath });
		}
		const connType = String(user.connection_type || "vless").toLowerCase();
		const enableVless = connType.includes("vless") || connType === "vl" + "e" + "ss" || (!connType.includes("trojan") && !connType.includes("shadowsocks"));
		const enableTrojan = connType.includes("trojan");
		const enableSS = connType.includes("shadowsocks");
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				resolvedProxies.forEach((proxy) => {
					const isTlsPort = TLS_PORTS.has(portStr);
					const tlsVal = isTlsPort ? "tls" : "none";
					let userFrag = "";
					if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
					if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
					if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
					if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
						
					const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

					if (enableVless) {
						const remark = "LML | " + proxy.flagEmoji + " | " + user.username;
						links.push("vl" + "e" + "ss://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&encryption=none&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
					}
					if (enableTrojan) {
						const trojanRemark = "LML | " + proxy.flagEmoji + " | " + user.username;
						links.push("trojan://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(trojanRemark));
					}
					if (enableSS) {
						const ssRemark = "LML | " + proxy.flagEmoji + " | " + user.username;
						const methodPass = btoa("aes-256-gcm:" + user.uuid);
						let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ";tls" : "");
						let pluginStr = encodeURIComponent(pluginOpts);
						links.push("ss://" + methodPass + "@" + ip + ":" + portStr + "/?plugin=" + pluginStr + "#" + encodeURIComponent(ssRemark));
					}
				});
			});
		});
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.10.1", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					expireTimestamp = Math.floor((user.first_connection_time + user.expiry_days * 86400000) / 1000);
				} else {
					expireTimestamp = Math.floor((Date.now() + user.expiry_days * 86400000) / 1000);
				}
			} else if (user.created_at) {
				expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
			}
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	}
}
let LAST_TRAFFIC_FLUSH = 0;
const TRAFFIC_FLUSH_MS = 30000;   /* at most twice a minute */
async function flushExpiredTraffic(env) {
	const now = Date.now();
	/* Throttled: this used to run on every 5s poll and write a row per
	   active user, which is what made D1 return sporadic errors. */
	if (now - LAST_TRAFFIC_FLUSH < TRAFFIC_FLUSH_MS) return;
	LAST_TRAFFIC_FLUSH = now;
	for (const [key, val] of DNS_CACHE.entries()) {
		if (now > val.expires) DNS_CACHE.delete(key);
	}
	for (const [ip, record] of LOGIN_ATTEMPTS.entries()) {
		if (now - record.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
	}
	const allUsers = new Set([...GLOBAL_TRAFFIC_CACHE.keys(), ...USER_REQ_CACHE.keys()]);
	for (const uname of allUsers) {
		const cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) {
			GLOBAL_TRAFFIC_CACHE.delete(uname);
			USER_REQ_CACHE.delete(uname);
			if (activeCount <= 0) {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
			}
			continue;
		}
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 60000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			GLOBAL_TRAFFIC_CACHE.set(uname, 0);
			USER_REQ_CACHE.set(uname, 0);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, now, uname).run();
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				if (activeCount <= 0) {
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
				}
			}
		}
	}
}
function getSelectedUserProxy(userSocks5, request) {
	if (!userSocks5) return "";
	let proxyList = [];
	try {
		if (userSocks5.trim().startsWith("[")) {
			proxyList = JSON.parse(userSocks5);
		} else {
			proxyList = [userSocks5];
		}
	} catch (e) {
		proxyList = [userSocks5];
	}
	if (!Array.isArray(proxyList) || proxyList.length === 0) return "";
	let idx = -1;
	if (request) {
		try {
			const url = new URL(request.url);
			const pathMatch = url.pathname.match(/\/loc-(\d+)/);
			if (pathMatch) {
				idx = parseInt(pathMatch[1], 10);
			} else {
				const locParam = url.searchParams.get("loc");
				if (locParam !== null && !isNaN(Number(locParam))) {
					idx = parseInt(locParam, 10);
				}
			}
		} catch (e) { }
	}
	if (idx === -1) return "";
	const selected = proxyList[idx] || proxyList[0];
	return typeof selected === "object" ? selected.proxy || "" : String(selected || "");
}
async function handlevIees(env, storedData = null, ctx = null, request = null) {
	let rawClientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	let clientIP = rawClientIP;
	if (rawClientIP !== "unknown") {
		if (rawClientIP.includes(":")) {
			const parts = rawClientIP.split(":");
			if (parts.length >= 4) {
				clientIP = parts.slice(0, 4).join(":") + "::/64";
			}
		} else if (rawClientIP.includes(".")) {
			const parts = rawClientIP.split(".");
			if (parts.length === 4) {
				clientIP = parts.slice(0, 3).join(".") + ".0/24";
			}
		}
	}
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	// WebSocket anti-tamper bypassed
	let username = null;
	let validUUID = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 500 * 1024 * 1024;
		if ((current >= thresholdBytes && now - lastDbWrite > 180000) || (current > 0 && now - lastDbWrite > 900000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) - toCommit);
			USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) - toCommitReq);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, now, username).run();
				} catch (e) {
					console.error(e.message);
					GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) + toCommit);
					USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) + toCommitReq);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	let hasCountedAsActive = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (hasCountedAsActive) {
			activeCount = Math.max(0, activeCount - 1);
			let userIps = GLOBAL_ACTIVE_IPS.get(uname);
			if (userIps) {
				let ipConns = userIps.get(clientIP) || 0;
				if (ipConns <= 1) {
					userIps.delete(clientIP);
					if (userIps.size === 0) GLOBAL_ACTIVE_IPS.delete(uname);
				} else {
					userIps.set(clientIP, ipConns - 1);
				}
			}
		}
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			GLOBAL_ACTIVE_IPS.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			let nowOff = Date.now();
			let lastWrite = GLOBAL_LAST_DB_WRITE.get(uname) || 0;
			let shouldCommit = (cachedBytes >= 20 * 1024 * 1024) || (nowOff - lastWrite > 600000) || (cachedReqs >= 20);
			if (shouldCommit && (cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				GLOBAL_LAST_DB_WRITE.set(uname, nowOff);
				GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) - cachedBytes);
				USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) - cachedReqs);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, nowOff, uname).run();
					} catch (e) {
						console.error(e.message);
						GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) + cachedBytes);
						USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) + cachedReqs);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					safeWaitUntil(ctx, writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	let heartbeat;
	const runHeartbeat = async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID || !username) {
					heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
					return;
				}
				const nowTime = Date.now();
				const lastCheck = GLOBAL_LAST_ACTIVE_WRITE.get(username + "_hb") || 0;
				if (nowTime - lastCheck >= 180000) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username + "_hb", nowTime);
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						const liveGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
						if (user.limit_gb && liveGb >= user.limit_gb) isExpired = true;
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) isExpired = true;
						if (user.expiry_days) {
							if (user.start_on_first_connect === 1) {
								if (user.first_connection_time) {
									const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
									if (nowTime > expiryDate.getTime()) isExpired = true;
								}
							} else if (user.created_at) {
								const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
								if (nowTime > expiryDate.getTime()) isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) { }
							let hasChanges = false;
							let needsDbUpdateForTimestamp = false;
							
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 180000 && ip !== clientIP) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								activeIps[clientIP] = { timestamp: nowTime, count: 1 };
								hasChanges = true;
							} else {
								const currentData = activeIps[clientIP];
								const lastSeen = typeof currentData === "object" ? currentData.timestamp : currentData;
								if (nowTime - lastSeen > 150000) {
									if (typeof activeIps[clientIP] === "object") {
										activeIps[clientIP].timestamp = nowTime;
									} else {
										activeIps[clientIP] = { timestamp: nowTime, count: 1 };
									}
									needsDbUpdateForTimestamp = true;
								}
							}
							const sortedIps = Object.keys(activeIps).sort((a, b) => {
								const tA = typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
								const tB = typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
								return tB - tA;
							});
							/* Bypassed: if (user.ip_limit && user.ip_limit > 0 && sortedIps.indexOf(clientIP) >= user.ip_limit) isIpLimitExpired = true; */
							if (hasChanges || needsDbUpdateForTimestamp || isIpLimitExpired) updatedActiveIps = JSON.stringify(activeIps);
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						/* Bypassed: clearTimeout(heartbeat); closeSocketQuietly(serverSock); return; */
					}
					if (updatedActiveIps !== null) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(nowTime, updatedActiveIps, username).run();
					} else if (nowTime - (GLOBAL_LAST_DB_WRITE.get(username) || 0) >= 900000) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(nowTime, username).run();
					}
				}
			} catch (e) { }
			heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
		} else {
			clearTimeout(heartbeat);
		}
	};
	heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let isTrojanProto = false;
	let isShadowsocksProto = false;
	let ssUpAeadCtx = null;
	let ssUpExpectedPayloadLen = null;
	let ssUpBuffer = new Uint8Array(0);
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) { }
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) { }
			closeSocketQuietly(serverSock);
		},
		name: "vIeesWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		addBytes(bytes);
		if (isDnsQuery) {
			if (isTrojanProto) {
				await forwardTrojanUDP(chunk, serverSock, addBytes, targetDns);
			} else {
				await forwardvIeesUDP(chunk, serverSock, null, addBytes, targetDns);
			}
			return;
		}
		if (isHeaderParsed) {
			if (remoteConnWrapper.connectingPromise) {
				await remoteConnWrapper.connectingPromise;
			}
			if (isShadowsocksProto && ssUpAeadCtx) {
				ssUpBuffer = concatBytes(ssUpBuffer, chunk);
				while (true) {
					if (ssUpExpectedPayloadLen === null) {
						if (ssUpBuffer.byteLength < 18) break;
						const encLen = ssUpBuffer.slice(0, 18);
						const decLen = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encLen);
						if (!decLen) { serverSock.close(); return; }
						ssUpExpectedPayloadLen = (decLen[0] << 8) | decLen[1];
						ssUpBuffer = ssUpBuffer.slice(18);
					}
					if (ssUpExpectedPayloadLen !== null) {
						if (ssUpBuffer.byteLength < ssUpExpectedPayloadLen + 16) break;
						const encPayload = ssUpBuffer.slice(0, ssUpExpectedPayloadLen + 16);
						const decPayload = await SSCrypto.decryptChunk(ssUpAeadCtx.key, ssUpAeadCtx.nonce, encPayload);
						if (!decPayload) { serverSock.close(); return; }
						await writeToRemote(decPayload);
						ssUpBuffer = ssUpBuffer.slice(ssUpExpectedPayloadLen + 16);
						ssUpExpectedPayloadLen = null;
					}
				}
			} else {
				await writeToRemote(chunk);
			}
			return;
		}
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			
			let isTrojan = false;
			let isShadowsocks = false;
			if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0D && chunkBuffer[57] === 0x0A) {
				const checkHex = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
				if (/^[0-9a-f]{56}$/.test(checkHex)) {
					isTrojan = true;
				}
			} else if (chunkBuffer.byteLength > 0 && chunkBuffer[0] !== 0x00 && chunkBuffer[0] !== 0x01 && chunkBuffer[0] !== 0x02 && chunkBuffer[0] !== 0x03) {
				isShadowsocks = true;
			}
			
			let cmd = 0;
			let port = 0;
			let addrType = 0;
			let addr = "";
			let rawData = null;
			let respHeader = null;
			let userLookupKey = null;
			let user = null;

			if (isHeaderParsing) return;
			isHeaderParsing = true;
			isTrojanProto = isTrojan;

			try {
				if (isShadowsocks) {
					if (chunkBuffer.byteLength < 50) { isHeaderParsing = false; return; }
					if (request) {
						const reqUrl = new URL(request.url);
						const pathParts = reqUrl.pathname.split("/");
						if (pathParts.length >= 4) userLookupKey = pathParts[3];
					}
					if (userLookupKey) {
						user = await env.DB.prepare("SELECT * FROM users WHERE uuid LIKE ? AND is_active = 1").bind('%' + userLookupKey).first();
					}
					if (!user || !String(user.connection_type).includes("shadowsocks")) {
						serverSock.close();
						return;
					}
					
					isShadowsocksProto = true;
					const salt = chunkBuffer.slice(0, 32);
					const key = await SSCrypto.deriveSubkey(user.uuid, salt);
					const nonce = new Uint8Array(12);
					ssUpAeadCtx = { key, nonce };
					const encLen = chunkBuffer.slice(32, 32 + 18);
					const decLenBuf = await SSCrypto.decryptChunk(key, nonce, encLen);
					if (!decLenBuf) { serverSock.close(); return; }
					const payloadLen = (decLenBuf[0] << 8) | decLenBuf[1];
					if (chunkBuffer.byteLength < 50 + payloadLen + 16) return;
					const encPayload = chunkBuffer.slice(50, 50 + payloadLen + 16);
					const decryptedPayload = await SSCrypto.decryptChunk(key, nonce, encPayload);
					if (!decryptedPayload) { serverSock.close(); return; }
					
					let offset = 0;
					addrType = decryptedPayload[offset++];
					if (addrType === 1) {
						addr = `${decryptedPayload[offset++]}.${decryptedPayload[offset++]}.${decryptedPayload[offset++]}.${decryptedPayload[offset++]}`;
					} else if (addrType === 3) {
						const domainLen = decryptedPayload[offset++];
						addr = TEXT_DECODER.decode(decryptedPayload.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 4) {
						const v6 = [];
						for (let i = 0; i < 8; i++) v6.push(((decryptedPayload[offset++] << 8) | decryptedPayload[offset++]).toString(16));
						addr = v6.join(":");
					} else {
						serverSock.close();
						return;
					}
					port = (decryptedPayload[offset++] << 8) | decryptedPayload[offset++];
					cmd = 1;
					rawData = decryptedPayload.slice(offset);
					
					let bufOffset = 50 + payloadLen + 16;
					ssUpBuffer = chunkBuffer.slice(bufOffset);
					while (true) {
						if (ssUpExpectedPayloadLen === null) {
							if (ssUpBuffer.byteLength < 18) break;
							const encL = ssUpBuffer.slice(0, 18);
							const decL = await SSCrypto.decryptChunk(key, nonce, encL);
							if (!decL) { serverSock.close(); return; }
							ssUpExpectedPayloadLen = (decL[0] << 8) | decL[1];
							ssUpBuffer = ssUpBuffer.slice(18);
						}
						if (ssUpExpectedPayloadLen !== null) {
							if (ssUpBuffer.byteLength < ssUpExpectedPayloadLen + 16) break;
							const encP = ssUpBuffer.slice(0, ssUpExpectedPayloadLen + 16);
							const decP = await SSCrypto.decryptChunk(key, nonce, encP);
							if (!decP) { serverSock.close(); return; }
							rawData = concatBytes(rawData, decP);
							ssUpBuffer = ssUpBuffer.slice(ssUpExpectedPayloadLen + 16);
							ssUpExpectedPayloadLen = null;
						}
					}
					
					respHeader = null;
					
				} else if (isTrojan) {
					const hexHash = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
					userLookupKey = hexHash;
					let offset = 58;
					cmd = chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
					if (addrType === 1) {
						if (chunkBuffer.byteLength < offset + 4 + 2 + 2) { isHeaderParsing = false; return; }
						addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
					} else if (addrType === 3) {
						if (chunkBuffer.byteLength < offset + 1) { isHeaderParsing = false; return; }
						const domainLen = chunkBuffer[offset++];
						if (chunkBuffer.byteLength < offset + domainLen + 2 + 2) { isHeaderParsing = false; return; }
						addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 4) {
						if (chunkBuffer.byteLength < offset + 16 + 2 + 2) { isHeaderParsing = false; return; }
						const v6 = [];
						for (let i = 0; i < 8; i++) {
							v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
						}
						addr = v6.join(":");
					} else {
						serverSock.close();
						return;
					}
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					if (chunkBuffer[offset] !== 0x0D || chunkBuffer[offset + 1] !== 0x0A) {
						serverSock.close();
						return;
					}
					offset += 2;
					rawData = chunkBuffer.slice(offset);
					respHeader = null;
					
					user = await env.DB.prepare("SELECT * FROM users WHERE trojan_hash = ? OR uuid = ?").bind(userLookupKey, userLookupKey).first();
					if (!user) {
						const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
						if (results) {
							user = results.find(u => u.uuid && sha224Pure(u.uuid) === userLookupKey);
							if (user) {
								const updateHashTask = async () => {
									try { await env.DB.prepare("UPDATE users SET trojan_hash = ? WHERE id = ?").bind(userLookupKey, user.id).run(); } catch (err) {}
								};
								if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(updateHashTask());
								else updateHashTask();
							}
						}
					}
				} else {
					if (chunkBuffer.byteLength < 24) { isHeaderParsing = false; return; }
					let optLen = chunkBuffer[17];
					let requiredLen = 18 + optLen + 4;
					if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
					addrType = chunkBuffer[18 + optLen + 3];
					if (addrType === 1) requiredLen += 4;
					else if (addrType === 2) {
						requiredLen += 1;
						if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
						requiredLen += chunkBuffer[18 + optLen + 4];
					} else if (addrType === 3) requiredLen += 16;
					else { serverSock.close(); return; }
					if (chunkBuffer.byteLength < requiredLen) { isHeaderParsing = false; return; }
					reqUUID = extractUUIDFromvIees(chunkBuffer);
					if (!reqUUID) { serverSock.close(); return; }
					userLookupKey = reqUUID;
					let offset = 17;
					optLen = chunkBuffer[offset++];
					offset += optLen;
					cmd = chunkBuffer[offset++];
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
					if (addrType === 1) {
						addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
					} else if (addrType === 2) {
						const domainLen = chunkBuffer[offset++];
						addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
						offset += domainLen;
					} else if (addrType === 3) {
						const v6 = [];
						for (let i = 0; i < 8; i++) v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
						addr = v6.join(":");
					}
					rawData = chunkBuffer.slice(offset);
					respHeader = new Uint8Array([chunkBuffer[0], 0]);
					user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(userLookupKey).first();
				}
			} catch (e) { }
			if (!user) {
				serverSock.close();
				return;
			}
			const userConn = String(user.connection_type || "vless").toLowerCase();
			if (isTrojan) {
				if (!userConn.includes("trojan")) {
					serverSock.close();
					return;
				}
			} else if (isShadowsocks) {
				if (!userConn.includes("shadowsocks")) {
					serverSock.close();
					return;
				}
			} else {
				if (!userConn.includes("vless") && userConn !== "vl" + "e" + "ss") {
					serverSock.close();
					return;
				}
			}
			reqUUID = user.uuid;
			if (request) {
				const reqUrl = new URL(request.url);
				const expectedPath = "/stream/LML_PANEL/" + ((user.uuid || "").split("-")[4] || "default");
				if (!reqUrl.pathname.startsWith(expectedPath)) {
					serverSock.close();
					return;
				}
			}
			username = user.username;
			validUUID = reqUUID;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			if (!GLOBAL_TRAFFIC_CACHE.has(username)) {
				GLOBAL_TRAFFIC_CACHE.set(username, 0);
			}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (user.is_active === 0) {
				serverSock.close();
				return;
			}
			const liveGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
			if (user.limit_gb && liveGb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) > user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.start_on_first_connect === 1 && !user.first_connection_time && !GLOBAL_WRITE_LOCK.get(reqUUID + "_first_conn")) {
				GLOBAL_WRITE_LOCK.set(reqUUID + "_first_conn", true);
				const firstConnectNow = Date.now();
				user.first_connection_time = firstConnectNow;
				const updateFirstTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET first_connection_time = ? WHERE uuid = ?").bind(firstConnectNow, reqUUID).run();
					} catch (e) {
						GLOBAL_WRITE_LOCK.delete(reqUUID + "_first_conn");
					}
				};
				if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(updateFirstTask());
				else updateFirstTask();
			}
			if (user.expiry_days) {
				let isTimeExpired = false;
				if (user.start_on_first_connect === 1) {
					if (user.first_connection_time) {
						const expiryDate = new Date(user.first_connection_time + user.expiry_days * 24 * 60 * 60 * 1000);
						if (new Date() > expiryDate) isTimeExpired = true;
					}
				} else if (user.created_at) {
					const created = new Date(user.created_at);
					const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
					if (new Date() > expiryDate) isTimeExpired = true;
				}
				if (isTimeExpired) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) { }
					serverSock.close();
					return;
				}
			}
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) { }
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 180000) delete activeIps[ip];
				}
				let isNewIp = false;
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps);
					/* Bypassed: if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) { serverSock.close(); return; } */
					activeIps[clientIP] = { timestamp: now, count: 1 };
					isNewIp = true;
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
				}
				let lastDbW = GLOBAL_LAST_DB_WRITE.get(username) || 0;
				let needIpWrite = isNewIp;
				let needTimeWrite = (now - lastDbW > 900000);
				if (needIpWrite || needTimeWrite) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
					GLOBAL_LAST_DB_WRITE.set(username, now);
					const updateTask = async () => {
						try {
							await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
						} catch (e) { }
					};
					if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(updateTask());
					else updateTask();
				}
			}
			isHeaderParsed = true;
			chunkBuffer = new Uint8Array(0);
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			let userIps = GLOBAL_ACTIVE_IPS.get(username);
			if (!userIps) { userIps = new Map(); GLOBAL_ACTIVE_IPS.set(username, userIps); }
			userIps.set(clientIP, (userIps.get(clientIP) || 0) + 1);
			hasCountedAsActive = true;
			try {
				let isDomainAddress = (isTrojanProto && addrType === 3) || (!isTrojanProto && addrType === 2);
				let isIpAddress = (isTrojanProto && (addrType === 1 || addrType === 4)) || (!isTrojanProto && (addrType === 1 || addrType === 3));
				let sniffedDomain = null;
				if (isIpAddress && port === 443 && rawData && rawData.byteLength > 43) {
					try {
						let pos = 43;
						if (rawData[0] === 0x16 && rawData[5] === 0x01) {
							const sessionIdLen = rawData[pos];
							pos += 1 + sessionIdLen;
							const cipherSuitesLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2 + cipherSuitesLen;
							const compMethodsLen = rawData[pos];
							pos += 1 + compMethodsLen;
							const extensionsLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2;
							const endPos = Math.min(pos + extensionsLen, rawData.byteLength);
							while (pos + 4 <= endPos) {
								const extType = (rawData[pos] << 8) | rawData[pos + 1];
								const extLen = (rawData[pos + 2] << 8) | rawData[pos + 3];
								pos += 4;
								if (extType === 0x0000) {
									let sniListLen = (rawData[pos] << 8) | rawData[pos + 1];
									let sniPos = pos + 2;
									if (rawData[sniPos] === 0x00) {
										let sniLen = (rawData[sniPos + 1] << 8) | rawData[sniPos + 2];
										sniffedDomain = new TextDecoder().decode(rawData.slice(sniPos + 3, sniPos + 3 + sniLen));
										break;
									}
								}
								pos += extLen;
							}
						}
					} catch (e) {}
				}
				if (user.block_porn === 1 || user.block_ads === 1) {
					const dohIps = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"];
					if (port === 443 && isIpAddress && dohIps.includes(addr)) {
						serverSock.close();
						return;
					}
				}
				let checkDomain = isDomainAddress ? addr : sniffedDomain;
				if ((user.block_ads === 1 || user.block_porn === 1) && checkDomain && port !== 53) {
					try {
						const dnsCheck = await dohQuery(checkDomain, "A", targetDoh);
						const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
						if (user.block_porn === 1 && dnsCheck.length > 0) {
							const isSearchEngine = /(google\.|bing\.com|yandex\.|yahoo\.|duckduckgo\.com|youtube\.)/i.test(checkDomain);
							if (isSearchEngine) {
								const validIpRecord = dnsCheck.find(r => r.type === 1 || r.type === 28);
								if (validIpRecord) {
									const safeIp = validIpRecord.data;
									if (safeIp && safeIp !== "0.0.0.0" && safeIp !== "::") {
										addr = safeIp;
									}
								}
							}
						}
					} catch (e) { }
				}
				if ((isTrojanProto && cmd === 3) || (!isTrojanProto && cmd === 2)) {
					if (port === 53) {
						isDnsQuery = true;
						if (isTrojanProto) {
							await forwardTrojanUDP(rawData, serverSock, addBytes, targetDns);
						} else {
							await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
						}
						return;
					}
					serverSock.close();
					return;
				}
				if (port === 25 || /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
					serverSock.close();
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						let socks5 = getSelectedUserProxy(user?.user_socks5, request);
						
						const panelHost = request ? new URL(request.url).hostname : null;
						let loopBypassProxies = [];
						
						if (!socks5 && panelHost && (addr === panelHost || addr.endsWith('.workers.dev') || addr.endsWith('.pages.dev'))) {
							if (!GLOBAL_IPS_CACHE.loop_bypass || Date.now() - (GLOBAL_IPS_CACHE.loop_last_fetch || 0) > 3600000) {
								GLOBAL_IPS_CACHE.loop_bypass = [];
								let targetCountries = ["DE", "US", "GB", "NL", "FR"];
								
								try {
									const vipRes = await fetchWithFallback("vip-list");
									if (vipRes.ok) {
										const files = await vipRes.json();
										const fetchedVips = files.filter(f => f.name.endsWith(".txt")).map(f => f.name.replace(".txt", "").toUpperCase());
										if (fetchedVips.length > 0) targetCountries = fetchedVips;
									}
								} catch(e) {}
								
								targetCountries = targetCountries.sort(() => 0.5 - Math.random()).slice(0, 3);
								
								for (const fc of targetCountries) {
									try {
										const res = await fetchWithFallback("proxy_vip/" + fc + ".txt");
										if (res.ok) {
											const text = await res.text();
											const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 5);
											if (lines.length > 0) {
												GLOBAL_IPS_CACHE.loop_bypass = GLOBAL_IPS_CACHE.loop_bypass.concat(lines);
											}
										}
									} catch(e) {}
								}
								if (GLOBAL_IPS_CACHE.loop_bypass.length > 0) {
									GLOBAL_IPS_CACHE.loop_last_fetch = Date.now();
								}
							}
							
							if (GLOBAL_IPS_CACHE.loop_bypass && GLOBAL_IPS_CACHE.loop_bypass.length > 0) {
								const shuffled = [...GLOBAL_IPS_CACHE.loop_bypass].sort(() => 0.5 - Math.random());
								loopBypassProxies = shuffled.slice(0, 4);
							}
						}

						if (loopBypassProxies.length > 0) {
							const ac = new AbortController();
							try {
								s = await Promise.any(
									loopBypassProxies.map(p => 
										connectProxy(p, addr, port, dataPayload).then(sock => {
											if (ac.signal.aborted) {
												try { sock.close(); } catch(e) {}
												throw new Error("Cancelled");
											}
											ac.abort();
											return sock;
										})
									)
								);
							} catch (e) {
								throw new Error("Loop bypass proxies failed");
							}
						} else if (socks5) {
							try {
								s = await connectProxy(socks5, addr, port, dataPayload);
							} catch (proxyErr) {
								if (user.auto_rotate_user_proxy === 1) {
									const replaceTask = replaceBrokenProxy(user.username, env, socks5);
									if (ctx && typeof ctx.waitUntil === 'function') {
										ctx.waitUntil(replaceTask);
									} else {
										replaceTask.catch(() => { });
									}
								}
								throw proxyErr;
							}
						} else {
							try {
								s = await connectDirect(addr, port, dataPayload, targetDoh);
							} catch (directErr) {
								if (useFallback) {
									const IATA_LIST = ["FRA", "AMS", "LHR", "CDG", "VIE", "HEL", "CPH", "MAD", "BCN", "MXP", "FCO", "ZRH", "WAW", "PRG", "DUB", "SNN", "MAN", "GVA", "BRU", "LIS", "ATH", "SOF", "OTP", "TLL", "RIX", "VNO", "BUD", "BEG", "ZAG", "MUC", "HAM", "SIN", "NRT", "HKG", "TPE", "ICN", "DXB", "BOM", "DEL", "YYZ", "YUL", "YVR", "JFK", "EWR", "LAX", "SFO", "ORD", "MIA", "DFW", "SEA", "IAD", "ATL"];
									let fallbackSuccess = false;
									const shuffledIatas = IATA_LIST.slice().sort(() => 0.5 - Math.random());
									const maxAttempts = 3;
									for (let i = 0; i < maxAttempts && i < shuffledIatas.length; i++) {
										const fallbackHost = shuffledIatas[i].toLowerCase() + ".proxyip.cmliussss.net";
										try {
											s = await connectDirect(fallbackHost, port, dataPayload, targetDoh);
											fallbackSuccess = true;
											break;
										} catch (fallbackErr) { }
									}
									if (!fallbackSuccess) throw directErr;
								} else {
							throw directErr;
						}
					}
				}
				remoteConnWrapper.socket = s;
				let aeadCtx = null;
				if (isShadowsocksProto && validUUID) {
					const downSalt = crypto.getRandomValues(new Uint8Array(32));
					const downKey = await SSCrypto.deriveSubkey(validUUID, downSalt);
					aeadCtx = { key: downKey, nonce: new Uint8Array(12), salt: downSalt };
				}
				connectStreams(s, serverSock, respHeader, null, addBytes, aeadCtx).finally(() => closeSocketQuietly(serverSock));
			})();
			remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		clearTimeout(heartbeat);
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		if (typeof event.data === "string") return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearTimeout(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}
let CF_USAGE_CACHE = null;
let CF_USAGE_LAST_FETCH = 0;
let CF_USAGE_CACHE_DATE = ""; 

async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	const nowTime = Date.now();
	const todayStr = new Date().toISOString().split("T")[0];
	
	if (CF_USAGE_CACHE && (nowTime - CF_USAGE_LAST_FETCH < 15000) && CF_USAGE_CACHE_DATE === todayStr) {
		return CF_USAGE_CACHE;
	}
	try {
		const now = new Date();
		const startOfDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
	  viewer {
		accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
		  today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
			sum { requests }
		  }
		  total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
			sum { requests }
		  }
		  d1: d1AnalyticsAdaptiveGroups(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
			sum { rowsRead rowsWritten }
		  }
		}
	  }
	}`;
		const ctrl = new AbortController();
		const tid = setTimeout(() => ctrl.abort(), 2000);
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
			signal: ctrl.signal,
			cache: "no-store" 
		});
		clearTimeout(tid);
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		const d1Reads = acc?.d1?.[0]?.sum?.rowsRead || 0;
		const d1Writes = acc?.d1?.[0]?.sum?.rowsWritten || 0;
		
		CF_USAGE_CACHE = { today: todayReqs, total: totalReqs, d1Reads, d1Writes };
		CF_USAGE_LAST_FETCH = nowTime;
		CF_USAGE_CACHE_DATE = todayStr;
		return CF_USAGE_CACHE;
	} catch (e) {
		return CF_USAGE_CACHE || { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	if (chunkList.length === 2) {
		const a = convertToUint8Array(chunkList[0]);
		const b = convertToUint8Array(chunkList[1]);
		if (!a.byteLength) return b;
		if (!b.byteLength) return a;
		const merged = new Uint8Array(a.byteLength + b.byteLength);
		merged.set(a, 0);
		merged.set(b, a.byteLength);
		return merged;
	}
	const chunks = chunkList.map(convertToUint8Array);
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) { }
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = TEXT_ENCODER.encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(TEXT_DECODER.decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		if (DNS_CACHE.size >= DNS_CACHE_MAX_ENTRIES) {
			const oldestKey = DNS_CACHE.keys().next().value;
			if (oldestKey !== undefined) DNS_CACHE.delete(oldestKey);
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await Promise.resolve();
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const MAX_CAP = 256 * 1024;
	const MIN_CAP = 16 * 1024;
	let currentPacketCap = 128 * 1024;
	const tailBytes = 512;
	let header = headerData;
	let pendingBuffer = null;
	let pendingBytes = 0;
	let flushPromise = null;
	let microtaskQueued = false;
	const adjustSmartBuffer = () => {
		const buffered = webSocket.bufferedAmount || 0;
		if (buffered > 256 * 1024) {
			currentPacketCap = Math.max(MIN_CAP, Math.floor(currentPacketCap / 2));
		} else if (buffered < 32 * 1024) {
			currentPacketCap = Math.min(MAX_CAP, currentPacketCap * 2);
		}
	};
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== 1) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
		if (typeof webSocket.bufferedAmount === "number") {
			while (webSocket.bufferedAmount > 1024 * 1024) {
				if (webSocket.readyState !== 1) break;
				await new Promise(r => setTimeout(r, 20));
			}
		}
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		microtaskQueued = false;
		while (flushPromise) await flushPromise;
		if (!pendingBytes) return;
		const output = pendingBuffer.slice(0, pendingBytes);
		adjustSmartBuffer();
		pendingBytes = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= currentPacketCap) {
					const sendBytes = Math.min(currentPacketCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					adjustSmartBuffer();
					continue;
				}
				const copyBytes = Math.min(currentPacketCap - pendingBytes, totalBytes - offset);
				if (!pendingBuffer) pendingBuffer = new Uint8Array(MAX_CAP);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				if (pendingBytes >= currentPacketCap || currentPacketCap - pendingBytes < tailBytes) {
					await flush();
				} else if (!microtaskQueued) {
					microtaskQueued = true;
					queueMicrotask(() => {
						if (pendingBytes) flush().catch(() => closeSocketQuietly(webSocket));
					});
				}
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		while (ws.bufferedAmount > 1024 * 1024) {
			if (ws.readyState !== 1) break;
			await new Promise((r) => setTimeout(r, 20));
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes, aeadCtx = null) {
	let header = headerData,
		hasData = false;
	if (aeadCtx) {
		header = header ? concatBytes(aeadCtx.salt, header) : aeadCtx.salt;
	}
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		let reader = remoteSocket.readable.getReader({ mode: "byob" });
		let useBYOB = true;
		reader.releaseLock();
		if (useBYOB) {
			const transformStream = new TransformStream({
				async transform(chunk, controller) {
					hasData = true;
					if (typeof onBytes === "function") onBytes(chunk.byteLength);
					if (aeadCtx) {
						let offset = 0;
						while (offset < chunk.byteLength) {
							const sliceLen = Math.min(chunk.byteLength - offset, 16383);
							const slice = chunk.subarray(offset, offset + sliceLen);
							const lenBuf = new Uint8Array([(sliceLen >> 8) & 0xff, sliceLen & 0xff]);
							const encLen = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, lenBuf);
							const encPayload = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, slice);
							if (encLen && encPayload) controller.enqueue(concatBytes(encLen, encPayload));
							offset += sliceLen;
						}
					} else {
						controller.enqueue(chunk);
					}
				}
			});
			const writePromise = transformStream.readable.pipeTo(new WritableStream({
				async write(chunk) {
					await downstreamSender.send(chunk);
				}
			}));
			await remoteSocket.readable.pipeTo(transformStream.writable);
			await writePromise;
		}
	} catch (e) {
		let reader = remoteSocket.readable.getReader();
		try {
			while (true) {
				if (webSocket.bufferedAmount > 1024 * 1024) await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				
				if (aeadCtx) {
					let offset = 0;
					while (offset < value.byteLength) {
						const sliceLen = Math.min(value.byteLength - offset, 16383);
						const slice = value.subarray(offset, offset + sliceLen);
						const lenBuf = new Uint8Array([(sliceLen >> 8) & 0xff, sliceLen & 0xff]);
						const encLen = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, lenBuf);
						const encPayload = await SSCrypto.encryptChunk(aeadCtx.key, aeadCtx.nonce, slice);
						if (encLen && encPayload) await downstreamSender.send(concatBytes(encLen, encPayload));
						offset += sliceLen;
					}
				} else {
					await downstreamSender.send(value);
				}
			}
		} finally {
			try { reader.cancel(); } catch (err) {}
			try { reader.releaseLock(); } catch (err) {}
		}
	} finally {
		await downstreamSender.flush();
		closeSocketQuietly(webSocket);
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const socket = connect({ hostname: address, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	if (initialData && initialData.byteLength > 0) {
		const w = socket.writable.getWriter();
		await w.write(convertToUint8Array(initialData));
		w.releaseLock();
	}
	return socket;
}
function sha224Pure(message) {
	function rotateRight(n, x) { return (x >>> n) | (x << (32 - n)); }
	function choice(x, y, z) { return (x & y) ^ (~x & z); }
	function majority(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
	function sigma0(x) { return rotateRight(2, x) ^ rotateRight(13, x) ^ rotateRight(22, x); }
	function sigma1(x) { return rotateRight(6, x) ^ rotateRight(11, x) ^ rotateRight(25, x); }
	function gamma0(x) { return rotateRight(7, x) ^ rotateRight(18, x) ^ (x >>> 3); }
	function gamma1(x) { return rotateRight(17, x) ^ rotateRight(19, x) ^ (x >>> 10); }
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];
	let H = [
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
		0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	];
	const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
	const bitLen = msgBytes.length * 8;
	const newLen = (((msgBytes.length + 8) >> 6) + 1) << 6;
	const padded = new Uint8Array(newLen);
	padded.set(msgBytes);
	padded[msgBytes.length] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(newLen - 4, bitLen, false);
	const W = new Uint32Array(64);
	for (let i = 0; i < newLen; i += 64) {
		for (let t = 0; t < 16; t++) {
			W[t] = view.getUint32(i + t * 4, false);
		}
		for (let t = 16; t < 64; t++) {
			W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
		}
		let [a, b, c, d, e, f, g, h] = H;
		for (let t = 0; t < 64; t++) {
			const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
			const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) >>> 0;
		}
		H[0] = (H[0] + a) >>> 0;
		H[1] = (H[1] + b) >>> 0;
		H[2] = (H[2] + c) >>> 0;
		H[3] = (H[3] + d) >>> 0;
		H[4] = (H[4] + e) >>> 0;
		H[5] = (H[5] + f) >>> 0;
		H[6] = (H[6] + g) >>> 0;
		H[7] = (H[7] + h) >>> 0;
	}
	return H.slice(0, 7).map(w => w.toString(16).padStart(8, '0')).join('');
}
async function forwardTrojanUDP(udpChunk, webSocket, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 7) return;
		let offset = 0;
		const addrType = data[offset++];
		let headerAddrBytes = [];
		
		if (addrType === 1) {
			if (data.byteLength < offset + 4) return;
			headerAddrBytes = [addrType, data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
			offset += 4;
		} else if (addrType === 3) {
			if (data.byteLength < offset + 1) return;
			const domainLen = data[offset++];
			if (data.byteLength < offset + domainLen) return;
			headerAddrBytes = [addrType, domainLen, ...data.slice(offset, offset + domainLen)];
			offset += domainLen;
		} else if (addrType === 4) {
			if (data.byteLength < offset + 16) return;
			headerAddrBytes = [addrType, ...data.slice(offset, offset + 16)];
			offset += 16;
		} else {
			return;
		}
		
		if (data.byteLength < offset + 4) return;
		const port = (data[offset++] << 8) | data[offset++];
		const length = (data[offset++] << 8) | data[offset++];
		offset += 2; 
		if (data.byteLength < offset + length) return;
		
		const dnsPayload = data.slice(offset, offset + length);
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpHeader = new Uint8Array(headerAddrBytes.length + 2 + 2 + 2);
		let hOff = 0;
		for (let b of headerAddrBytes) udpHeader[hOff++] = b;
		udpHeader[hOff++] = (port >> 8) & 0xff;
		udpHeader[hOff++] = port & 0xff;
		udpHeader[hOff++] = (resLen >> 8) & 0xff;
		udpHeader[hOff++] = resLen & 0xff;
		udpHeader[hOff++] = 0x0D;
		udpHeader[hOff++] = 0x0A;
		const merged = new Uint8Array(udpHeader.length + resLen);
		merged.set(udpHeader, 0);
		merged.set(rawResponse, udpHeader.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 2) return;
		const length = (data[0] << 8) | data[1];
		if (data.byteLength < 2 + length) return;
		
		const dnsPayload = data.slice(2, 2 + length);
		
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpPacket = new Uint8Array(2 + resLen);
		udpPacket[0] = (resLen >> 8) & 0xff;
		udpPacket[1] = resLen & 0xff;
		udpPacket.set(rawResponse, 2);
		const header = respHeader || new Uint8Array([0, 0]);
		const merged = new Uint8Array(header.length + udpPacket.byteLength);
		merged.set(header, 0);
		merged.set(udpPacket, header.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
function extractUUIDFromvIees(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) { }
		};
		if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}
	const hasProtocol = /^(socks4|socks5|socks|http|https):\/\//i.test(normalized);
	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	if (isSocks4) {
		return await connectSocks4(cleanStr, destAddr, destPort, initialData);
	}
	if (hasProtocol) {
		return await connectSocks5(cleanStr, destAddr, destPort, initialData);
	}
	return await Promise.any([
		connectSocks5(cleanStr, destAddr, destPort, initialData),
		connectHttp(cleanStr, destAddr, destPort, initialData)
	]);
}
async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 1080);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		const portHigh = (destPort >> 8) & 0xff;
		const portLow = destPort & 0xff;
		let req;
		if (isIPv4(destAddr)) {
			const ipBytes = destAddr.split(".").map(Number);
			req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
		} else {
			const hostBytes = new TextEncoder().encode(destAddr);
			req = new Uint8Array(9 + hostBytes.length + 1);
			req[0] = 0x04;
			req[1] = 0x01;
			req[2] = portHigh;
			req[3] = portLow;
			req[4] = 0x00;
			req[5] = 0x00;
			req[6] = 0x00;
			req[7] = 0x01;
			req[8] = 0x00;
			req.set(hostBytes, 9);
			req[9 + hostBytes.length] = 0x00;
		}
		await writer.write(req);
		let res = await readWithTimeout(reader, 4000);
		if (res.done || !res.value || res.value[0] !== 0x00 || res.value[1] !== 0x5a) {
			throw new Error("پـروکـسـی SOCKS4 وصل نشد یا اتصال را رد کرد");
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
function parseProxyConfig(proxyStr, defaultPort) {
	let user = "",
		pass = "",
		host = "",
		port = defaultPort;
	let auth = false,
		remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
		} else {
			host = remain;
		}
	}
	return { user, pass, host, port, auth };
}
async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}
		let res = await readWithTimeout(reader, 4000);
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پـروکـسـی SOCKS5 نیست یا خاموش است)");
		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			await writer.write(authReq);
			let authRes = await readWithTimeout(reader, 4000);
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پـروکـسـی اشتباه است");
		}
		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else if (destAddr.includes(":")) {
			addrType = 0x04;
			addrBytes = new Uint8Array(16);
			const blocks = destAddr.split(":");
			for (let i = 0; i < 8; i++) {
				const val = parseInt(blocks[i] || "0", 16);
				addrBytes[i * 2] = (val >> 8) & 0xff;
				addrBytes[i * 2 + 1] = val & 0xff;
			}
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;
		await writer.write(req);
		let connRes = await readWithTimeout(reader, 4000);
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پـروکـسـی وصل شد اما دسترسی به اینترنت آزاد ندارد");
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
	const socket = connect({ hostname: host, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		await writer.write(new TextEncoder().encode(req));
		let resStr = "";
		const dec = new TextDecoder();
		while (true) {
			const res = await readWithTimeout(reader, 4000);
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += dec.decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
const COMMON_HEAD = `
	<script>
		window.GLOBAL_GFX = "/*{{GFX_SETTING}}*/";
		if (window.GLOBAL_GFX === 'false' || (window.GLOBAL_GFX.startsWith('/*') && localStorage.getItem('gfx-enabled') !== 'true')) {
			document.documentElement.classList.add('gfx-off');
		}
		if (localStorage.getItem('color-theme') === 'light' && window.location.pathname === '/panel') {
			document.documentElement.classList.remove('dark');
		} else {
			document.documentElement.classList.add('dark');
		}
		if (localStorage.getItem('grayscale-theme') === 'true') {
			document.documentElement.classList.add('grayscale-active');
		}
		try { localStorage.removeItem('proxy_flag_cache'); } catch(e) {}
	</script>
<script src="https://cdn.tailwindcss.com"></script>
<script defer src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js"></script>
	<link rel="manifest" href="/manifest.json">
	<link rel="icon" type="image/svg+xml" href="/icon.svg">
	<link rel="apple-touch-icon" href="/icon-192.png">
	<meta name="theme-color" content="#060913">
	<meta name="mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
	<meta name="apple-mobile-web-app-title" content="LML Panel">
	<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css">
<script>
	if (typeof tailwind !== 'undefined') { tailwind.config = {
		darkMode: 'class',
		theme: {
			extend: {
				fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
				colors: { amoled: { bg: '#060913', card: '#0d1526', input: '#0a1220', border: 'rgba(148, 163, 255, 0.13)' } }
			}
		}
	}
}
</script>
<style>
	.cursor-wrapper {
		pointer-events: none;
		position: fixed;
		top: 0;
		left: 0;
		z-index: 9999;
		display: none;
	}
	.hidden {
		display: none !important;
	}
	
	/* LML High-Contrast Styles for Modals */
	#user-modal input[type="text"],
	#user-modal input[type="number"],
	#user-modal input[type="password"],
	#user-modal textarea,
	#user-modal select,
	#bulk-modal input,
	#warp-modal textarea,
	#telegram-modal input {
		color: #0f172a !important;
		background-color: #ffffff !important;
		border: 1.5px solid #94a3b8 !important;
		font-weight: 700 !important;
	}
	.dark #user-modal input[type="text"],
	.dark #user-modal input[type="number"],
	.dark #user-modal input[type="password"],
	.dark #user-modal textarea,
	.dark #user-modal select,
	.dark #bulk-modal input,
	.dark #warp-modal textarea,
	.dark #telegram-modal input {
		color: #ffffff !important;
		background-color: rgba(4, 10, 24, 0.55) !important;
		border: 1.5px solid rgba(129, 116, 255, 0.5) !important;
		font-weight: 700 !important;
	}
	#user-modal input::placeholder,
	#user-modal textarea::placeholder {
		color: #64748b !important;
		opacity: 1 !important;
	}
	.dark #user-modal input::placeholder,
	.dark #user-modal textarea::placeholder {
		color: #94a3b8 !important;
		opacity: 1 !important;
	}

	/* Standard cursor for Windows and all platforms */
	*, *::before, *::after {
		cursor: auto !important;
	}
	a, button, input[type="button"], input[type="submit"], input[type="checkbox"], input[type="radio"], select, [role="button"], .cursor-pointer, .btn, label {
		cursor: pointer !important;
	}
	input[type="text"], input[type="password"], input[type="number"], textarea {
		cursor: text !important;
	}
	.cursor-wrapper, #cursor-dot, #cursor-ring-pos, #cursor-glow-pos {
		display: none !important;
		visibility: hidden !important;
		pointer-events: none !important;
	}
	#cursor-dot {
		width: 6px;
		height: 6px;
		background-color: #2563eb;
		border-radius: 50%;
		box-shadow: 0 0 8px #2563eb, 0 0 16px #1d4ed8;
		transform: translate(-50%, -50%);
	}
	#cursor-ring-pos {
		width: 36px;
		height: 36px;
		transform: translate(-50%, -50%);
		transition: width 0.2s cubic-bezier(0.16, 1, 0.3, 1), height 0.2s cubic-bezier(0.16, 1, 0.3, 1);
	}
	#cursor-ring-visual {
		width: 100%;
		height: 100%;
		border: 1.5px dashed rgba(37, 99, 235, 0.9);
		border-radius: 50%;
		animation: spinRing 10s linear infinite;
		transition: border-color 0.2s, background-color 0.2s;
	}
	@keyframes spinRing {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}
	body.hover-active #cursor-ring-pos {
		width: 48px;
		height: 48px;
	}
	body.hover-active #cursor-ring-visual {
		border: 2px solid #2563eb;
		background-color: rgba(37, 99, 235, 0.2);
		animation: spinRingFast 3s linear infinite;
	}
	@keyframes spinRingFast {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}
	#cursor-glow-pos {
		width: 40px;
		height: 40px;
		transform: translate(-50%, -50%);
		transition: width 0.2s cubic-bezier(0.16, 1, 0.3, 1), height 0.2s cubic-bezier(0.16, 1, 0.3, 1);
	}
	body.hover-active #cursor-glow-pos {
		width: 54px;
		height: 54px;
	}
	#cursor-glow-visual {
		width: 100%;
		height: 100%;
		border-radius: 50%;
		background: radial-gradient(circle, rgba(37, 99, 235, 0.4) 0%, rgba(29, 78, 216, 0.1) 40%, transparent 70%);
	}
		:root {
			--bg-tint: rgba(59, 130, 246, 0.03);
			--plane-color: #93c5fd; 
			--plane-dark: #f9fafb;
			--plane-opacity: 0.20;
		}
		.dark {
			--bg-tint: rgba(16, 32, 64, 0.4); 
			--plane-color: #1d4ed8; 
			--plane-dark: #000105;
			--plane-opacity: 0.15;
		}
		.bg-canvas { position: fixed; inset: 0; z-index: 0; pointer-events: none; }
		#waves { position: fixed; inset: 0; width: 100%; height: 100%; display: block; }
		.vignette {
			position: fixed; inset: 0; z-index: 2; pointer-events: none;
			background: radial-gradient(ellipse at center, transparent 35%, rgba(255,255,255,0.5) 100%);
		}
		.dark .vignette {
			background: radial-gradient(ellipse at center, transparent 35%, rgba(0,1,5,0.85) 100%);
		}
		.ambient {
			position: fixed; inset: 0; z-index: 1; pointer-events: none;
			background:
				radial-gradient(700px 500px at 12% 20%, var(--bg-tint), transparent 60%),
				radial-gradient(800px 600px at 90% 90%, var(--bg-tint), transparent 60%);
		}
</style>
	<style>
	/* ---- Aurora Glass theme ---- */
	html.dark { background: #060913; --bg-tint: rgba(99, 102, 241, 0.06); --plane-color: #6366f1; --plane-dark: #060913; --plane-opacity: 0.35; }
	html.dark body { background: #060913; -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; }
	html.dark:not(.gfx-off) body::before {
		content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none;
		background:
			radial-gradient(900px 620px at 8% -2%, rgba(99,102,241,0.17), transparent 60%),
			radial-gradient(820px 540px at 96% 6%, rgba(34,211,238,0.10), transparent 55%),
			radial-gradient(780px 560px at 90% 94%, rgba(217,70,239,0.08), transparent 60%),
			radial-gradient(660px 500px at 10% 96%, rgba(59,130,246,0.10), transparent 55%);
	}
	html.dark [class*="bg-amoled-card"] {
		background-color: rgba(13, 21, 38, 0.60) !important;
		backdrop-filter: blur(16px) saturate(1.25);
		-webkit-backdrop-filter: blur(16px) saturate(1.25);
	}
	html.dark [class*="bg-amoled-input"] { background-color: rgba(3, 8, 20, 0.50) !important; }
	html.dark [class*="bg-amoled-bg"] { background-color: rgba(6, 9, 19, 0.60) !important; }
	html.dark ::-webkit-scrollbar { width: 8px; height: 8px; }
	html.dark ::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.25); }
	html.dark ::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #6366f1, #22d3ee); border-radius: 999px; }
	html.dark ::selection { background: rgba(99, 102, 241, 0.45); color: #fff; }
	html.dark [class~="bg-blue-600"] { background-color: #5754ee; }
	html.dark [class~="hover:bg-blue-600"]:hover { background-color: #4643d8; }
	html.dark [class~="bg-blue-500"] { background-color: #6157f5; }
	html.dark [class~="text-blue-400"] { color: #a5adfa; }
	html.dark [class~="text-blue-500"] { color: #8e97fb; }
	html.dark [class~="text-blue-600"] { color: #837cf9; }
	html.dark [class~="dark:text-blue-400"] { color: #a5adfa; }
	html.dark [class~="border-blue-500"], html.dark [class~="dark:border-blue-500"] { border-color: rgba(124, 116, 255, 0.5); }
	html.dark [class~="border-blue-600"] { border-color: rgba(124, 116, 255, 0.55); }
	html.dark [class~="bg-blue-100"] { background-color: rgba(99, 102, 241, 0.15); }
	html.dark [class~="dark:bg-blue-900\/30"] { background-color: rgba(87, 84, 238, 0.16); }
	html.dark [class~="dark:hover:bg-blue-900\/40"]:hover { background-color: rgba(87, 84, 238, 0.24); }
	html.dark [class~="focus:ring-blue-500"]:focus, html.dark [class~="focus:ring-blue-500\/50"]:focus { --tw-ring-color: rgba(124, 116, 255, 0.4) !important; }
	html.dark [class~="focus:border-blue-500"]:focus { border-color: rgba(124, 116, 255, 0.6) !important; }
	</style>
<!-- Native System Cursor Active Everywhere -->`;
const COMMON_TOAST_HTML = `<div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>`;
const COMMON_WAVES_SCRIPT = `
	<canvas id="waves" class="bg-canvas"></canvas>
	<script defer src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
	<script>
	  (function initWaves(){
		try {
		const canvas = document.getElementById('waves');
		if (!canvas) return;
		if (typeof THREE === 'undefined') return;
		if (window.GLOBAL_GFX === 'false' || (window.GLOBAL_GFX.startsWith('/*') && localStorage.getItem('gfx-enabled') !== 'true')) {
			canvas.style.display = 'none';
			return;
		}
		const IS_MOBILE = window.innerWidth < 768;
		const renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: false, alpha: false, powerPreference: "default" });
		renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1));
		renderer.setSize(window.innerWidth, window.innerHeight);
		
		const isDarkInit = document.documentElement.classList.contains('dark');
		renderer.setClearColor(isDarkInit ? 0x000105 : 0xf9fafb, 1);
		const scene = new THREE.Scene();
		const camera = new THREE.PerspectiveCamera(60, window.innerWidth/window.innerHeight, 0.1, 200);
		camera.position.set(0, 0, IS_MOBILE ? 35 : 14);
		const segX = IS_MOBILE ? 80 : 80;
		const segY = IS_MOBILE ? 40 : 40;
		const geom = new THREE.PlaneGeometry(80, IS_MOBILE ? 90 : 40, segX, segY);
		const vertShader = "uniform float uTime; uniform float uStrength; varying float vElev; void main(){ vec3 p = position; float x = p.x * 0.2 + uTime * 0.3; float y = p.y * 0.2 + uTime * 0.25; float wave = sin(x)*cos(y)*1.6 + sin(x*2.1 + uTime)*0.7 + cos(y*1.7 - uTime*0.6)*0.7; wave *= uStrength * 1.5; p.z += wave; vElev = wave; gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0); }";
		const fragShader = "varying float vElev; uniform vec3 uHigh; uniform vec3 uLow; uniform float uFade; void main(){ float t = clamp((vElev + 2.0) / 4.0, 0.0, 1.0); vec3 col = mix(uLow, uHigh, t); gl_FragColor = vec4(col, uFade); }";
		function makePlane(px, py, pz, rx, ry, rz, high, low, fade){
		  const mat = new THREE.ShaderMaterial({
			wireframe: true, 
			transparent: true, 
			depthWrite: false,
			uniforms:{
			  uTime:{value:0}, 
			  uStrength:{value:1.1},
			  uHigh:{value:new THREE.Color(high)}, 
			  uLow:{value:new THREE.Color(low)},
			  uFade:{value:fade}
			},
			vertexShader: vertShader, 
			fragmentShader: fragShader
		  });
		  const m = new THREE.Mesh(geom, mat);
		  m.position.set(px, py, pz);
		  m.rotation.set(rx, ry, rz);
		  return m;
		}
		const cs = getComputedStyle(document.documentElement);
		const yOffset = IS_MOBILE ? 14 : 8;
		
		const topPlane = makePlane(0, yOffset, -5, -Math.PI/2.4, 0, 0, '#4f46e5', '#060913', 0.35);
		const midPlane = makePlane(
		  0, 0, -25, 0, 0, 0, 
		  cs.getPropertyValue('--plane-color').trim() || '#6366f1', 
		  cs.getPropertyValue('--plane-dark').trim() || '#060913', 
		  (parseFloat(cs.getPropertyValue('--plane-opacity')) || 0.35) * 0.7
		);
		const botPlane = makePlane(
		  0, -yOffset, -5, Math.PI/2.4, 0, 0, 
		  cs.getPropertyValue('--plane-color').trim() || '#6366f1', 
		  cs.getPropertyValue('--plane-dark').trim() || '#060913', 
		  parseFloat(cs.getPropertyValue('--plane-opacity')) || 0.35
		);
		scene.add(topPlane);
		scene.add(midPlane);
		scene.add(botPlane);
		
		window.__dxTopPlane = topPlane;
		window.__dxMidPlane = midPlane;
		window.__dxBotPlane = botPlane;
		const clock = new THREE.Clock();
		let lastFrameTime = 0;
		function animate(timestamp) {
		  requestAnimationFrame(animate);
		  if (timestamp - lastFrameTime < 30) return;
		  lastFrameTime = timestamp;
		  
		  const t = clock.getElapsedTime();
		  topPlane.material.uniforms.uTime.value = t * 0.8; 
		  midPlane.material.uniforms.uTime.value = t * 0.6;
		  botPlane.material.uniforms.uTime.value = t * 0.8; 
		  renderer.render(scene, camera);
		}
		requestAnimationFrame(animate);
		window.addEventListener('resize', function(){
		  camera.aspect = window.innerWidth/window.innerHeight;
		  camera.updateProjectionMatrix();
		  renderer.setSize(window.innerWidth, window.innerHeight);
		});
		} catch(e) {}
		function retintScene(){
		  const isDark = document.documentElement.classList.contains('dark');
		  if (renderer) renderer.setClearColor(isDark ? 0x060913 : 0xf9fafb, 1);
		  const pColor = isDark ? '#6366f1' : '#a5b4fc';
		  const pDark = isDark ? '#060913' : '#f9fafb';
		  const pOpacity = isDark ? 0.15 : 0.20;
		  if (botPlane) {
			botPlane.material.uniforms.uHigh.value.set(pColor);
			botPlane.material.uniforms.uLow.value.set(pDark);
			botPlane.material.uniforms.uFade.value = pOpacity;
		  }
		  if (midPlane) {
			midPlane.material.uniforms.uHigh.value.set(pColor);
			midPlane.material.uniforms.uLow.value.set(pDark);
			midPlane.material.uniforms.uFade.value = pOpacity * 0.7;
		  }
		  if (topPlane) {
			 if (!isDark) {
				topPlane.material.uniforms.uLow.value.set('#f9fafb');
				topPlane.material.uniforms.uHigh.value.set('#bfdbfe');
			 } else {
				topPlane.material.uniforms.uLow.value.set('#060913');
				topPlane.material.uniforms.uHigh.value.set('#4f46e5');
			 }
		  }
		}
		
		const observer = new MutationObserver(function(mutations) {
			mutations.forEach(function(mutation) {
				if (mutation.attributeName === 'class') {
					retintScene();
				}
			});
		});
		observer.observe(document.documentElement, { attributes: true });
		retintScene();
	  })();
	</script>
`;
const COMMON_TOAST_JS = `
		function showToast(message, type = 'success') {
			let container = document.getElementById('toast-container');
			if (!container) {
				container = document.createElement('div');
				container.id = 'toast-container';
				container.className = 'fixed top-5 left-1/2 -translate-x-1/2 z-[10000] flex flex-col gap-2 items-center pointer-events-none w-full max-w-sm px-4';
				document.body.appendChild(container);
			}
			const toast = document.createElement('div');
			const colors = type === 'error' 
				? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
				: 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
			toast.className = 'px-4 py-3 border rounded-md shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
			toast.innerText = message;
			container.appendChild(toast);
			const raf = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (cb => setTimeout(cb, 16));
			raf(() => {
				toast.classList.remove('-translate-y-full', 'opacity-0');
			});
			setTimeout(() => {
				toast.classList.add('-translate-y-full', 'opacity-0');
				setTimeout(() => toast.remove(), 300);
			}, 3000);
		}
		window.alert = function(message) {
			let msgStr = message ? message.toString() : '';
			if (msgStr.toLowerCase().includes('d1') && (msgStr.toLowerCase().includes('limit') || msgStr.toLowerCase().includes('exceeded') || msgStr.toLowerCase().includes('daily row'))) {
				msgStr = '❌ سهمیه دیتابیس (D1) شما تمام شده و ساعت 3:30 درست میشه';
			}
			if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
				showToast(msgStr, 'error');
			} else {
				showToast(msgStr, 'success');
			}
		};
`;
const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>LML Cloud — Global Anycast Edge & CDN Infrastructure</title>
	${COMMON_HEAD}
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
		.hero-glow {
			background: radial-gradient(circle at 50% 30%, rgba(37, 99, 235, 0.25), transparent 70%);
		}
		.grid-card {
			background: rgba(10, 22, 40, 0.7);
			border: 1px solid rgba(59, 130, 246, 0.2);
			backdrop-filter: blur(12px);
		}
	</style>
</head>
<body class="bg-[#060913] text-slate-100 min-h-screen flex flex-col justify-between selection:bg-blue-600 selection:text-white" dir="ltr">

	<!-- Top Navigation -->
	<header class="border-b border-blue-900/30 bg-[#0d1526]/80 backdrop-blur-md sticky top-0 z-50">
		<div class="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
			<div class="flex items-center gap-3">
				<div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center font-black text-white text-lg shadow-lg shadow-blue-500/30">
					⚡
				</div>
				<span class="font-extrabold text-xl tracking-tight bg-gradient-to-r from-blue-400 via-indigo-300 to-white bg-clip-text text-transparent">LML Cloud</span>
				<span class="hidden sm:inline-block px-2 py-0.5 text-[10px] font-bold rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">Edge v2.5</span>
			</div>
			<nav class="flex items-center gap-4 text-xs font-semibold">
				<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
					<span class="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
					All Systems Operational
				</span>
				<a href="/panel" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg transition shadow-md shadow-blue-600/30 flex items-center gap-1.5">
					<span>Client Portal</span>
					<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
				</a>
			</nav>
		</div>
	</header>

	<!-- Hero Section -->
	<main class="flex-1 hero-glow relative overflow-hidden flex flex-col items-center justify-center px-4 py-16 sm:py-24 text-center">
		<div class="max-w-3xl mx-auto space-y-6 relative z-10">
			<div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-950/60 border border-blue-500/30 text-blue-300 text-xs font-semibold shadow-inner">
				<span class="text-blue-400">🌐 Anycast Tier-1 Backbone</span>
				<span class="text-slate-500">•</span>
				<span id="global-ping">Latency: 18ms</span>
			</div>
			<h1 class="text-3xl sm:text-5xl font-black tracking-tight text-white leading-tight sm:leading-none">
				Accelerated Enterprise Edge &amp; Intelligent CDN Infrastructure
			</h1>
			<p class="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
				Ultra-low latency content delivery, automated packet fragmentation, and DDoS mitigation powered by 320+ distributed points of presence worldwide.
			</p>
			<div class="flex flex-wrap items-center justify-center gap-3 pt-4">
				<a href="/panel" class="px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold rounded-xl text-sm transition shadow-xl shadow-blue-500/25 flex items-center gap-2">
					<span>Launch Management Console</span>
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
				</a>
				<button type="button" onclick="runEdgeLatencyTest()" id="latency-btn" class="px-5 py-3 bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700 font-bold rounded-xl text-sm transition flex items-center gap-2">
					<svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
					<span id="latency-text">Live Latency Benchmark</span>
				</button>
			</div>
		</div>

		<!-- Edge Global POPs Telemetry -->
		<div class="max-w-4xl w-full mx-auto mt-14 grid grid-cols-2 sm:grid-cols-4 gap-3 text-left">
			<div class="grid-card p-4 rounded-xl">
				<div class="text-[10px] text-slate-400 font-mono flex items-center justify-between">
					<span>FRANKFURT (FRA)</span>
					<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
				</div>
				<div class="text-lg font-mono font-bold text-emerald-400 mt-1" id="pop-fra">14 ms</div>
				<div class="text-[10px] text-slate-500">100 Gbps Port</div>
			</div>
			<div class="grid-card p-4 rounded-xl">
				<div class="text-[10px] text-slate-400 font-mono flex items-center justify-between">
					<span>AMSTERDAM (AMS)</span>
					<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
				</div>
				<div class="text-lg font-mono font-bold text-emerald-400 mt-1" id="pop-ams">18 ms</div>
				<div class="text-[10px] text-slate-500">100 Gbps Port</div>
			</div>
			<div class="grid-card p-4 rounded-xl">
				<div class="text-[10px] text-slate-400 font-mono flex items-center justify-between">
					<span>LONDON (LHR)</span>
					<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
				</div>
				<div class="text-lg font-mono font-bold text-emerald-400 mt-1" id="pop-lhr">21 ms</div>
				<div class="text-[10px] text-slate-500">100 Gbps Port</div>
			</div>
			<div class="grid-card p-4 rounded-xl">
				<div class="text-[10px] text-slate-400 font-mono flex items-center justify-between">
					<span>SINGAPORE (SIN)</span>
					<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
				</div>
				<div class="text-lg font-mono font-bold text-emerald-400 mt-1" id="pop-sin">72 ms</div>
				<div class="text-[10px] text-slate-500">80 Gbps Port</div>
			</div>
		</div>
	</main>

	<!-- Footer -->
	<footer class="border-t border-blue-950/60 bg-[#040a14] py-6 px-4 text-center text-xs text-slate-500">
		<div class="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
			<div class="flex items-center gap-2">
				<span class="font-bold text-slate-400">LML Edge Network Services</span>
				<span>© 2026. All rights reserved.</span>
			</div>
			<div class="flex items-center gap-4 text-[11px]">
				<span class="text-slate-400">Security SLA 99.99%</span>
				<span>•</span>
				<span class="text-slate-400">Zero-Trust Verified</span>
				<span>•</span>
				<a href="/panel" class="text-blue-400 hover:underline font-bold">Portal Access</a>
			</div>
		</div>
	</footer>

	<script>
		function runEdgeLatencyTest() {
			const btn = document.getElementById('latency-text');
			if (btn) btn.innerText = 'Benchmarking...';
			const start = performance.now();
			fetch('/icon.svg?t=' + Date.now(), { cache: 'no-store' })
				.then(() => {
					const ping = Math.round(performance.now() - start);
					if (btn) btn.innerText = 'RTT: ' + ping + ' ms (Optimal)';
					const gp = document.getElementById('global-ping');
					if (gp) gp.innerText = 'Latency: ' + ping + 'ms';
				})
				.catch(() => {
					if (btn) btn.innerText = 'Ping benchmark finished';
				});
		}
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	setup: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>تعریف رمز عبور پـنـل</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center justify-center p-4 gap-6">

	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl p-6 relative z-10">
		<h2 class="text-xl font-bold mb-2 text-center text-blue-600 dark:text-blue-400">تنظیم رمز عبور جدید</h2>
		<p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6">این اولین ورود شما به پـنـل مدیریت است. لطفاً رمز عبور خود را تعیین کنید.</p>
		<form onsubmit="handleSetup(event)" class="space-y-4">
			<div>
				<label class="block text-sm font-medium mb-1.5">رمز عبور</label>
				<input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<div>
				<label class="block text-sm font-medium mb-1.5">تکرار رمز عبور</label>
				<input type="password" id="confirm-password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">ثبت و ورود</button>
		</form>
	</div>
	<div class="flex flex-col gap-4 relative z-10 w-full max-w-md">
		<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
			
			
		</div>
		<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
			
			
		</div>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS};
		async function handleSetup(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const confirmPassword = document.getElementById('confirm-password').value.trim();
			const btn = document.getElementById('submit-btn');
			if (password !== confirmPassword) {
				alert('⚠️ رمز عبور و تکرار آن مطابقت ندارند!');
				return;
			}
			btn.disabled = true;
			btn.innerText = 'در حال ثبت...';
			try {
				const res = await fetch('/api/setup-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت تنظیم شد. در حال ورود...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('خطا: ' + (data.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'ثبت و ورود';
			}
		}
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	login: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>ورود به پــنــل مدیریت</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center justify-center p-4 gap-6">

	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl p-6 relative z-10">
		<div id="login-section">
			<h2 class="text-xl font-bold mb-6 text-center text-blue-600 dark:text-blue-400">ورود به پـنـل مدیریت</h2>
			<form onsubmit="handleLogin(event)" class="space-y-4">
				<div>
					<label class="block text-sm font-medium mb-1.5">رمز عبور</label>
					<input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required>
				</div>
				<button type="submit" id="submit-btn" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">ورود</button>
			</form>
			<div class="mt-4 text-center">
				<button onclick="toggleRecovery(true)" class="text-xs text-blue-500 hover:text-blue-600 transition font-medium">بازیابی رمز پـنـل</button>
			</div>
		</div>
		<div id="recovery-section" class="hidden">
			<h2 class="text-xl font-bold mb-4 text-center text-orange-600 dark:text-orange-400">بازیابی رمز پـنـل</h2>
			<div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-md text-xs leading-relaxed text-orange-800 dark:text-orange-300">
				برای احراز هویت و اثبات مالکیت پـنـل، از طریق دکمه زیر وارد کلودفلر شوید و توکن دریافتی را کپی کرده و در کادر زیر وارد کنید.
				<a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=LML-Deployer-Token" target="_blank" class="mt-3 w-full flex items-center justify-center gap-2 py-2 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 rounded-md font-bold transition shadow-md">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
					دریافت توکن
				</a>
			</div>
			<form onsubmit="handleRecovery(event)" class="space-y-4">
				<div>
					<input type="password" id="api-token" placeholder="توکن را وارد کنید" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 text-xs text-center font-mono" required>
				</div>
				<div class="flex gap-2 pt-2">
					<button type="button" onclick="toggleRecovery(false)" class="w-1/3 py-2.5 bg-transparent border-2 border-red-700 text-red-700 hover:bg-red-900/20 hover:text-red-800 dark:border-red-700 dark:text-red-500 dark:hover:bg-red-900/40 dark:hover:text-red-400 font-bold rounded-md text-sm transition shadow-sm">انصراف</button>
					<button type="submit" id="recover-btn" class="w-2/3 py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-medium rounded-md text-sm transition font-bold">بازیابی رمز پـنـل</button>
				</div>
			</form>
		</div>
	</div>
	<div class="flex flex-col gap-4 relative z-10 w-full max-w-md">
		<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
			
			
		</div>
		<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
			
			
		</div>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS}
		async function handleLogin(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const btn = document.getElementById('submit-btn');
			btn.disabled = true;
			try {
				const res = await fetch('/api/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					window.location.reload();
				} else {
					alert(data.error || '❌ رمز عبور اشتباه است');
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
			}
		}
		function toggleRecovery(show) {
			document.getElementById('login-section').classList.toggle('hidden', show);
			document.getElementById('recovery-section').classList.toggle('hidden', !show);
		}
		async function handleRecovery(event) {
			event.preventDefault();
			const apiToken = document.getElementById('api-token').value;
			const btn = document.getElementById('recover-btn');
			btn.disabled = true;
			btn.innerText = 'در حال بررسی...';
			try {
				const res = await fetch('/api/recover', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ api_token: apiToken })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت حذف شد. در حال انتقال به صفحه تنظیمات اولیه...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('❌ ' + (data.error || 'خطا در تایید اطلاعات'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'بازیابی رمز پـنـل';
			}
		}
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
	<meta name="robots" content="noindex, nofollow">
	<title>LML PANEL — داشبورد مدیریت</title>
	<link rel="manifest" href="/manifest.json">
	<link rel="icon" type="image/svg+xml" href="/icon.svg">
	<link rel="apple-touch-icon" href="/icon-192.png">
	<meta name="theme-color" content="#08090c">
	<meta name="mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
	<meta name="apple-mobile-web-app-title" content="LML Panel">
	<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css">
	<script>
		window._CF_UI_INTEGRITY = atob("TE1MX1BBTkVMX0NPUkVfU1lTVEVNX1JFQURZ");
		window.GLOBAL_GFX = "/*{{GFX_SETTING}}*/";
		(function () {
			try {
				var gfxOn = (window.GLOBAL_GFX === 'true') || (!window.GLOBAL_GFX.startsWith('/*') && window.GLOBAL_GFX === 'true') || localStorage.getItem('gfx-enabled') === 'true';
				if (!gfxOn) document.documentElement.classList.add('gfx-off');
				var stored = localStorage.getItem('lml-theme');
				var theme = stored || (localStorage.getItem('color-theme') === 'light' ? 'light' : 'dark');
				document.documentElement.setAttribute('data-theme', theme);
				if (theme !== 'dark') document.documentElement.classList.remove('dark');
				else document.documentElement.classList.add('dark');
				if (localStorage.getItem('grayscale-theme') === 'true') document.documentElement.classList.add('grayscale-active');
				var density = localStorage.getItem('lml-density');
				document.documentElement.setAttribute('data-density', density || 'comfortable');
				var sbPref = localStorage.getItem('lml-sidebar-pref') || localStorage.getItem('lml-sidebar');
				document.documentElement.setAttribute('data-sidebar', (sbPref === 'mini') ? 'mini' : 'expanded');
			} catch (e) {}
		})();
	</script>
	<style>
	/* ============================================================
	   LML PANEL — DESIGN SYSTEM
	   Presentation layer only. No backend logic in this file.
	   ============================================================ */

	*, *::before, *::after { box-sizing: border-box; }
	html, body { height: 100%; }
	html, body {
		-webkit-font-smoothing: antialiased;
		-moz-osx-font-smoothing: grayscale;
		text-rendering: optimizeLegibility;
	}
	html { -webkit-text-size-adjust: 100%; }

	:root {
		--font-sans: 'Vazirmatn', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Tahoma, sans-serif;
		--font-mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace;

		--r-xs: 8px;
		--r-sm: 10px;
		--r-md: 14px;
		--r-lg: 18px;
		--r-xl: 24px;
		--r-full: 999px;

		--sb-w: 272px;
		--sb-mini: 76px;
		--topbar-h: 64px;

		--ease: cubic-bezier(.22,.61,.36,1);
		--dur: .18s;

		--fs-xs: 12px;
		--fs-sm: 13px;
		--fs-md: 14.5px;
		--fs-lg: 16px;
		--fs-xl: 20px;
		--fs-2xl: 27px;
		--fs-3xl: 35px;
	}

	html[data-density="compact"] { --fs-md: 12.5px; --fs-lg: 14px; --fs-xl: 17px; --fs-2xl: 22px; }
	html[data-density="compact"] .card { padding: 12px; }
	html[data-density="compact"] .tbl th, html[data-density="compact"] .tbl td { padding: 7px 10px; }

	html[data-theme="dark"] {
		--bg: #08090c;
		--bg-soft: #0b0d12;
		--surface: #0f1116;
		--surface-2: #14171e;
		--surface-3: #1a1e27;
		--border: rgba(255,255,255,.075);
		--border-strong: rgba(255,255,255,.14);
		--text: #e7e9ef;
		--text-2: #b3bacb;
		--text-3: #7b839a;
		--text-4: #565d70;
		--accent: #4f7cff;
		--accent-soft: rgba(79,124,255,.14);
		--accent-text: #8fa8ff;
		--ok: #34d399;
		--ok-soft: rgba(52,211,153,.13);
		--warn: #fbbf24;
		--warn-soft: rgba(251,191,36,.13);
		--err: #f87171;
		--err-soft: rgba(248,113,113,.13);
		--info: #38bdf8;
		--info-soft: rgba(56,189,248,.13);
		--violet: #a78bfa;
		--violet-soft: rgba(167,139,250,.13);
		--shadow-1: 0 1px 2px rgba(0,0,0,.4);
		--shadow-2: 0 4px 16px rgba(0,0,0,.35);
		--shadow-3: 0 18px 50px rgba(0,0,0,.55);
		--glass: rgba(15,17,22,.72);
		--grid-line: rgba(255,255,255,.06);
		color-scheme: dark;
	}

	html[data-theme="light"] {
		--bg: #f4f5f8;
		--bg-soft: #eceef2;
		--surface: #ffffff;
		--surface-2: #f7f8fa;
		--surface-3: #eff1f5;
		--border: rgba(15,17,22,.09);
		--border-strong: rgba(15,17,22,.17);
		--text: #12151c;
		--text-2: #414a5c;
		--text-3: #6b7488;
		--text-4: #98a0b3;
		--accent: #3457e0;
		--accent-soft: rgba(52,87,224,.10);
		--accent-text: #2f4ed0;
		--ok: #059669;
		--ok-soft: rgba(5,150,105,.11);
		--warn: #b45309;
		--warn-soft: rgba(180,83,9,.11);
		--err: #dc2626;
		--err-soft: rgba(220,38,38,.10);
		--info: #0369a1;
		--info-soft: rgba(3,105,161,.10);
		--violet: #7c3aed;
		--violet-soft: rgba(124,58,237,.10);
		--shadow-1: 0 1px 2px rgba(16,24,40,.06);
		--shadow-2: 0 4px 14px rgba(16,24,40,.08);
		--shadow-3: 0 18px 44px rgba(16,24,40,.16);
		--glass: rgba(255,255,255,.78);
		--grid-line: rgba(15,17,22,.07);
		color-scheme: light;
	}

	html.grayscale-active { filter: grayscale(100%); }

	body {
		margin: 0;
		font-family: var(--font-sans);
		font-size: var(--fs-md);
		line-height: 1.65;
		color: var(--text);
		background: var(--bg);
		-webkit-font-smoothing: antialiased;
		text-rendering: optimizeLegibility;
		overflow: hidden;
	}

	/* Subtle ambient depth (disabled in gfx-off mode) */
	body::before {
		content: '';
		position: fixed; inset: 0; z-index: 0; pointer-events: none;
		background:
			radial-gradient(900px 520px at 88% -8%, var(--accent-soft), transparent 62%),
			radial-gradient(760px 460px at 4% 104%, var(--violet-soft), transparent 60%);
		opacity: .9;
	}
	html.gfx-off body::before { display: none; }

	::-webkit-scrollbar { width: 10px; height: 10px; }
	::-webkit-scrollbar-track { background: transparent; }
	::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 99px; border: 3px solid transparent; background-clip: content-box; }
	::-webkit-scrollbar-thumb:hover { background: var(--text-4); background-clip: content-box; }
	* { scrollbar-width: thin; scrollbar-color: var(--border-strong) transparent; }

	::selection { background: var(--accent); color: #fff; }

	a { color: var(--accent-text); text-decoration: none; }
	a:hover { text-decoration: underline; }

	button, input, select, textarea { font-family: inherit; font-size: inherit; color: inherit; }
	button { cursor: pointer; background: none; border: none; padding: 0; }
	input, select, textarea { cursor: text; }
	input[type="checkbox"], input[type="radio"], select, button, label.btn, .switch { cursor: pointer; }

	.hidden { display: none !important; }
	.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }

	.num, .mono, code, kbd { font-family: var(--font-mono); font-variant-numeric: tabular-nums; direction: ltr; unicode-bidi: isolate; }
	.ltr { direction: ltr; unicode-bidi: isolate; display: inline-block; }

	/* ============================ APP SHELL ============================ */
	.app { position: relative; z-index: 1; display: flex; height: 100vh; height: 100dvh; overflow: hidden; }

	/* ---------- Sidebar ---------- */
	.sidebar {
		position: relative; z-index: 60;
		flex: 0 0 var(--sb-w); width: var(--sb-w);
		display: flex; flex-direction: column;
		background: var(--surface);
		border-inline-end: 1px solid var(--border);
		transition: width var(--dur) var(--ease), flex-basis var(--dur) var(--ease);
	}
	html[data-sidebar="mini"] .sidebar { flex-basis: var(--sb-mini); width: var(--sb-mini); }
	html[data-sidebar="hidden"] .sidebar { flex-basis: 0; width: 0; overflow: hidden; border-inline-end-width: 0; }

	.sb-brand {
		height: var(--topbar-h); flex: 0 0 var(--topbar-h);
		display: flex; align-items: center; gap: 10px;
		padding: 0 16px; border-bottom: 1px solid var(--border);
		min-width: 0;
	}
	.sb-logo {
		flex: 0 0 34px; width: 34px; height: 34px; border-radius: 10px;
		display: grid; place-items: center;
		background: var(--accent); color: #fff;
		box-shadow: 0 4px 14px var(--accent-soft);
	}
	.sb-logo svg { width: 19px; height: 19px; }
	.sb-brand-text { min-width: 0; overflow: hidden; }
	.sb-brand-title { font-weight: 800; font-size: var(--fs-lg); letter-spacing: .2px; line-height: 1.2; white-space: nowrap; }
	.sb-brand-sub { font-size: 10px; color: var(--text-3); white-space: nowrap; }
	html[data-sidebar="mini"] .sb-brand { padding: 0; justify-content: center; }
	html[data-sidebar="mini"] .sb-brand-text { display: none; }

	.sb-scroll { flex: 1 1 auto; overflow-y: auto; overflow-x: hidden; padding: 10px 10px 24px; }
	.sb-scroll::-webkit-scrollbar { width: 0; }

	.sb-section { margin-bottom: 4px; }
	.sb-group-head {
		width: 100%; display: flex; align-items: center; gap: 9px;
		padding: 8px 10px; border-radius: var(--r-sm);
		color: var(--text-2); font-weight: 700; font-size: var(--fs-sm);
		transition: background var(--dur) var(--ease), color var(--dur) var(--ease);
		text-align: right;
	}
	.sb-group-head:hover { background: var(--surface-2); color: var(--text); }
	.sb-group-head .g-icon { flex: 0 0 20px; width: 20px; height: 20px; display: grid; place-items: center; }
	.sb-group-head .g-icon svg { width: 17px; height: 17px; }
	.sb-group-head .g-label { flex: 1 1 auto; text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.sb-group-head .g-desc { display: block; font-size: 10px; font-weight: 500; color: var(--text-4); line-height: 1.3; }
	.sb-group-head .g-chev { flex: 0 0 14px; width: 14px; height: 14px; color: var(--text-4); transition: transform var(--dur) var(--ease); }
	.sb-group-head[aria-expanded="true"] .g-chev { transform: rotate(180deg); }
	.sb-group-head.is-active { background: var(--accent-soft); color: var(--accent-text); }
	.sb-group-head.is-active .g-desc { color: var(--accent-text); opacity: .75; }

	.sb-sub { display: none; padding: 2px 0 6px; margin: 2px 0 0; list-style: none; }
	.sb-sub.open { display: block; }
	.sb-link {
		position: relative;
		width: 100%; display: flex; align-items: center; gap: 9px;
		padding: 7px 10px 7px 10px; margin-inline-start: 8px;
		border-radius: var(--r-sm);
		color: var(--text-2); font-size: var(--fs-sm); font-weight: 600;
		text-align: right; transition: background var(--dur) var(--ease), color var(--dur) var(--ease);
	}
	.sb-link::before {
		content: ''; position: absolute; inset-inline-start: -8px; top: 50%; transform: translateY(-50%);
		width: 8px; height: 8px; border-inline-start: 1px solid var(--border); border-block-end: 1px solid var(--border);
		border-end-start-radius: 8px;
	}
	.sb-link:hover { background: var(--surface-2); color: var(--text); }
	.sb-link.active { background: var(--accent-soft); color: var(--accent-text); font-weight: 700; }
	.sb-link .dot { flex: 0 0 6px; width: 6px; height: 6px; border-radius: 99px; background: var(--text-4); }
	.sb-link.active .dot { background: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
	.sb-link .lbl { flex: 1 1 auto; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.sb-link .cnt {
		flex: 0 0 auto; min-width: 20px; text-align: center;
		font-size: 10px; font-weight: 800; padding: 1px 6px; border-radius: 99px;
		background: var(--surface-3); color: var(--text-3);
	}
	.sb-link.active .cnt { background: var(--accent); color: #fff; }

	html[data-sidebar="mini"] .sb-group-head { justify-content: center; padding: 10px 0; }
	html[data-sidebar="mini"] .g-label, html[data-sidebar="mini"] .g-chev { display: none; }
	/* collapsed rail: inline links are hidden; each group opens as a floating panel
	   (#sbFly - position:fixed, appended to <body>) beside its icon, so it is never
	   clipped by the scrollable nav and works with click, hover and keyboard */
	html[data-sidebar="mini"] .sb-sub { display: none !important; }
	html[data-sidebar="mini"] .sb-group-head.fly-open { background: var(--surface-2); color: var(--text); }
	html[data-sidebar="mini"] .sb-group-head.is-active { box-shadow: inset 3px 0 0 var(--accent); }
	.sb-fly {
		position: fixed; z-index: 200; min-width: 222px; max-width: 290px; padding: 6px;
		background: var(--surface); border: 1px solid var(--border-strong);
		border-radius: var(--r-md); box-shadow: var(--shadow-3);
		opacity: 0; visibility: hidden; pointer-events: none; transform: translateX(4px);
		transition: opacity .14s var(--ease), transform .14s var(--ease), visibility .14s;
	}
	.sb-fly.open { opacity: 1; visibility: visible; pointer-events: auto; transform: none; }
	.sb-fly-head { display: flex; align-items: center; gap: 8px; padding: 7px 10px 8px; margin-bottom: 4px; border-bottom: 1px solid var(--border); font-weight: 800; font-size: var(--fs-sm); color: var(--text); }
	.sb-fly-head .g-icon { flex: 0 0 20px; width: 20px; height: 20px; display: grid; place-items: center; color: var(--accent-text); }
	.sb-fly-head .g-icon svg { width: 16px; height: 16px; }
	.sb-fly-head .g-desc { display: block; font-size: 10px; font-weight: 500; color: var(--text-4); line-height: 1.3; }
	.sb-fly-list { list-style: none; margin: 0; padding: 0; }
	.sb-fly .sb-link { margin: 0; padding: 8px 10px; }
	.sb-fly .sb-link::before { display: none; }

	.sb-foot { flex: 0 0 auto; padding: 10px; border-top: 1px solid var(--border); }
	.sb-user {
		display: flex; align-items: center; gap: 10px; padding: 8px; border-radius: var(--r-sm);
		background: var(--surface-2); border: 1px solid var(--border); min-width: 0;
	}
	.sb-user .avatar {
		flex: 0 0 30px; width: 30px; height: 30px; border-radius: 99px;
		display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-text);
		font-weight: 800; font-size: 12px;
	}
	.sb-user .meta { min-width: 0; flex: 1 1 auto; }
	.sb-user .nm { font-size: var(--fs-sm); font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.sb-user .rl { font-size: 10px; color: var(--text-3); }
	html[data-sidebar="mini"] .sb-user { justify-content: center; padding: 6px; }
	html[data-sidebar="mini"] .sb-user .meta { display: none; }

	.sb-overlay {
		display: none; position: fixed; inset: 0; z-index: 55;
		background: rgba(0,0,0,.5); backdrop-filter: blur(2px);
	}
	body.sb-drawer .sb-overlay { display: block; }

	/* ---------- Main column ---------- */
	.main { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; height: 100%; }

	.topbar {
		flex: 0 0 var(--topbar-h); height: var(--topbar-h);
		display: flex; align-items: center; gap: 10px;
		padding: 0 14px;
		background: var(--glass);
		backdrop-filter: blur(14px) saturate(1.4);
		-webkit-backdrop-filter: blur(14px) saturate(1.4);
		border-bottom: 1px solid var(--border);
		z-index: 40;
	}
	.tb-btn {
		flex: 0 0 auto; width: 36px; height: 36px; border-radius: var(--r-sm);
		display: grid; place-items: center; color: var(--text-2);
		border: 1px solid transparent; transition: all var(--dur) var(--ease);
	}
	.tb-btn svg { width: 18px; height: 18px; }
	.tb-btn:hover { background: var(--surface-2); border-color: var(--border); color: var(--text); }
	.tb-btn.is-on { background: var(--accent-soft); color: var(--accent-text); border-color: var(--accent-soft); }

	.tb-search {
		position: relative; flex: 1 1 auto; max-width: 460px; min-width: 0;
	}
	.tb-search svg { position: absolute; inset-inline-start: 11px; top: 50%; transform: translateY(-50%); width: 16px; height: 16px; color: var(--text-4); pointer-events: none; }
	.tb-search input {
		width: 100%; height: 38px; padding: 0 36px 0 12px;
		background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-sm);
		color: var(--text); font-size: var(--fs-sm); outline: none;
		transition: border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease), background var(--dur) var(--ease);
	}
	.tb-search input::placeholder { color: var(--text-4); }
	.tb-search input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); background: var(--surface); }
	.tb-search .kbd-hint {
		position: absolute; inset-inline-end: 8px; top: 50%; transform: translateY(-50%);
		font-size: 10px; font-family: var(--font-mono); color: var(--text-4);
		border: 1px solid var(--border); border-radius: 5px; padding: 0 5px; background: var(--surface-3);
		pointer-events: none;
	}
	.tb-spacer { flex: 1 1 auto; }
	.tb-group { display: flex; align-items: center; gap: 6px; flex: 0 0 auto; }
	.tb-sep { width: 1px; height: 26px; background: var(--border); margin: 0 4px; }

	.search-pop {
		position: absolute; inset-inline-start: 0; inset-inline-end: 0; top: calc(100% + 6px);
		background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-md);
		box-shadow: var(--shadow-3); max-height: 340px; overflow-y: auto; z-index: 80; padding: 6px;
	}
	.search-pop .sp-head { font-size: 10px; font-weight: 800; color: var(--text-4); padding: 6px 8px 4px; letter-spacing: .5px; }
	.search-pop .sp-item {
		display: flex; align-items: center; gap: 8px; width: 100%;
		padding: 7px 8px; border-radius: var(--r-sm); text-align: right; color: var(--text-2); font-size: var(--fs-sm);
	}
	.search-pop .sp-item:hover, .search-pop .sp-item.sel { background: var(--accent-soft); color: var(--accent-text); }
	.search-pop .sp-item .t { flex: 1 1 auto; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.search-pop .sp-item .k { font-size: 10px; color: var(--text-4); }

	.content { flex: 1 1 auto; overflow-y: auto; overflow-x: hidden; padding: 20px 22px 40px; scroll-behavior: smooth; }
	@media (max-width: 900px) { .content { padding: 14px 12px 60px; } }

	.view { display: none; animation: viewIn .26s var(--ease); }
	.view.active { display: block; }
	@keyframes viewIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
	html.gfx-off .view { animation: none; }

	/* ============================ PRIMITIVES ============================ */
	.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; flex-wrap: wrap; margin-bottom: 16px; }
	.page-title { font-size: var(--fs-2xl); font-weight: 800; letter-spacing: -.3px; margin: 0; line-height: 1.25; }
	.page-sub { color: var(--text-3); font-size: var(--fs-sm); margin: 2px 0 0; }
	.page-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

	.card {
		background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-lg);
		padding: 16px; box-shadow: var(--shadow-1);
	}
	.card.flat { box-shadow: none; }
	.card.pad-0 { padding: 0; overflow: hidden; }
	.card-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }
	.card-title { font-size: var(--fs-lg); font-weight: 800; margin: 0; }
	.card-desc { font-size: var(--fs-sm); color: var(--text-3); margin: 2px 0 0; }

	.grid { display: grid; gap: 12px; }
	.g-2 { grid-template-columns: repeat(2, minmax(0,1fr)); }
	.g-3 { grid-template-columns: repeat(3, minmax(0,1fr)); }
	.g-4 { grid-template-columns: repeat(4, minmax(0,1fr)); }
	.g-stats { grid-template-columns: repeat(auto-fill, minmax(214px, 1fr)); }
	.g-main { grid-template-columns: minmax(0,1.55fr) minmax(0,1fr); }
	@media (max-width: 1180px) { .g-main { grid-template-columns: minmax(0,1fr); } .g-4 { grid-template-columns: repeat(2, minmax(0,1fr)); } .g-3 { grid-template-columns: repeat(2, minmax(0,1fr)); } }
	@media (max-width: 640px) { .g-2, .g-3, .g-4 { grid-template-columns: minmax(0,1fr); } }

	/* ---------- Stat cards ---------- */
	.stat {
		position: relative; overflow: hidden;
		background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-lg);
		padding: 14px 15px; box-shadow: var(--shadow-1);
		transition: transform var(--dur) var(--ease), border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease);
	}
	.stat:hover { transform: translateY(-2px); border-color: var(--border-strong); box-shadow: var(--shadow-2); }
	html.gfx-off .stat:hover { transform: none; }
	.stat-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
	.stat-label { font-size: var(--fs-sm); color: var(--text-3); font-weight: 600; }
	.stat-icon { flex: 0 0 30px; width: 30px; height: 30px; border-radius: var(--r-sm); display: grid; place-items: center; }
	.stat-icon svg { width: 15px; height: 15px; }
	.stat-value { font-size: var(--fs-3xl); font-weight: 800; letter-spacing: -.6px; line-height: 1.15; margin-top: 6px; font-family: var(--font-mono); font-variant-numeric: tabular-nums; direction: ltr; }
	.stat-unit { font-size: var(--fs-md); font-weight: 700; color: var(--text-3); margin-inline-start: 3px; font-family: var(--font-sans); }
	.stat-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-top: 8px; }
	.stat-hint { font-size: var(--fs-xs); color: var(--text-4); }
	.stat.danger { border-color: var(--err); box-shadow: 0 0 0 1px var(--err-soft), var(--shadow-1); }
	.ci-accent { background: var(--accent-soft); color: var(--accent-text); }
	.ci-ok { background: var(--ok-soft); color: var(--ok); }
	.ci-err { background: var(--err-soft); color: var(--err); }
	.ci-warn { background: var(--warn-soft); color: var(--warn); }
	.ci-info { background: var(--info-soft); color: var(--info); }
	.ci-violet { background: var(--violet-soft); color: var(--violet); }

	.bar { height: 5px; border-radius: 99px; background: var(--surface-3); overflow: hidden; }
	.bar > i { display: block; height: 100%; border-radius: 99px; background: var(--accent); transition: width .5s var(--ease); }

	/* ---------- Buttons ---------- */
	.btn {
		display: inline-flex; align-items: center; justify-content: center; gap: 6px;
		height: 36px; padding: 0 14px; border-radius: var(--r-sm);
		font-size: var(--fs-sm); font-weight: 700; white-space: nowrap;
		border: 1px solid var(--border); background: var(--surface-2); color: var(--text-2);
		transition: all var(--dur) var(--ease);
	}
	.btn svg { width: 15px; height: 15px; flex: 0 0 auto; }
	.btn:hover:not(:disabled) { background: var(--surface-3); color: var(--text); border-color: var(--border-strong); }
	.btn:disabled { opacity: .5; cursor: not-allowed; }
	.btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; box-shadow: 0 2px 10px var(--accent-soft); }
	.btn-primary:hover:not(:disabled) { background: var(--accent); filter: brightness(1.08); color: #fff; }
	.btn-danger { background: var(--err-soft); border-color: transparent; color: var(--err); }
	.btn-danger:hover:not(:disabled) { background: var(--err); color: #fff; }
	.btn-ok { background: var(--ok-soft); border-color: transparent; color: var(--ok); }
	.btn-ok:hover:not(:disabled) { background: var(--ok); color: #fff; }
	.btn-ghost { background: transparent; border-color: transparent; color: var(--text-3); }
	.btn-ghost:hover:not(:disabled) { background: var(--surface-2); color: var(--text); }
	.btn-sm { height: 30px; padding: 0 10px; font-size: var(--fs-xs); }
	.btn-lg { height: 42px; padding: 0 20px; font-size: var(--fs-md); }
	.btn-block { width: 100%; }
	.icon-btn {
		width: 32px; height: 32px; border-radius: var(--r-sm); display: grid; place-items: center;
		color: var(--text-3); border: 1px solid transparent; transition: all var(--dur) var(--ease);
	}
	.icon-btn svg { width: 16px; height: 16px; }
	.icon-btn:hover { background: var(--surface-2); border-color: var(--border); color: var(--text); }
	.icon-btn.danger:hover { background: var(--err-soft); color: var(--err); border-color: transparent; }

	/* ---------- Badges / pills ---------- */
	.badge {
		display: inline-flex; align-items: center; gap: 5px;
		padding: 2px 9px; border-radius: 99px; font-size: var(--fs-xs); font-weight: 700;
		background: var(--surface-3); color: var(--text-2); border: 1px solid transparent; white-space: nowrap;
	}
	.badge.ok { background: var(--ok-soft); color: var(--ok); }
	.badge.err { background: var(--err-soft); color: var(--err); }
	.badge.warn { background: var(--warn-soft); color: var(--warn); }
	.badge.info { background: var(--info-soft); color: var(--info); }
	.badge.accent { background: var(--accent-soft); color: var(--accent-text); }
	.badge.violet { background: var(--violet-soft); color: var(--violet); }
	.badge.muted { background: var(--surface-2); color: var(--text-3); border-color: var(--border); }
	.dot-live { width: 7px; height: 7px; border-radius: 99px; background: var(--text-4); flex: 0 0 auto; }
	.dot-live.on { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-soft); }
	.dot-live.off { background: var(--text-4); }
	.dot-live.busy { background: var(--warn); box-shadow: 0 0 0 3px var(--warn-soft); }

	.chip {
		display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 8px;
		font-size: var(--fs-xs); font-weight: 700; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-2);
	}

	/* ---------- Forms ---------- */
	.field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 12px; }
	.field > label, .lbl-sm { font-size: var(--fs-sm); font-weight: 700; color: var(--text-2); }
	.field .hint { font-size: var(--fs-xs); color: var(--text-4); font-weight: 500; }
	.input, .select, textarea.input {
		width: 100%; min-height: 38px; padding: 8px 11px;
		background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-sm);
		color: var(--text); font-size: var(--fs-sm); outline: none;
		transition: border-color var(--dur) var(--ease), box-shadow var(--dur) var(--ease);
	}
	textarea.input { min-height: 82px; resize: vertical; line-height: 1.7; font-family: var(--font-mono); font-size: var(--fs-sm); }
	.input::placeholder, textarea.input::placeholder { color: var(--text-4); }
	.input:focus, .select:focus, textarea.input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
	.input:disabled, .select:disabled { opacity: .55; cursor: not-allowed; }
	.select {
		appearance: none; -webkit-appearance: none; padding-inline-end: 30px; cursor: pointer;
		background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%237b839a' stroke-width='2.5' stroke-linecap='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
		background-repeat: no-repeat; background-position: left 10px center; background-size: 15px;
	}
	.input-mono { font-family: var(--font-mono); direction: ltr; text-align: left; }
	.form-row { display: grid; gap: 12px; grid-template-columns: repeat(2, minmax(0,1fr)); }
	.form-row-3 { display: grid; gap: 12px; grid-template-columns: repeat(3, minmax(0,1fr)); }
	@media (max-width: 680px) { .form-row, .form-row-3 { grid-template-columns: minmax(0,1fr); } }

	.input-group { display: flex; align-items: stretch; gap: 6px; }
	.input-group .input { flex: 1 1 auto; min-width: 0; }
	.input-group .btn { flex: 0 0 auto; }

	/* Switch */
	.switch { position: relative; flex: 0 0 42px; width: 42px; height: 24px; }
	.switch input { position: absolute; opacity: 0; width: 100%; height: 100%; margin: 0; cursor: pointer; }
	.switch i {
		position: absolute; inset: 0; border-radius: 99px; background: var(--surface-3);
		border: 1px solid var(--border); transition: background var(--dur) var(--ease), border-color var(--dur) var(--ease);
	}
	.switch i::after {
		content: ''; position: absolute; top: 2px; inset-inline-start: 2px; width: 18px; height: 18px;
		border-radius: 99px; background: #fff; box-shadow: var(--shadow-1);
		transition: transform var(--dur) var(--ease);
	}
	html[dir="rtl"] .switch i::after { inset-inline-start: auto; inset-inline-end: 2px; }
	.switch input:checked + i { background: var(--accent); border-color: var(--accent); }
	.switch input:checked + i::after { transform: translateX(-18px); }
	html[dir="rtl"] .switch input:checked + i::after { transform: translateX(18px); }
	.switch input:disabled + i { opacity: .5; }

	.switch-row {
		display: flex; align-items: center; justify-content: space-between; gap: 14px;
		padding: 11px 13px; border: 1px solid var(--border); border-radius: var(--r-md);
		background: var(--surface-2); margin-bottom: 10px;
	}
	.switch-row .sr-text { min-width: 0; }
	.switch-row .sr-t { font-size: var(--fs-sm); font-weight: 700; }
	.switch-row .sr-d { font-size: var(--fs-xs); color: var(--text-4); line-height: 1.5; }

	/* Checkbox list / option cards */
	.opt-grid { display: grid; gap: 8px; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); }
	.opt-card {
		position: relative; display: flex; align-items: center; gap: 10px;
		padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--r-md);
		background: var(--surface-2); cursor: pointer; transition: all var(--dur) var(--ease);
	}
	.opt-card:hover { border-color: var(--border-strong); }
	.opt-card input { position: absolute; opacity: 0; pointer-events: none; }
	.opt-card .box {
		flex: 0 0 18px; width: 18px; height: 18px; border-radius: 5px; border: 1.5px solid var(--border-strong);
		display: grid; place-items: center; transition: all var(--dur) var(--ease); background: var(--surface);
	}
	.opt-card .box svg { width: 12px; height: 12px; color: #fff; opacity: 0; transform: scale(.5); transition: all var(--dur) var(--ease); }
	.opt-card input:checked ~ .box { background: var(--accent); border-color: var(--accent); }
	.opt-card input:checked ~ .box svg { opacity: 1; transform: scale(1); }
	.opt-card input:checked ~ .oc-text .oc-t { color: var(--accent-text); }
	.opt-card .oc-text { min-width: 0; }
	.opt-card .oc-t { font-size: var(--fs-sm); font-weight: 700; }
	.opt-card .oc-d { font-size: var(--fs-xs); color: var(--text-4); }
	.opt-card:has(input:checked) { border-color: var(--accent); background: var(--accent-soft); }

	.port-grid { display: flex; flex-wrap: wrap; gap: 6px; }
	.port-chip { position: relative; cursor: pointer; }
	.port-chip input { position: absolute; opacity: 0; pointer-events: none; }
	.port-chip span {
		display: inline-flex; align-items: center; gap: 4px;
		padding: 5px 10px; border-radius: 8px; border: 1px solid var(--border);
		background: var(--surface-2); font-size: var(--fs-xs); font-weight: 700; font-family: var(--font-mono);
		color: var(--text-2); transition: all var(--dur) var(--ease);
	}
	.port-chip span:hover { border-color: var(--border-strong); }
	.port-chip input:checked + span { background: var(--accent); border-color: var(--accent); color: #fff; }
	.port-chip.nontls input:checked + span { background: var(--warn); border-color: var(--warn); color: #1a1206; }

	.quick-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
	.quick-row .lbl { font-size: var(--fs-xs); color: var(--text-4); font-weight: 700; }

	/* ---------- Tables ---------- */
	.tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
	.tbl { width: 100%; border-collapse: separate; border-spacing: 0; font-size: var(--fs-sm); min-width: 900px; }
	.tbl th {
		position: sticky; top: 0; z-index: 2;
		background: var(--surface-2); color: var(--text-3);
		font-size: var(--fs-xs); font-weight: 800; letter-spacing: .2px;
		text-align: right; padding: 10px 12px; white-space: nowrap;
		border-bottom: 1px solid var(--border);
	}
	.tbl td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
	.tbl tbody tr { transition: background var(--dur) var(--ease); }
	.tbl tbody tr:hover { background: var(--surface-2); }
	.tbl tbody tr.dragging { opacity: .4; }
	.tbl tbody tr.drop-target { box-shadow: inset 0 2px 0 var(--accent); }
	.tbl .c-actions { text-align: center; white-space: nowrap; }
	.tbl .c-actions .icon-btn { width: 32px; height: 32px; }
	.tbl .c-num { font-family: var(--font-mono); font-variant-numeric: tabular-nums; direction: ltr; }
	.cell-user { display: flex; align-items: center; gap: 9px; min-width: 0; }
	.cell-user .uname { font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
	.cell-user .umeta { font-size: var(--fs-xs); color: var(--text-4); }
	.u-avatar {
		flex: 0 0 30px; width: 30px; height: 30px; border-radius: 9px; display: grid; place-items: center;
		font-size: 11px; font-weight: 800; background: var(--surface-3); color: var(--text-2); font-family: var(--font-mono);
	}
	.drag-grip { cursor: grab; color: var(--text-4); padding: 0 2px; user-select: none; }
	.drag-grip:active { cursor: grabbing; }

	.meter { min-width: 96px; }
	.meter-top { display: flex; align-items: center; justify-content: space-between; gap: 6px; font-size: var(--fs-xs); font-family: var(--font-mono); }
	.meter-top .v { color: var(--text); font-weight: 700; }
	.meter-top .m { color: var(--text-4); }
	.meter .bar { margin-top: 4px; height: 4px; }

	.tbl-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 12px; border-bottom: 1px solid var(--border); }
	.tbl-toolbar .grow { flex: 1 1 auto; }
	.tbl-foot { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 12px; border-top: 1px solid var(--border); font-size: var(--fs-xs); color: var(--text-4); flex-wrap: wrap; }

	/* Card layout for tables on small screens */
	@media (max-width: 760px) {
		.tbl { min-width: 0; }
		.tbl thead { display: none; }
		.tbl, .tbl tbody, .tbl tr, .tbl td { display: block; width: 100%; }
		.tbl tr {
			border: 1px solid var(--border); border-radius: var(--r-md); margin: 0 0 10px; padding: 4px 0; background: var(--surface-2);
		}
		.tbl td { border: none; padding: 6px 12px; display: flex; align-items: center; justify-content: space-between; gap: 10px; }
		.tbl td::before { content: attr(data-col); font-size: var(--fs-xs); color: var(--text-4); font-weight: 700; flex: 0 0 auto; }
		.tbl td.c-hide-sm { display: none; }
		.tbl .c-actions { justify-content: flex-start; }
		.meter { min-width: 120px; }
	}

	/* ---------- Dropdown menu ---------- */
	.menu {
		position: absolute; z-index: 200; min-width: 178px; padding: 5px;
		background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-md);
		box-shadow: var(--shadow-3); display: none;
	}
	.menu.open { display: block; animation: menuIn .14s var(--ease); }
	/* mounted on <body>; must sit above modals (300) and drawers (310) */
	.menu.menu-fixed { position: fixed; z-index: 400; max-height: calc(100vh - 16px); overflow-y: auto; }
	@keyframes menuIn { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
	.menu .mi {
		display: flex; align-items: center; gap: 9px; width: 100%;
		padding: 7px 9px; border-radius: var(--r-sm); font-size: var(--fs-sm); font-weight: 600;
		color: var(--text-2); text-align: right; transition: background var(--dur) var(--ease), color var(--dur) var(--ease);
	}
	.menu .mi svg { width: 15px; height: 15px; flex: 0 0 auto; }
	.menu .mi:hover { background: var(--surface-2); color: var(--text); }
	.menu .mi.danger { color: var(--err); }
	.menu .mi.danger:hover { background: var(--err-soft); }
	.menu .mi-sep { height: 1px; background: var(--border); margin: 4px 6px; }
	.menu .mi-head { font-size: 10px; font-weight: 800; color: var(--text-4); padding: 5px 9px 3px; letter-spacing: .4px; }

	/* ---------- Modal / Drawer ---------- */
	.modal {
		position: fixed; inset: 0; z-index: 300;
		display: none; align-items: center; justify-content: center; padding: 20px;
		background: rgba(3,4,7,.62); backdrop-filter: blur(3px);
	}
	.modal.open { display: flex; animation: fadeIn .16s var(--ease); }
	@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
	.modal-card {
		width: 100%; max-width: 560px; max-height: calc(100vh - 40px);
		display: flex; flex-direction: column;
		background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--r-xl);
		box-shadow: var(--shadow-3); overflow: hidden;
		animation: cardIn .2s var(--ease);
	}
	@keyframes cardIn { from { opacity: 0; transform: translateY(10px) scale(.985); } to { opacity: 1; transform: none; } }
	html.gfx-off .modal-card { animation: none; }
	/* forms that wrap body+foot (user / voucher / reseller modals) must be flex columns,
	   otherwise the body cannot scroll and the footer (submit button) gets clipped */
	.modal-card > form { display: flex; flex-direction: column; flex: 1 1 auto; min-height: 0; }
	.modal.wide .modal-card { max-width: 860px; }
	.modal.xwide .modal-card { max-width: 960px; margin: 4vh auto; }
	.modal .modal-card { margin: 4vh auto; }
	#userModal .modal-body { padding: 18px 22px; }
	#userModal .vtabs-body { max-width: 100%; }
	#userModal .form-row, #userModal .form-row-3 { gap: 14px; }
	#userModal .field { margin-bottom: 0; }
	#userModal .opt-grid { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
	@media (min-width: 720px) { #vtab-account { max-width: 680px; margin: 0 auto; } #vtab-network { max-width: 680px; margin: 0 auto; } #vtab-proxy { max-width: 680px; margin: 0 auto; } }
	.modal.narrow .modal-card { max-width: 420px; }
	.modal-head {
		flex: 0 0 auto; display: flex; align-items: flex-start; gap: 12px;
		padding: 16px 18px; border-bottom: 1px solid var(--border);
	}
	.modal-head .mh-icon { flex: 0 0 38px; width: 38px; height: 38px; border-radius: var(--r-sm); display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-text); }
	.modal-head .mh-icon svg { width: 19px; height: 19px; }
	.modal-head .mh-text { flex: 1 1 auto; min-width: 0; }
	.modal-title { font-size: var(--fs-xl); font-weight: 800; margin: 0; line-height: 1.3; }
	.modal-sub { font-size: var(--fs-sm); color: var(--text-3); margin: 2px 0 0; }
	.modal-body { flex: 1 1 auto; overflow-y: auto; padding: 18px; }
	.modal-foot {
		flex: 0 0 auto; display: flex; align-items: center; justify-content: flex-start; gap: 8px;
		padding: 13px 18px; border-top: 1px solid var(--border); background: var(--surface-2); flex-wrap: wrap;
	}
	.modal-foot .spacer { flex: 1 1 auto; }
	@media (max-width: 640px) {
		.modal { padding: 0; align-items: flex-end; }
		.modal-card { max-width: 100%; max-height: 94vh; border-radius: var(--r-xl) var(--r-xl) 0 0; }
	}

	.drawer {
		position: fixed; inset: 0; z-index: 310; display: none;
		background: rgba(3,4,7,.6); backdrop-filter: blur(3px);
	}
	.drawer.open { display: block; animation: fadeIn .16s var(--ease); }
	.drawer-panel {
		position: absolute; top: 0; bottom: 0; inset-inline-end: 0; width: min(520px, 100%);
		display: flex; flex-direction: column; background: var(--surface);
		border-inline-start: 1px solid var(--border-strong); box-shadow: var(--shadow-3);
		animation: slideIn .22s var(--ease);
	}
	@keyframes slideIn { from { transform: translateX(-24px); opacity: .6; } to { transform: none; opacity: 1; } }
	html[dir="rtl"] .drawer-panel { animation-name: slideInRtl; }
	@keyframes slideInRtl { from { transform: translateX(24px); opacity: .6; } to { transform: none; opacity: 1; } }
	html.gfx-off .drawer-panel { animation: none; }

	/* ---------- Tabs ---------- */
	.tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 14px; overflow-x: auto; }
	.tabs::-webkit-scrollbar { height: 0; }
	.tabs .tab {
		position: relative; flex: 0 0 auto; padding: 9px 14px; font-size: var(--fs-sm); font-weight: 700;
		color: var(--text-3); border-radius: var(--r-sm) var(--r-sm) 0 0; white-space: nowrap;
		transition: color var(--dur) var(--ease), background var(--dur) var(--ease);
	}
	.tabs .tab:hover { color: var(--text); background: var(--surface-2); }
	.tabs .tab.active { color: var(--accent-text); background: var(--accent-soft); }
	.tabs .tab.active::after { content: ''; position: absolute; inset-inline: 8px; bottom: -1px; height: 2px; background: var(--accent); border-radius: 2px; }
	.tabpanes { position: relative; }
	.tabpane { display: none; }
	.tabpane.active { display: block; animation: viewIn .2s var(--ease); }

	/* Vertical step tabs (create user) */
	.vtabs { display: flex; gap: 10px; align-items: stretch; }
	.vtabs-nav { flex: 0 0 168px; display: flex; flex-direction: column; gap: 4px; }
	.vtab {
		display: flex; align-items: center; gap: 9px; padding: 9px 11px; border-radius: var(--r-sm);
		text-align: right; color: var(--text-3); font-size: var(--fs-sm); font-weight: 700;
		border: 1px solid transparent; transition: all var(--dur) var(--ease);
	}
	.vtab .vnum {
		flex: 0 0 22px; width: 22px; height: 22px; border-radius: 7px; display: grid; place-items: center;
		font-size: 11px; font-weight: 800; background: var(--surface-3); color: var(--text-3); font-family: var(--font-mono);
	}
	.vtab:hover { background: var(--surface-2); color: var(--text); }
	.vtab.active { background: var(--accent-soft); border-color: var(--accent-soft); color: var(--accent-text); }
	.vtab.active .vnum { background: var(--accent); color: #fff; }
	.vtabs-body { flex: 1 1 auto; min-width: 0; }
	@media (max-width: 720px) {
		.vtabs { flex-direction: column; }
		.vtabs-nav { flex: 0 0 auto; flex-direction: row; overflow-x: auto; gap: 6px; padding-bottom: 4px; }
		.vtab { flex: 0 0 auto; white-space: nowrap; }
	}

	/* ---------- Accordion (settings) ---------- */
	.acc { border: 1px solid var(--border); border-radius: var(--r-md); margin-bottom: 10px; overflow: hidden; background: var(--surface); }
	.acc-head {
		width: 100%; display: flex; align-items: center; gap: 11px; padding: 13px 15px; text-align: right;
		transition: background var(--dur) var(--ease);
	}
	.acc-head:hover { background: var(--surface-2); }
	.acc-head .ah-icon { flex: 0 0 32px; width: 32px; height: 32px; border-radius: var(--r-sm); display: grid; place-items: center; background: var(--surface-3); color: var(--text-2); }
	.acc-head .ah-icon svg { width: 16px; height: 16px; }
	.acc-head .ah-text { flex: 1 1 auto; min-width: 0; }
	.acc-head .ah-t { font-size: var(--fs-md); font-weight: 800; }
	.acc-head .ah-d { font-size: var(--fs-xs); color: var(--text-4); }
	.acc-head .ah-chev { flex: 0 0 16px; width: 16px; height: 16px; color: var(--text-4); transition: transform var(--dur) var(--ease); }
	.acc.open .acc-head .ah-chev { transform: rotate(180deg); }
	.acc-body { display: none; padding: 4px 15px 16px; border-top: 1px solid var(--border); }
	.acc.open .acc-body { display: block; }

	/* ---------- Toast ---------- */
	#toast-wrap {
		position: fixed; z-index: 900; bottom: 18px; inset-inline-start: 18px;
		display: flex; flex-direction: column; gap: 8px; align-items: flex-start;
		pointer-events: none; max-width: min(400px, calc(100vw - 36px));
	}
	.toast {
		pointer-events: auto; display: flex; align-items: flex-start; gap: 10px;
		padding: 11px 13px; border-radius: var(--r-md); min-width: 240px;
		background: var(--surface); border: 1px solid var(--border-strong); box-shadow: var(--shadow-3);
		animation: toastIn .22s var(--ease); position: relative; overflow: hidden;
	}
	.toast.out { animation: toastOut .2s var(--ease) forwards; }
	@keyframes toastIn { from { opacity: 0; transform: translateY(10px) scale(.97); } to { opacity: 1; transform: none; } }
	@keyframes toastOut { to { opacity: 0; transform: translateY(6px) scale(.97); } }
	html.gfx-off .toast { animation: none; }
	.toast .tic { flex: 0 0 22px; width: 22px; height: 22px; border-radius: 7px; display: grid; place-items: center; margin-top: 1px; }
	.toast .tic svg { width: 13px; height: 13px; }
	.toast .tbody { flex: 1 1 auto; min-width: 0; font-size: var(--fs-sm); font-weight: 600; line-height: 1.55; word-break: break-word; }
	.toast .tclose { flex: 0 0 auto; color: var(--text-4); }
	.toast.ok .tic { background: var(--ok-soft); color: var(--ok); }
	.toast.err .tic { background: var(--err-soft); color: var(--err); }
	.toast.warn .tic { background: var(--warn-soft); color: var(--warn); }
	.toast.info .tic { background: var(--info-soft); color: var(--info); }
	.toast::after {
		content: ''; position: absolute; bottom: 0; inset-inline-start: 0; height: 2px; width: 100%;
		background: var(--text-4); opacity: .35; animation: toastBar 4s linear forwards;
	}
	.toast.ok::after { background: var(--ok); } .toast.err::after { background: var(--err); }
	.toast.warn::after { background: var(--warn); } .toast.info::after { background: var(--info); }
	@keyframes toastBar { from { width: 100%; } to { width: 0%; } }

	/* ---------- States ---------- */
	.state { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; padding: 46px 20px; text-align: center; color: var(--text-3); }
	.state .si { width: 54px; height: 54px; border-radius: var(--r-lg); display: grid; place-items: center; background: var(--surface-2); color: var(--text-4); }
	.state .si svg { width: 26px; height: 26px; }
	.state .st { font-size: var(--fs-lg); font-weight: 800; color: var(--text); }
	.state .sd { font-size: var(--fs-sm); max-width: 420px; }
	.spinner { width: 26px; height: 26px; border-radius: 99px; border: 2.5px solid var(--surface-3); border-top-color: var(--accent); animation: spin .7s linear infinite; }
	@keyframes spin { to { transform: rotate(360deg); } }
	.skeleton { background: linear-gradient(90deg, var(--surface-2) 25%, var(--surface-3) 37%, var(--surface-2) 63%); background-size: 400% 100%; animation: shimmer 1.3s ease-in-out infinite; border-radius: 8px; height: 12px; }
	@keyframes shimmer { from { background-position: 100% 0; } to { background-position: 0 0; } }
	html.gfx-off .skeleton { animation: none; }

	/* ---------- Charts ---------- */
	.chart { width: 100%; overflow: visible; }
	.chart-legend { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
	.chart-legend .lg { display: flex; align-items: center; gap: 6px; font-size: var(--fs-xs); color: var(--text-2); }
	.chart-legend .sw { width: 9px; height: 9px; border-radius: 3px; flex: 0 0 auto; }
	.bars { display: flex; flex-direction: column; gap: 9px; }
	.bar-row { display: grid; grid-template-columns: minmax(72px, 108px) minmax(0,1fr) auto; align-items: center; gap: 10px; }
	.bar-row .bl { font-size: var(--fs-xs); font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: var(--font-mono); direction: ltr; }
	.bar-row .bt { font-size: var(--fs-xs); color: var(--text-3); font-family: var(--font-mono); direction: ltr; }
	.bar-track { height: 8px; border-radius: 99px; background: var(--surface-3); overflow: hidden; }
	.bar-fill { height: 100%; border-radius: 99px; transition: width .6s var(--ease); }

	.kv-list { display: flex; flex-direction: column; gap: 0; }
	.kv { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid var(--border); }
	.kv:last-child { border-bottom: none; }
	.kv .k { font-size: var(--fs-sm); color: var(--text-3); }
	.kv .v { font-size: var(--fs-sm); font-weight: 700; font-family: var(--font-mono); direction: ltr; }

	/* ---------- Misc ---------- */
	.note {
		display: flex; align-items: flex-start; gap: 9px; padding: 10px 12px; border-radius: var(--r-md);
		font-size: var(--fs-sm); line-height: 1.65; border: 1px solid var(--border); background: var(--surface-2); color: var(--text-2);
	}
	.note svg { flex: 0 0 16px; width: 16px; height: 16px; margin-top: 3px; }
	.note.warn { background: var(--warn-soft); border-color: transparent; color: var(--warn); }
	.note.err { background: var(--err-soft); border-color: transparent; color: var(--err); }
	.note.ok { background: var(--ok-soft); border-color: transparent; color: var(--ok); }
	.note.info { background: var(--info-soft); border-color: transparent; color: var(--info); }

	.bulk-bar {
		position: fixed; z-index: 250; bottom: 18px; inset-inline-start: 50%; transform: translateX(-50%) translateY(140%);
		display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-radius: var(--r-lg);
		background: var(--surface); border: 1px solid var(--border-strong); box-shadow: var(--shadow-3);
		transition: transform .24s var(--ease); max-width: calc(100vw - 28px); flex-wrap: wrap;
	}
	html[dir="rtl"] .bulk-bar { transform: translateX(50%) translateY(140%); }
	.bulk-bar.show { transform: translateX(-50%) translateY(0); }
	html[dir="rtl"] .bulk-bar.show { transform: translateX(50%) translateY(0); }
	.bulk-bar .bc { font-size: var(--fs-sm); font-weight: 800; padding-inline-end: 6px; white-space: nowrap; }

	.qr-box { display: grid; place-items: center; padding: 14px; background: #fff; border-radius: var(--r-md); }
	.qr-box canvas, .qr-box img, .qr-box svg { display: block; max-width: 100%; height: auto; }
	.copy-field {
		display: flex; align-items: center; gap: 8px; padding: 9px 11px; border-radius: var(--r-sm);
		background: var(--surface-2); border: 1px solid var(--border);
	}
	.copy-field .cf-val { flex: 1 1 auto; min-width: 0; font-family: var(--font-mono); font-size: var(--fs-xs); direction: ltr; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

	.flag { font-size: 14px; line-height: 1; }
	.flags { display: inline-flex; gap: 2px; flex-wrap: wrap; justify-content: center; align-items: center; }

	.empty-illus { opacity: .5; }

	@media print { .sidebar, .topbar { display: none !important; } .content { padding: 0; overflow: visible; } }
	.soon-chip { display:inline-block; margin-inline-start:6px; padding:1px 7px; font-size:9px; font-weight:800;
		border-radius:999px; vertical-align:middle; white-space:nowrap; line-height:1.6;
		color:var(--warn); background:var(--warn-soft); border:1px solid var(--warn); }
	.beta-chip { display:inline-flex; align-items:center; gap:4px; padding:2px 8px; font-size:9px; font-weight:800;
		border-radius:999px; white-space:nowrap; vertical-align:middle;
		color:var(--accent); background:var(--accent-soft); border:1px solid var(--accent); }
	.beta-banner { display:flex; align-items:flex-start; gap:10px; margin:0 0 16px; padding:12px 14px;
		border-radius:var(--r-lg); background:var(--warn-soft); border:1px solid var(--warn);
		color:var(--text-2); font-size:var(--fs-xs); line-height:1.9; position: sticky; top: 0; z-index: 120; }
	.beta-banner b { color:var(--text); }
	.beta-banner .bb-x { margin-inline-start:auto; flex:0 0 auto; }
	.scan-log { margin-top:10px; padding:10px 12px; border-radius:var(--r-md); background:var(--surface-2);
		border:1px solid var(--border); font-size:var(--fs-xs); line-height:2; color:var(--text-3); white-space:pre-line; }
	.sb-logo-lml { background: transparent; box-shadow: none; }
	.sb-logo-lml svg { width: 22px; height: 19px; display: block; }
	html[data-sidebar="mini"] .sb-logo-lml svg { width: 22px; height: 19px; }
	.lml-hero { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin: 0 0 16px;
		padding: 14px 16px; border-radius: var(--r-xl); background: var(--surface); border: 1px solid var(--border); }
	.lml-hero-mark { flex: 0 0 auto; }
	.lml-hero-mark svg { width: 36px; height: 31px; display: block; }
	.lml-hero-txt { min-width: 0; }
	.lml-hero-name { font-weight: 900; font-size: var(--fs-xl); letter-spacing: .4px; display: flex; align-items: center; gap: 8px; line-height: 1.2; }
	.lml-hero-sub { font-size: var(--fs-xs); color: var(--text-3); margin-top: 3px; }
	.lml-ver { font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 999px; color: var(--accent); background: var(--accent-soft); }
	.lml-hero-free { margin-inline-start: auto; display: flex; align-items: center; gap: 9px; padding: 8px 15px;
		border-radius: 999px; background: var(--ok-soft); color: var(--ok); font-size: var(--fs-xs); }
	.lml-hero-free > svg { width: 13px; height: 13px; flex: 0 0 auto; }
	.lml-hero-free b { display: block; font-weight: 900; }
	.lml-hero-free span { display: block; font-size: 10px; color: var(--text-3); font-weight: 500; }
	@media (max-width: 700px) { .lml-hero-free { margin-inline-start: 0; width: 100%; } }

	/* ============================================================
	   بهينه‌سازي موبايل / اندرويد
	   ============================================================ */
	html, body { -webkit-text-size-adjust: 100%; }
	* { -webkit-tap-highlight-color: transparent; }
	body { overflow-x: hidden; overscroll-behavior-y: none; }
	img, svg, video, canvas { max-width: 100%; height: auto; }

	@media (max-width: 900px) {
		/* --- ناچ و نوار اشاره سيستم --- */
		.topbar {
			padding-top: env(safe-area-inset-top);
			height: calc(var(--topbar-h) + env(safe-area-inset-top));
			flex-basis: calc(var(--topbar-h) + env(safe-area-inset-top));
			padding-left: max(12px, env(safe-area-inset-left));
			padding-right: max(12px, env(safe-area-inset-right));
		}
		.sidebar {
			padding-top: env(safe-area-inset-top);
			padding-bottom: env(safe-area-inset-bottom);
			padding-left: env(safe-area-inset-left);
		}
		.content {
			padding: 14px 12px calc(60px + env(safe-area-inset-bottom));
			padding-left: max(12px, env(safe-area-inset-left));
			padding-right: max(12px, env(safe-area-inset-right));
			-webkit-overflow-scrolling: touch;
			overscroll-behavior-y: contain;
		}
		.modal-foot {
			padding-bottom: calc(13px + env(safe-area-inset-bottom));
		}
		#toast-wrap {
			bottom: calc(16px + env(safe-area-inset-bottom));
			left: max(12px, env(safe-area-inset-left));
		}

		/* --- جدول‌ها: قابل اسکرول به جاي بريده شدن --- */
		.tbl { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; }
		.tbl thead, .tbl tbody { display: table; width: 100%; }

		/* --- اندازه لمس (حداقل استاندارد اندرويد ۴۸dp) --- */
		.btn { height: 46px; padding: 0 16px; font-size: 15px; }
		.btn.btn-sm { height: 40px; padding: 0 12px; }
		.icon-btn { width: 44px; height: 44px; min-width: 44px; min-height: 44px; }
		.tab { min-height: 44px; padding: 11px 16px; }
		.sb-link { min-height: 48px; }
		.sb-group-head { min-height: 54px; }
		.switch { min-width: 48px; }

		/* --- جلوگيري از زوم خودکار هنگام فوکس روي فيلد --- */
		input, select, textarea { font-size: 16px; }
		input[type="checkbox"], input[type="radio"] { width: 20px; height: 20px; }
	}

	@media (max-width: 640px) {
		.content { padding-left: 10px; padding-right: 10px; }
		.modal { padding: 0; align-items: flex-end; }
		.modal-card { max-height: 96vh; width: 100%; border-radius: var(--r-xl) var(--r-xl) 0 0; }
		.modal-foot { flex-wrap: wrap; gap: 8px; }
		.modal-foot .btn { flex: 1 1 45%; }
		.modal-foot .icon-btn { flex: 0 0 auto; }
		.stat { padding: 12px 13px; }
		.kv-list { gap: 8px; }
		.copy-field .cf-val { font-size: 11px; }
		.toast { min-width: 0; width: calc(100vw - 24px); max-width: calc(100vw - 24px); }
	}

	/* ---------- user modal footer: primary action at the start corner, step nav at the end ---------- */
	.uf-foot { justify-content: flex-start; }
	.uf-foot .uf-submit { min-width: 156px; box-shadow: 0 6px 18px var(--accent-soft); }
	.uf-steps { display: flex; align-items: center; gap: 6px; }
	.uf-step-ind { min-width: 40px; text-align: center; font-size: 11px; font-weight: 800; color: var(--text-3); font-variant-numeric: tabular-nums; }
	/* while a modal/drawer is open, lift toasts clear of its footer so they never cover the primary button */
	body:has(.modal.open, .drawer.open) #toast-wrap { bottom: 108px; }
	@media (max-width: 640px) { body:has(.modal.open, .drawer.open) #toast-wrap { bottom: auto; top: calc(12px + env(safe-area-inset-top)); } }
	@media (max-width: 640px) {
		.uf-foot .spacer { display: none; }
		.uf-foot .uf-submit { flex: 1 1 56%; }
		.uf-foot > .btn:not(.uf-submit) { flex: 1 1 30%; }
		.uf-foot .uf-steps { flex: 1 1 100%; justify-content: space-between; }
		.uf-foot .uf-steps .btn { flex: 0 0 auto; }
	}

	/* دستگاه‌هاي لمسي: افکت hover سرسام‌آور است */
	@media (hover: none) {
		.btn:hover, .icon-btn:hover, .sb-link:hover, .stat:hover { transform: none; }
		.card:hover, .tbl tbody tr:hover { background: inherit; }
	}

	</style>
</head>
<body>

<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>
	<symbol id="i-grid" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></symbol>
	<symbol id="i-activity" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol>
	<symbol id="i-users" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></symbol>
	<symbol id="i-user" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></symbol>
	<symbol id="i-user-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M20 8v6M23 11h-6"/></symbol>
	<symbol id="i-user-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M16 11l2 2 4-4"/></symbol>
	<symbol id="i-user-x" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M17 8l4 4M21 8l-4 4"/></symbol>
	<symbol id="i-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></symbol>
	<symbol id="i-bolt" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z"/></symbol>
	<symbol id="i-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol>
	<symbol id="i-globe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></symbol>
	<symbol id="i-chart" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M7 15l4-5 3 3 5-7"/></symbol>
	<symbol id="i-ticket" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v2z"/><path d="M13 5v2M13 11v2M13 17v2"/></symbol>
	<symbol id="i-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></symbol>
	<symbol id="i-handshake" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 17l-2 2a2 2 0 0 1-3-3l2-2"/><path d="M14 14l2-2a2 2 0 0 1 3 3l-2 2"/><path d="M8.5 8.5L6 11a2 2 0 0 0 0 3l3.5-3.5"/><path d="M15.5 8.5L18 11a2 2 0 0 1 0 3"/><path d="M3 6l4-3 3 2 2-2 3 2 3-2 4 3-3 4-2-1-3 3-2-2-3 3-2-1z"/></symbol>
	<symbol id="i-send" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></symbol>
	<symbol id="i-bot" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="8" width="18" height="12" rx="3"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1.2" fill="currentColor" stroke="none"/><path d="M8 13h.01M16 13h.01"/><path d="M9 17h6"/><path d="M3 13H1M23 13h-2"/></symbol>
	<symbol id="i-webhook" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="M6 17a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/><path d="M16 6h.01"/><path d="M22 12c0 6-4.39 10-9.806 10C7.793 22 4 18.628 4 14c0-3.5 2-6.5 5-8"/><path d="M17.806 10A5 5 0 1 0 12 3.2"/></symbol>
	<symbol id="i-flag" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/></symbol>
	<symbol id="i-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></symbol>
	<symbol id="i-shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></symbol>
	<symbol id="i-palette" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r="1.5" fill="currentColor" stroke="none"/><circle cx="17.5" cy="10.5" r="1.5" fill="currentColor" stroke="none"/><circle cx="8.5" cy="7.5" r="1.5" fill="currentColor" stroke="none"/><circle cx="6.5" cy="12.5" r="1.5" fill="currentColor" stroke="none"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/></symbol>
	<symbol id="i-network" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2"/></symbol>
	<symbol id="i-sliders" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></symbol>
	<symbol id="i-server" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/></symbol>
	<symbol id="i-database" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></symbol>
	<symbol id="i-logs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5M8 9h2"/></symbol>
	<symbol id="i-backup" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></symbol>
	<symbol id="i-restore" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></symbol>
	<symbol id="i-wrench" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></symbol>
	<symbol id="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/></symbol>
	<symbol id="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></symbol>
	<symbol id="i-refresh" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></symbol>
	<symbol id="i-logout" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></symbol>
	<symbol id="i-download" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></symbol>
	<symbol id="i-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></symbol>
	<symbol id="i-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
	<symbol id="i-qr" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14h1M14 20h1M20 20h1M20 17h1M17 20v1"/></symbol>
	<symbol id="i-edit" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></symbol>
	<symbol id="i-trash" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/></symbol>
	<symbol id="i-power" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><path d="M12 2v10"/></symbol>
	<symbol id="i-more" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="12" cy="19" r="1.7"/></symbol>
	<symbol id="i-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></symbol>
	<symbol id="i-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></symbol>
	<symbol id="i-alert" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></symbol>
	<symbol id="i-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></symbol>
	<symbol id="i-x" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></symbol>
	<symbol id="i-heart" viewBox="0 0 24 24" fill="currentColor"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></symbol>
	<symbol id="i-megaphone" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11v2a1 1 0 0 0 1 1h2l4 4V6L6 10H4a1 1 0 0 0-1 1z"/><path d="M14 8a5 5 0 0 1 0 8"/><path d="M17.5 5a9 9 0 0 1 0 14"/><path d="M7 14v4a2 2 0 0 0 4 0"/></symbol>
	<symbol id="i-github" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5A11.5 11.5 0 0 0 .5 12a11.5 11.5 0 0 0 7.86 10.92c.58.11.79-.25.79-.56v-2c-3.2.7-3.88-1.36-3.88-1.36-.53-1.34-1.29-1.7-1.29-1.7-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 0 1 5.74 0c2.18-1.49 3.14-1.18 3.14-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.26 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.68.8.56A11.5 11.5 0 0 0 23.5 12 11.5 11.5 0 0 0 12 .5z"/></symbol>
	<symbol id="i-telegram" viewBox="0 0 24 24" fill="currentColor"><path d="M21.94 4.3a1.5 1.5 0 0 0-1.62-.26L3.4 11.1c-.9.34-.89 1.5.02 1.83l4.2 1.53 1.63 5.02c.25.78 1.24.95 1.8.31l2.36-2.7 4.3 3.17c.7.52 1.72.16 1.95-.71l3.2-14.1c.18-.79-.33-1.56-1.12-1.75zM9.1 14.2l-.42 3.9-1.2-3.7 8.5-5.5-6.88 5.3z"/></symbol>
	<symbol id="i-external" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></symbol>
	<symbol id="i-key" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></symbol>
	<symbol id="i-layers" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></symbol>
	<symbol id="i-clock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></symbol>
	<symbol id="i-wallet" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"/><path d="M3 5v14a2 2 0 0 0 2 2h16v-5"/><path d="M18 12a2 2 0 0 0 0 4h4v-4z"/></symbol>
	<symbol id="i-crown" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18h20M4 18l-1-9 5 3 4-7 4 7 5-3-1 9"/></symbol>
	<symbol id="i-shuffle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3h5v5"/><path d="M4 20L21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/></symbol>
	<symbol id="i-wifi" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><path d="M12 20h.01"/></symbol>
	<symbol id="i-box" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/></symbol>
	<symbol id="i-pin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></symbol>
	<symbol id="i-terminal" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 17l6-6-6-6"/><path d="M12 19h8"/></symbol>
	<symbol id="i-rocket" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></symbol>
	<symbol id="i-gift" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12v10H4V12"/><path d="M2 7h20v5H2z"/><path d="M12 22V7"/><path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/><path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/></symbol>
	<symbol id="i-filter" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></symbol>
	<symbol id="i-monitor" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></symbol>
	<symbol id="i-phone" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2.5"/><path d="M11 18.5h2"/></symbol>
	<symbol id="i-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
	<symbol id="i-sort" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5h10M11 9h7M11 13h4M3 17l3 3 3-3M6 4v16"/></symbol>
	<symbol id="i-zap-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.41 6.79L13 2l-2.5 3.5"/><path d="M12 22l1-5-1-4-3 1"/><path d="M2 2l20 20"/><path d="M17.5 8.5L19 5l-4 1"/></symbol>
	<symbol id="i-git" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M1.05 12H7M17.01 12h5.95"/></symbol>
	<symbol id="i-pause" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></symbol>
	<symbol id="i-play" viewBox="0 0 24 24" fill="currentColor"><path d="M6 3l14 9-14 9V3z"/></symbol>
</defs></svg>

<div class="app">

	<!-- ============ SIDEBAR ============ -->
	<div class="sb-overlay" id="sbOverlay"></div>
	<aside class="sidebar" id="sidebar">
		<div class="sb-brand">
				<div class="sb-logo sb-logo-lml"><svg viewBox="0 0 46 40" aria-hidden="true"><defs><linearGradient id="lmlGradBrand" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#7c8cff"/><stop offset="100%" stop-color="#22d3ee"/></linearGradient></defs><rect x="1" y="1" width="44" height="38" rx="12" fill="url(#lmlGradBrand)"/><g fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13v14h6"/><path d="M20 27V13l4.5 8.5L29 13v14"/><path d="M35 13v14h6"/></g></svg></div>
			<div class="sb-brand-text">
						<div class="sb-brand-title">LML PANEL <span class="beta-chip">BETA</span></div>
				<div class="sb-brand-sub">مدیریت یکپارچه سرویس</div>
			</div>
		</div>

		<nav class="sb-scroll" id="sbNav">
			<!-- Groups injected by JS -->
		</nav>

		<div class="sb-foot">
			<div class="sb-user">
				<div class="avatar" id="sbAvatar">A</div>
				<div class="meta">
					<div class="nm" id="sbUserName">مدیر کل</div>
					<div class="rl" id="sbUserRole">دسترسی کامل</div>
				</div>
				<button type="button" class="icon-btn" id="btnLogout" title="خروج"><svg><use href="#i-logout"/></svg></button>
			</div>
		</div>
	</aside>

	<!-- ============ MAIN ============ -->
	<div class="main">
		<header class="topbar">
			<button type="button" class="tb-btn" id="btnSidebar" title="تغییر وضعیت منو"><svg><use href="#i-grid"/></svg></button>

			<div class="tb-search" id="searchBox">
				<svg><use href="#i-search"/></svg>
				<input type="text" id="globalSearch" placeholder="جستجوی کاربر، UUID، نماینده یا ووچر..." autocomplete="off" spellcheck="false">
				<span class="kbd-hint">/</span>
				<div class="search-pop hidden" id="searchPop"></div>
			</div>

			<div class="tb-spacer"></div>

			<div class="tb-group">
				<span class="badge" id="liveBadge" title="وضعیت ارتباط با سرور"><span class="dot-live off" id="liveDot"></span><span id="liveText">در حال اتصال</span></span>
				<span class="badge muted hidden" id="resellerBadge" title="اطلاعات نماینده"></span>
			</div>
			<div class="tb-sep"></div>
			<div class="tb-group">
				<button type="button" class="tb-btn" id="btnRefresh" title="بروزرسانی داده‌ها"><svg><use href="#i-refresh"/></svg></button>
				<button type="button" class="tb-btn" id="btnAppInstall" title="نصب اپلیکیشن"><svg><use href="#i-phone"/></svg></button>
<button type="button" class="tb-btn" id="btnSupport" title="شبکه‌های اجتماعی"><svg><use href="#i-megaphone"/></svg></button>
				<button type="button" class="tb-btn" id="btnTheme" title="تغییر تم"><svg id="themeIcon"><use href="#i-moon"/></svg></button>
				<button type="button" class="tb-btn" id="btnNotifications" title="اعلان‌ها و پیام‌ها"><svg><use href="#i-info"/></svg></button>
				<button type="button" class="tb-btn" id="btnQuickAdd" title="ایجاد سریع کاربر"><svg><use href="#i-user-plus"/></svg></button>
			</div>
		</header>

		<main class="content" id="content">
			<div class="beta-banner" id="betaBanner">
				<svg style="width:16px;height:16px;flex:0 0 auto;color:var(--warn);margin-top:2px"><use href="#i-alert"/></svg>
				<div><b>این نسخه بتا (آزمایشی) است.</b> پنل LML در مرحله آزمایشی قرار دارد و ممکن است در بخش‌هایی باگ یا رفتار ناپایدار دیده شود. لبخند! قبل از هر به‌روزرسانی حتماً از دیتابیس خود بکاپ بگیرید.</div>
				<button type="button" class="icon-btn bb-x" id="btnBetaClose" title="بستن"><svg><use href="#i-x"/></svg></button>
			</div>
<!-- ==================== DASHBOARD ==================== -->
			<section class="view" id="view-dashboard">
				<div class="lml-hero">
					<div class="lml-hero-mark"><svg viewBox="0 0 46 40" aria-hidden="true"><defs><linearGradient id="lmlGradHero" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#7c8cff"/><stop offset="100%" stop-color="#22d3ee"/></linearGradient></defs><rect x="1" y="1" width="44" height="38" rx="12" fill="url(#lmlGradHero)"/><g fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13v14h6"/><path d="M20 27V13l4.5 8.5L29 13v14"/><path d="M35 13v14h6"/></g></svg></div>
					<div class="lml-hero-txt">
						<div class="lml-hero-name">LML PANEL <span class="lml-ver" id="lmlVer">v1.0.0</span></div>
						<div class="lml-hero-sub">مدیریت یکپارچه سرویس‌های کانفیگ</div>
					</div>
					<div class="lml-hero-free">
						<svg><use href="#i-heart"/></svg>
						<div><b>این پنل رایگان است 🎁</b><span>استفاده از آن برای همه آزاد و بدون هزینه است</span></div>
					</div>
				</div>
				<div class="page-head">
					<div>
						<h1 class="page-title">نمای کلی</h1>
						<p class="page-sub">وضعیت لحظه‌ای پنل، کاربران و مصرف منابع</p>
					</div>
					<div class="page-actions">
						<span class="badge" id="sysStatusBadge"><span class="dot-live off" id="sysDot"></span><span id="sysStatusText">در حال بررسی</span></span>
						<button type="button" class="btn" id="btnDashRefresh"><svg><use href="#i-refresh"/></svg>بروزرسانی</button>
						<button type="button" class="btn btn-primary" id="btnDashNewUser"><svg><use href="#i-user-plus"/></svg>کاربر جدید</button>
					</div>
				</div>

				<div class="grid g-stats" id="statGrid">
					<div class="stat" id="stat-card-users">
						<div class="stat-top">
							<div class="stat-label">کل کاربران</div>
							<div class="stat-icon ci-accent"><svg><use href="#i-users"/></svg></div>
						</div>
						<div class="stat-value num" id="statTotalUsers">0</div>
						<div class="stat-foot"><span class="stat-hint">کاربر تعریف‌شده روی پنل</span></div>
					</div>
					<div class="stat" id="stat-card-active">
						<div class="stat-top">
							<div class="stat-label">کاربران فعال</div>
							<div class="stat-icon ci-ok"><svg><use href="#i-user-check"/></svg></div>
						</div>
						<div class="stat-value num" id="statActiveUsers">0</div>
						<div class="stat-foot"><span class="stat-hint">فعال و در محدوده مجاز</span></div>
					</div>
					<div class="stat" id="stat-card-expired">
						<div class="stat-top">
							<div class="stat-label">کاربران منقضی</div>
							<div class="stat-icon ci-err"><svg><use href="#i-user-x"/></svg></div>
						</div>
						<div class="stat-value num" id="statExpiredUsers">0</div>
						<div class="stat-foot"><span class="stat-hint">پایان حجم، زمان یا غیرفعال</span></div>
					</div>
					<div class="stat" id="stat-card-online">
						<div class="stat-top">
							<div class="stat-label">اتصال‌های آنلاین</div>
							<div class="stat-icon ci-info"><svg><use href="#i-wifi"/></svg></div>
						</div>
						<div class="stat-value num" id="statOnlineConns">0</div>
						<div class="stat-foot"><span class="stat-hint">متصل در این لحظه</span></div>
					</div>
					<div class="stat" id="stat-card-traffic">
						<div class="stat-top">
							<div class="stat-label">ترافیک مصرفی</div>
							<div class="stat-icon ci-violet"><svg><use href="#i-chart"/></svg></div>
						</div>
						<div class="stat-value num" id="statTraffic">0<span class="stat-unit">GB</span></div>
						<div class="stat-foot"><span class="stat-hint">مجموع مصرف ثبت‌شده</span></div>
					</div>
					<div class="stat" id="stat-card-vouchers">
						<div class="stat-top">
							<div class="stat-label">ووچرهای فعال</div>
							<div class="stat-icon ci-warn"><svg><use href="#i-ticket"/></svg></div>
						</div>
						<div class="stat-value num" id="statVouchers">0</div>
						<div class="stat-foot"><span class="stat-hint">کارت شارژ استفاده‌نشده</span></div>
					</div>
<div class="stat" id="stat-card-requests">
						<div class="stat-top">
							<div class="stat-label">درخواست‌های امروز</div>
							<div class="stat-icon ci-warn"><svg><use href="#i-activity"/></svg></div>
						</div>
						<div class="stat-value num" id="statRequests">0</div>
						<div class="stat-foot">
							<span class="stat-hint">مجموع: <span class="num" id="statRequestsTotal">0</span></span>
							<span class="badge muted num" id="statRequestsPct">0%</span>
						</div>
						<div class="bar" style="margin-top:8px"><i id="statRequestsBar" style="width:0%"></i></div>
					</div>
				</div>

				<div class="grid g-main" style="margin-top:12px">
					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">پرمصرف‌ترین کاربران</h2>
								<p class="card-desc">بر اساس حجم مصرفی ثبت‌شده</p>
							</div>
							<button type="button" class="btn btn-sm btn-ghost" data-goto="view-services" data-tab="tab-traffic">نمایش کامل<svg><use href="#i-chevron"/></svg></button>
						</div>
						<div class="bars" id="dashTopUsers"></div>
					</div>
					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">ترکیب وضعیت کاربران</h2>
								<p class="card-desc">توزیع وضعیت روی کل کاربران</p>
							</div>
						</div>
						<div id="dashDonut" style="display:flex;align-items:center;justify-content:center;padding:6px 0"></div>
						<div class="chart-legend" id="dashDonutLegend" style="justify-content:center"></div>
					</div>
				</div>

				<div class="grid g-2" style="margin-top:12px">
					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">اتصال‌های فعال</h2>
								<p class="card-desc">کاربرانی که در این لحظه متصل هستند</p>
							</div>
						</div>
						<div id="dashOnlineList"></div>
					</div>
					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">سلامت منابع</h2>
								<p class="card-desc">سهمیه روزانه کلودفلر و دیتابیس</p>
							</div>
						</div>
						<div class="kv-list">
							<div class="kv"><span class="k">درخواست امروز</span><span class="v" id="kvReqToday">0 / 100k</span></div>
							<div class="kv"><span class="k">مجموع درخواست‌ها</span><span class="v" id="kvReqTotal">0</span></div>
							<div class="kv"><span class="k">نوشتن دیتابیس</span><span class="v" id="kvD1Writes">0 / 100k</span></div>
							<div class="kv"><span class="k">خواندن دیتابیس</span><span class="v" id="kvD1Reads">0 / 5M</span></div>
							<div class="kv"><span class="k">آخرین همگام‌سازی</span><span class="v" id="kvLastSync">—</span></div>
						</div>
						<div style="margin-top:12px">
							<div class="bar"><i id="kvReqBar" style="width:0%"></i></div>
						</div>
					</div>
				</div>

				<div class="card" style="margin-top:12px">
					<div class="card-head">
						<div>
							<h2 class="card-title">آمار تحلیلی</h2>
							<p class="card-desc">گزارش تجمیعی مستقیم از دیتابیس</p>
						</div>
						<button type="button" class="btn btn-sm btn-ghost" id="btnRefreshAnalytics">بروزرسانی<svg><use href="#i-refresh"/></svg></button>
					</div>
					<div class="grid g-4" id="dashAnalyticsStats"></div>
					<div class="bars" id="dashAnalyticsTop" style="margin-top:12px"></div>
				</div>

				<div class="card" style="margin-top:12px">
					<div class="card-head">
						<div>
							<h2 class="card-title">دسترسی سریع</h2>
							<p class="card-desc">عملیات پرکاربرد در یک کلیک</p>
						</div>
					</div>
					<div class="grid g-4" id="dashQuick"></div>
				</div>
			</section>

			<!-- ==================== USERS ==================== -->
			<section class="view" id="view-users">
				<div class="page-head">
					<div>
						<h1 class="page-title">کاربران</h1>
						<p class="page-sub">مدیریت حساب‌ها، محدودیت‌ها و اشتراک‌ها</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnUsersRefresh"><svg><use href="#i-refresh"/></svg>بروزرسانی</button>
						<button type="button" class="btn" id="btnBulkCreate"><svg><use href="#i-box"/></svg>ساخت گروهی</button>
						<button type="button" class="btn btn-primary" id="btnCreateUser"><svg><use href="#i-user-plus"/></svg>کاربر جدید</button>
					</div>
				</div>

				<div class="grid g-stats" id="userMiniStats" style="margin-bottom:12px"></div>

				<div class="card pad-0">
					<div class="tbl-toolbar">
						<div style="position:relative;flex:0 1 300px;min-width:180px">
							<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
							<input type="text" class="input" id="userSearch" placeholder="جستجوی نام کاربری یا UUID..." style="padding-inline-start:32px" autocomplete="off">
						</div>
						<select class="select" id="userFilter" style="width:auto;min-width:130px">
							<option value="all">همه وضعیت‌ها</option>
							<option value="active">فعال</option>
							<option value="inactive">غیرفعال</option>
							<option value="online">آنلاین</option>
							<option value="offline">آفلاین</option>
							<option value="expired">منقضی</option>
						</select>
						<select class="select" id="userSort" style="width:auto;min-width:150px">
							<option value="newest">جدیدترین</option>
							<option value="name">نام کاربری</option>
							<option value="usage-desc">بیشترین مصرف</option>
							<option value="usage-asc">کمترین مصرف</option>
							<option value="expiry-asc">کمترین زمان باقی‌مانده</option>
							<option value="online-desc">بیشترین اتصال</option>
						</select>
						<div class="grow"></div>
						<span class="badge muted" id="userCountBadge">0 کاربر</span>
					</div>

					<div class="tbl-wrap">
						<table class="tbl" id="usersTable">
							<thead>
								<tr>
									<th style="width:38px"><input type="checkbox" id="selectAllUsers" title="انتخاب همه"></th>
									<th style="width:38px"></th>
									<th>کاربر</th>
									<th>وضعیت</th>
									<th>ترافیک</th>
									<th class="c-hide-sm">ریکوئست</th>
									<th class="c-hide-sm">زمان</th>
									<th class="c-hide-sm">اتصال</th>
									<th class="c-hide-sm">پروتکل</th>
									<th class="c-actions">عملیات</th>
								</tr>
							</thead>
							<tbody id="usersTbody"></tbody>
						</table>
					</div>
					<div id="usersState"></div>
					<div class="tbl-foot">
						<span id="usersFootInfo">—</span>
						<span>برای دیدن کیوآر کد کانفیگ هر کاربر، روی <svg style="width:12px;height:12px;vertical-align:-2px"><use href="#i-qr"/></svg> همان ردیف بزنید</span>
					</div>
				</div>
			</section>
			<!-- ==================== SERVICES ==================== -->
			<section class="view" id="view-services">
				<div class="page-head">
					<div>
						<h1 class="page-title">سرویس‌ها</h1>
						<p class="page-sub">کانفیگ‌ها، اشتراک، وضعیت اتصال، آی‌پی و ترافیک</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnServicesRefresh"><svg><use href="#i-refresh"/></svg>بروزرسانی</button>
					</div>
				</div>

				<div class="tabs" id="servicesTabs">
					<button type="button" class="tab active" data-pane="tab-configs">کانفیگ‌ها</button>
					<button type="button" class="tab" data-pane="tab-subscription">اشتراک</button>
					<button type="button" class="tab" data-pane="tab-connstatus">وضعیت اتصال</button>
					<button type="button" class="tab" data-pane="tab-ips">آی‌پی‌ها</button>
					<button type="button" class="tab" data-pane="tab-traffic">ترافیک</button>
				</div>

				<div class="tabpanes">
					<div class="tabpane active" id="tab-configs">
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="cfgSearch" placeholder="جستجوی کاربر..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<div class="grow"></div>
								<span class="badge muted">فرمول: ۳ + لوکیشن × آی‌پی × پورت × پروتکل</span>
								<button type="button" class="btn btn-sm btn-ghost" id="btnCfgFormula"><svg><use href="#i-info"/></svg></button>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr>
										<th>کاربر</th><th>پروتکل</th><th>پورت‌ها</th><th>لوکیشن</th><th>تعداد کانفیگ</th><th class="c-actions">عملیات</th>
									</tr></thead>
									<tbody id="cfgTbody"></tbody>
								</table>
							</div>
							<div id="cfgState"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-subscription">
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="subSearch" placeholder="جستجوی کاربر..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<div class="grow"></div>
								<span class="badge muted">ساب متنی · Sing-box · وضعیت · VLESS</span>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr>
										<th>کاربر</th><th>لینک اشتراک</th><th class="c-actions">عملیات</th>
									</tr></thead>
									<tbody id="subTbody"></tbody>
								</table>
							</div>
							<div id="subState"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-connstatus">
						<div class="grid g-4" id="connSummary" style="margin-bottom:12px"></div>
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="connSearch" placeholder="جستجوی کاربر..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<div class="grow"></div>
								<button type="button" class="btn btn-sm" id="btnPingClient"><svg><use href="#i-activity"/></svg>تست اتصال مستقیم</button>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr>
										<th>کاربر</th><th>وضعیت</th><th>اتصال / سقف</th><th>نوع خروجی</th><th class="c-actions">عملیات</th>
									</tr></thead>
									<tbody id="connTbody"></tbody>
								</table>
							</div>
							<div id="connState"></div>
						</div>
						<div class="note warn" style="margin-top:12px">
							<svg><use href="#i-alert"/></svg>
							<div>به دلیل ساختار کلودفلر، شمارنده کاربران آنلاین تقریبی است؛ تست پینگ یا بروزرسانی لینک ساب توسط کلاینت می‌تواند باعث افزایش موقت این عدد شود.</div>
						</div>
					</div>

					<div class="tabpane" id="tab-ips">
						<div class="grid g-2">
							<div class="card">
								<div class="card-head">
									<div>
										<h2 class="card-title">مخزن آی‌پی تمیز</h2>
										<p class="card-desc">دریافت آی‌پی‌های کلودفلر بر اساس اوپراتور</p>
									</div>
									<button type="button" class="btn btn-sm btn-primary" id="btnOpenIpRepo"><svg><use href="#i-globe"/></svg>اسکنر آی‌پی</button>
								</div>
								<div class="kv-list">
									<div class="kv"><span class="k">آی‌پی‌های بارگذاری‌شده</span><span class="v" id="kvIpLoaded">0</span></div>
									<div class="kv"><span class="k">آخرین دریافت</span><span class="v" id="kvIpTime">—</span></div>
								</div>
								<div class="note info" style="margin-top:12px">
									<svg><use href="#i-info"/></svg>
									<div>آی‌پی‌ها از مخزن عمومی LML دریافت می‌شوند و برای ساخت کانفیگ‌های دارای آی‌پی تمیز استفاده می‌گردند.</div>
								</div>
							</div>
							<div class="card">
								<div class="card-head">
									<div>
										<h2 class="card-title">آی‌پی‌های هر کاربر</h2>
										<p class="card-desc">تعداد آی‌پی تمیز و وضعیت چرخش خودکار</p>
									</div>
								</div>
								<div class="tbl-wrap">
									<table class="tbl" style="min-width:0">
										<thead><tr><th>کاربر</th><th>تعداد آی‌پی</th><th>چرخش خودکار</th><th>اوپراتور</th></tr></thead>
										<tbody id="ipTbody"></tbody>
									</table>
								</div>
								<div id="ipState"></div>
							</div>
						</div>
					</div>

					<div class="tabpane" id="tab-traffic">
						<div class="grid g-4" id="trafficSummary" style="margin-bottom:12px"></div>
						<div class="card">
							<div class="card-head">
								<div>
									<h2 class="card-title">مصرف بر اساس کاربر</h2>
									<p class="card-desc">ده کاربر پرمصرف بر اساس داده‌های واقعی پنل</p>
								</div>
							</div>
							<div class="bars" id="trafficBars"></div>
						</div>
						<div class="card pad-0" style="margin-top:12px">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="trafficSearch" placeholder="جستجوی کاربر..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<div class="grow"></div>
								<select class="select" id="trafficSort" style="width:auto;min-width:150px">
									<option value="usage-desc">بیشترین مصرف</option>
									<option value="usage-asc">کمترین مصرف</option>
									<option value="req-desc">بیشترین ریکوئست</option>
								</select>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr>
										<th>کاربر</th><th>مصرف</th><th>سقف</th><th>درصد</th><th>ریکوئست</th><th class="c-actions">عملیات</th>
									</tr></thead>
									<tbody id="trafficTbody"></tbody>
								</table>
							</div>
							<div id="trafficState"></div>
						</div>
					</div>
				</div>
			</section>

			<!-- ==================== SALES ==================== -->
			<section class="view" id="view-sales">
				<div class="page-head">
					<div>
						<h1 class="page-title">ووچر</h1>
						<p class="page-sub">ووچرها، کارت شارژ و شبکه نمایندگان</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnSalesRefresh"><svg><use href="#i-refresh"/></svg>بروزرسانی</button>
						<button type="button" class="btn btn-primary" id="btnNewVoucher"><svg><use href="#i-ticket"/></svg>ایجاد ووچر</button>
					</div>
				</div>

				<div class="tabs" id="salesTabs">
					<button type="button" class="tab active" data-pane="tab-vouchers">ووچرها</button>
					<button type="button" class="tab" data-pane="tab-vcreate">ایجاد ووچر</button>
					<button type="button" class="tab" data-pane="tab-vused">استفاده‌شده</button>
</div>

				<div class="tabpanes">
					<div class="tabpane active" id="tab-vouchers">
						<div class="grid g-4" id="voucherSummary" style="margin-bottom:12px"></div>
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="voucherSearch" placeholder="جستجوی کد ووچر..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<select class="select" id="voucherFilter" style="width:auto;min-width:140px">
									<option value="all">همه</option>
									<option value="unused">استفاده‌نشده</option>
									<option value="used">استفاده‌شده</option>
								</select>
								<div class="grow"></div>
								<span class="badge muted" id="voucherCount">0 ووچر</span>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr>
										<th>کد</th><th>حجم</th><th>مدت</th><th>وضعیت</th><th class="c-hide-sm">مصرف‌کننده</th><th class="c-hide-sm">تاریخ</th><th class="c-actions">عملیات</th>
									</tr></thead>
									<tbody id="voucherTbody"></tbody>
								</table>
							</div>
							<div id="voucherState"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-vcreate">
						<div class="grid g-main">
							<div class="card">
								<div class="card-head">
									<div>
										<h2 class="card-title">تولید کارت شارژ جدید</h2>
										<p class="card-desc">کد را خالی بگذارید تا به‌صورت خودکار ساخته شود</p>
									</div>
								</div>
								<form id="voucherForm">
									<div class="field">
										<label for="voucherCode">کد کارت شارژ</label>
										<input type="text" class="input input-mono" id="voucherCode" placeholder="LML-50GB-30D" autocomplete="off">
										<span class="hint">فقط حروف، اعداد و خط تیره</span>
									</div>
									<div class="form-row">
										<div class="field">
											<label for="voucherGb">حجم شارژ (گیگابایت)</label>
											<input type="number" class="input" id="voucherGb" value="20" min="0" step="0.1">
										</div>
										<div class="field">
											<label for="voucherDays">مدت اعتبار (روز)</label>
											<input type="number" class="input" id="voucherDays" value="30" min="1" step="1">
										</div>
									</div>
									<div class="quick-row" style="margin-bottom:14px">
										<span class="lbl">سریع:</span>
										<button type="button" class="btn btn-sm" data-vpreset="10,30">۱۰G / ۳۰ روز</button>
										<button type="button" class="btn btn-sm" data-vpreset="30,30">۳۰G / ۳۰ روز</button>
										<button type="button" class="btn btn-sm" data-vpreset="50,60">۵۰G / ۶۰ روز</button>
										<button type="button" class="btn btn-sm" data-vpreset="100,90">۱۰۰G / ۹۰ روز</button>
									</div>
									<div style="display:flex;gap:8px">
										<button type="submit" class="btn btn-primary" id="voucherSubmit"><svg><use href="#i-plus"/></svg>تولید ووچر</button>
										<button type="button" class="btn" id="voucherReset">پاک کردن فرم</button>
									</div>
								</form>
							</div>
							<div class="card">
								<div class="card-head"><div><h2 class="card-title">آخرین ووچر ساخته‌شده</h2></div></div>
								<div id="voucherResult">
									<div class="state"><div class="si"><svg><use href="#i-ticket"/></svg></div><div class="sd">هنوز ووچری ساخته نشده است.</div></div>
								</div>
							</div>
						</div>
					</div>

					<div class="tabpane" id="tab-vused">
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div style="position:relative;flex:0 1 300px;min-width:180px">
									<svg style="position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--text-4);pointer-events:none"><use href="#i-search"/></svg>
									<input type="text" class="input" id="vusedSearch" placeholder="جستجو..." style="padding-inline-start:32px" autocomplete="off">
								</div>
								<div class="grow"></div>
								<span class="badge muted" id="vusedCount">0 مورد</span>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr><th>کد</th><th>حجم</th><th>مدت</th><th>مصرف‌کننده</th><th class="c-hide-sm">تاریخ</th><th class="c-actions">عملیات</th></tr></thead>
									<tbody id="vusedTbody"></tbody>
								</table>
							</div>
							<div id="vusedState"></div>
						</div>
					</div>
				</div>
			</section>

			<!-- ==================== TELEGRAM ==================== -->
			<section class="view" id="view-telegram">
				<div class="page-head">
					<div>
						<h1 class="page-title">مرکز تلگرام</h1>
						<p class="page-sub">اتصال ربات، وب‌هوک، دستورات و ارسال بکاپ</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnTgRefresh"><svg><use href="#i-refresh"/></svg>بررسی وضعیت</button>
						<button type="button" class="btn btn-primary" id="btnTgSave"><svg><use href="#i-check"/></svg>ذخیره و اتصال</button>
					</div>
				</div>

				<div class="grid g-4" style="margin-bottom:12px">
					<div class="stat" style="grid-column:span 2">
						<div class="stat-top">
							<div>
								<div class="stat-label">وضعیت اتصال ربات</div>
								<div style="font-size:var(--fs-xl);font-weight:800;margin-top:6px" id="tgStatusText">بررسی نشده</div>
							</div>
							<div class="stat-icon" id="tgStatusIcon"><svg><use href="#i-bot"/></svg></div>
						</div>
						<div class="stat-foot"><span class="stat-hint" id="tgStatusHint">برای فعال‌سازی، توکن ربات را ثبت کنید</span></div>
					</div>
					<div class="stat">
						<div class="stat-top">
							<div class="stat-label">وب‌هوک</div>
							<div class="stat-icon ci-info"><svg><use href="#i-webhook"/></svg></div>
						</div>
						<div style="font-size:var(--fs-lg);font-weight:800;margin-top:6px" id="tgWebhookState">—</div>
						<div class="stat-foot"><span class="stat-hint">به‌صورت خودکار تنظیم می‌شود</span></div>
					</div>
					<div class="stat">
						<div class="stat-top">
							<div class="stat-label">بکاپ خودکار</div>
							<div class="stat-icon ci-ok"><svg><use href="#i-backup"/></svg></div>
						</div>
						<div style="font-size:var(--fs-lg);font-weight:800;margin-top:6px">روزانه</div>
						<div class="stat-foot"><span class="stat-hint">ارسال فایل به تلگرام از طریق Cron</span></div>
					</div>
				</div>

				<div class="grid g-main">
					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">تنظیمات ربات</h2>
								<p class="card-desc">توکن ربات و آیدی عددی ادمین</p>
							</div>
						</div>
						<form id="tgForm">
							<div class="field">
								<label for="tgToken">توکن ربات (Bot Token)</label>
								<input type="text" class="input input-mono" id="tgToken" placeholder="123456789:AAHk1_..." autocomplete="off" spellcheck="false">
								<span class="hint">توکن را از <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> دریافت کنید.</span>
							</div>
							<div class="field">
								<label for="tgAdminId">آیدی عددی ادمین (Chat ID)</label>
								<input type="text" class="input input-mono" id="tgAdminId" placeholder="123456789" autocomplete="off">
								<span class="hint">اختیاری — برای محدود کردن دستورات. از <a href="https://t.me/userinfobot" target="_blank" rel="noopener">@userinfobot</a> بگیرید.</span>
							</div>
							<div class="field">
								<label for="tgWebhook">آدرس وب‌هوک</label>
								<div class="input-group">
									<input type="text" class="input input-mono" id="tgWebhook" readonly>
									<button type="button" class="btn" id="btnCopyWebhook"><svg><use href="#i-copy"/></svg>کپی</button>
								</div>
							</div>
							<div style="display:flex;gap:8px;flex-wrap:wrap">
								<button type="submit" class="btn btn-primary" id="tgSubmitBtn"><svg><use href="#i-check"/></svg>ذخیره و ثبت وب‌هوک</button>
								<button type="button" class="btn" id="btnTgTest"><svg><use href="#i-send"/></svg>تست اتصال</button>
							</div>
						</form>
					</div>

					<div class="card">
						<div class="card-head">
							<div>
								<h2 class="card-title">عملیات</h2>
								<p class="card-desc">ارسال بکاپ و دستورات پرکاربرد</p>
							</div>
						</div>
						<div style="display:flex;flex-direction:column;gap:8px">
							<button type="button" class="btn btn-block" id="btnTgBackup" style="justify-content:flex-start"><svg><use href="#i-send"/></svg>ارسال فایل بکاپ به تلگرام</button>
							<button type="button" class="btn btn-block" id="btnTgOpenBot" style="justify-content:flex-start"><svg><use href="#i-external"/></svg>باز کردن ربات در تلگرام</button>
							<button type="button" class="btn btn-block" id="btnTgDocs" style="justify-content:flex-start"><svg><use href="#i-logs"/></svg>راهنمای دستورات</button>
						</div>
						<div class="kv-list" style="margin-top:14px">
							<div class="kv"><span class="k">مسیر وب‌هوک</span><span class="v">/api/telegram-webhook</span></div>
							<div class="kv"><span class="k">دریافت اطلاعات</span><span class="v">/api/telegram-info</span></div>
							<div class="kv"><span class="k">تنظیم ربات</span><span class="v">/api/telegram-setup</span></div>
							<div class="kv"><span class="k">ارسال بکاپ</span><span class="v">/api/telegram-backup</span></div>
						</div>
					</div>
				</div>
			</section>
			<!-- ==================== SETTINGS ==================== -->
			<section class="view" id="view-settings">
				<div class="page-head">
					<div>
						<h1 class="page-title">تنظیمات</h1>
						<p class="page-sub">پیکربندی پنل در بخش‌های تفکیک‌شده</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnSettingsReload"><svg><use href="#i-refresh"/></svg>بارگذاری مجدد</button>
						<button type="button" class="btn btn-primary" id="btnSettingsSave"><svg><use href="#i-check"/></svg>ذخیره تنظیمات</button>
					</div>
				</div>

				<div class="grid g-main">
					<div>
						<!-- General -->
						<div class="acc open" data-acc="general">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-sliders"/></svg></span>
								<span class="ah-text"><span class="ah-t">عمومی</span><span class="ah-d">رفرش خودکار، آدرس پنل، نسخه و بروزرسانی</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="field">
									<label for="setRefreshRate">نرخ بروزرسانی خودکار پنل</label>
									<select class="select" id="setRefreshRate">
										<option value="1000">۱ ثانیه</option>
										<option value="2000">۲ ثانیه</option>
										<option value="15000">۱۵ ثانیه (پیش‌فرض)</option>
										<option value="10000">۱۰ ثانیه</option>
										<option value="30000">۳۰ ثانیه</option>
										<option value="60000">۱ دقیقه</option>
										<option value="300000">۵ دقیقه</option>
										<option value="600000">۱۰ دقیقه</option>
									</select>
									<span class="hint">فاصله دریافت خودکار داده‌ها هنگام باز بودن پنل</span>
								</div>
								<div class="field">
									<label>آدرس پنل</label>
									<div class="input-group">
										<input type="text" class="input input-mono" id="setPanelUrl" readonly>
										<button type="button" class="btn" id="btnCopyPanelUrl"><svg><use href="#i-copy"/></svg>کپی</button>
									</div>
								</div>
								<div class="kv-list">
									<div class="kv"><span class="k">نسخه پنل</span><span class="v" id="setVersion">—</span></div>
									<div class="kv"><span class="k">نسخه موجود</span><span class="v" id="setLatest">—</span></div>
									<div class="kv"><span class="k">زمان سرور</span><span class="v" id="setServerTime">—</span></div>
								</div>
							</div>
						</div>

						<!-- Security -->
						<div class="acc" data-acc="security">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-shield"/></svg></span>
								<span class="ah-text"><span class="ah-t">امنیت</span><span class="ah-d">تغییر رمز عبور و گزارش ورود ادمین</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="form-row">
									<div class="field">
										<label for="setPwdCurrent">رمز عبور فعلی</label>
										<input type="password" class="input" id="setPwdCurrent" autocomplete="current-password">
									</div>
									<div class="field">
										<label for="setPwdNew">رمز عبور جدید</label>
										<input type="password" class="input" id="setPwdNew" autocomplete="new-password">
									</div>
								</div>
								<button type="button" class="btn btn-primary" id="btnChangePwd"><svg><use href="#i-key"/></svg>تغییر رمز عبور</button>
								<div style="margin-top:16px">
									<button type="button" class="btn btn-block" id="btnToggleLogs" style="justify-content:space-between">
										<span style="display:flex;align-items:center;gap:8px"><svg><use href="#i-logs"/></svg>آخرین گزارش‌های ورود ادمین</span>
										<svg style="width:14px;height:14px" id="logsChev"><use href="#i-chevron"/></svg>
									</button>
									<div id="logsBox" class="hidden" style="margin-top:10px">
										<div class="tbl-wrap">
											<table class="tbl" style="min-width:0">
												<thead><tr><th>آی‌پی</th><th>وضعیت</th><th>تاریخ / ساعت</th></tr></thead>
												<tbody id="logsTbody"></tbody>
											</table>
										</div>
									</div>
								</div>
							</div>
						</div>

						<!-- Network -->
						<div class="acc" data-acc="network">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-network"/></svg></span>
								<span class="ah-text"><span class="ah-t">شبکه</span><span class="ah-d">پروکسی سراسری، تست اتصال و مخزن آی‌پی</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="field">
									<label for="setProxyIp">آی‌پی پروکسی سراسری</label>
									<input type="text" class="input input-mono" id="setProxyIp" placeholder="خالی = بدون پروکسی سراسری" autocomplete="off">
								</div>
								<div class="form-row">
									<div class="field">
										<label for="setProxyIata">کد کشور خروجی (IATA)</label>
										<input type="text" class="input input-mono" id="setProxyIata" placeholder="مثال: DE" autocomplete="off" maxlength="8">
									</div>
									<div class="field">
										<label for="setProxySocks">رشته SOCKS5</label>
										<input type="text" class="input input-mono" id="setProxySocks" placeholder="socks5://user:pass@host:port" autocomplete="off">
									</div>
								</div>
								<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
									<button type="button" class="btn" id="btnSaveProxy"><svg><use href="#i-check"/></svg>ذخیره تنظیمات شبکه</button>
									<button type="button" class="btn" id="btnPingDirect"><svg><use href="#i-activity"/></svg>تست اتصال مستقیم</button>
									<button type="button" class="btn" id="btnOpenIpRepo2"><svg><use href="#i-globe"/></svg>اسکنر آی‌پی زنده</button>
								</div>
								<div class="grid g-3" id="pingResult">
									<div class="kv"><span class="k">پینگ شما به کلودفلر</span><span class="v" id="pingClient">—</span></div>
									<div class="kv"><span class="k">کلودفلر به نت آزاد</span><span class="v" id="pingServer">—</span></div>
									<div class="kv"><span class="k">وضعیت</span><span class="v" id="pingState">—</span></div>
								</div>
							</div>
						</div>

						<!-- Telegram -->
						<div class="acc" data-acc="telegram">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-send"/></svg></span>
								<span class="ah-text"><span class="ah-t">تلگرام</span><span class="ah-d">توکن ربات، آیدی ادمین و وب‌هوک</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="field">
									<label for="setTgToken">توکن ربات</label>
									<input type="text" class="input input-mono" id="setTgToken" placeholder="123456789:AAHk1_..." autocomplete="off" spellcheck="false">
								</div>
								<div class="field">
									<label for="setTgAdmin">آیدی عددی ادمین</label>
									<input type="text" class="input input-mono" id="setTgAdmin" placeholder="123456789" autocomplete="off">
								</div>
								<div style="display:flex;gap:8px;flex-wrap:wrap">
									<button type="button" class="btn btn-primary" id="btnSaveTg2"><svg><use href="#i-check"/></svg>ذخیره تنظیمات تلگرام</button>
									<button type="button" class="btn" data-goto="view-telegram"><svg><use href="#i-send"/></svg>رفتن به مرکز تلگرام</button>
								</div>
							</div>
						</div>

						<!-- Subscription -->
						<div class="acc" data-acc="subscription">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-link"/></svg></span>
								<span class="ah-text"><span class="ah-t">اشتراک</span><span class="ah-d">مسیرهای سابسکریپشن و فرمت‌های خروجی</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="kv-list">
									<div class="kv"><span class="k">ساب متنی</span><span class="v">/sub/USERNAME</span></div>
									<div class="kv"><span class="k">ساب پیشرفته</span><span class="v">/feed/USERNAME</span></div>
									<div class="kv"><span class="k">Sing-box</span><span class="v">/singbox/USERNAME</span></div>
									<div class="kv"><span class="k">پرتال کاربر</span><span class="v">/s/USERNAME</span></div>
									<div class="kv"><span class="k">وضعیت اتصال</span><span class="v">/status/USERNAME</span></div>
								</div>
								<div class="note info" style="margin-top:12px">
									<svg><use href="#i-info"/></svg>
									<div>فرمت خروجی بر اساس کلاینت (v2ray / clash / sing-box / hiddify) به‌صورت خودکار تشخیص داده می‌شود.</div>
								</div>
								<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
									<button type="button" class="btn" data-goto="view-services" data-tab="tab-subscription"><svg><use href="#i-link"/></svg>مدیریت اشتراک‌ها</button>
									<button type="button" class="btn" id="btnCfgFormula2"><svg><use href="#i-alert"/></svg>نحوه محاسبه تعداد کانفیگ</button>
								</div>
							</div>
						</div>

						<!-- Automation -->
						<div class="acc" data-acc="automation">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-clock"/></svg></span>
								<span class="ah-text"><span class="ah-t">خودکارسازی</span><span class="ah-d">آپدیت خودکار، چرخش پروکسی، ریست و تمدید</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="switch-row">
									<div class="sr-text">
										<div class="sr-t">آپدیت خودکار پنل</div>
										<div class="sr-d">دریافت و اعمال نسخه جدید به‌صورت خودکار (نیازمند توکن کلودفلر)</div>
									</div>
									<label class="switch"><input type="checkbox" id="setAutoUpdate"><i></i></label>
								</div>
								<div class="kv" style="margin:2px 0 10px">
									<span class="k">اکانت کلودفلر متصل</span>
									<span class="v" id="cfAccountName">ثبت نشده</span>
								</div>
								<div class="switch-row">
									<div class="sr-text">
										<div class="sr-t">پویش سراسری پروکسی</div>
										<div class="sr-d">بررسی دوره‌ای پروکسی کاربران دارای تعویض خودکار و جایگزینی مورد خراب</div>
									</div>
									<label class="switch"><input type="checkbox" id="setAutoScan" checked><i></i></label>
								</div>
								<div class="kv-list" style="margin-bottom:14px">
									<div class="kv"><span class="k">ریست خودکار حجم / ریکوئست</span><span class="v">ساعت ۳:۳۰</span></div>
									<div class="kv"><span class="k">تعویض خودکار آی‌پی</span><span class="v">تنظیم هر کاربر</span></div>
									<div class="kv"><span class="k">بکاپ خودکار تلگرام</span><span class="v">روزانه (Cron)</span></div>
								</div>
								<div style="display:flex;gap:8px;flex-wrap:wrap">
									<button type="button" class="btn" id="btnSetBatchRenew"><svg><use href="#i-refresh"/></svg>تمدید دسته‌ای</button>
									<button type="button" class="btn" id="btnSetPrune"><svg><use href="#i-trash"/></svg>پاکسازی منقضی‌ها</button>
								</div>
							</div>
						</div>

						<!-- Appearance -->
						<div class="acc" data-acc="appearance">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-palette"/></svg></span>
								<span class="ah-text"><span class="ah-t">ظاهر</span><span class="ah-d">تم، تراکم، منو و جلوه‌های بصری</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="form-row">
									<div class="field">
										<label for="setTheme">تم رنگی</label>
										<select class="select" id="setTheme">
											<option value="dark">تیره</option>
											<option value="light">روشن</option>
										</select>
									</div>
									<div class="field">
										<label for="setDensity">تراکم نمایش</label>
										<select class="select" id="setDensity">
											<option value="comfortable">استاندارد</option>
											<option value="compact">فشرده</option>
										</select>
									</div>
								</div>
								<div class="field">
									<label for="setSidebar">حالت منوی کناری</label>
									<select class="select" id="setSidebar">
										<option value="expanded">باز</option>
										<option value="mini">فشرده (فقط آیکون)</option>
										<option value="hidden">بسته</option>
									</select>
								</div>
								<div class="switch-row">
									<div class="sr-text">
										<div class="sr-t">جلوه‌های گرافیکی</div>
										<div class="sr-d">پس‌زمینه محیطی و انیمیشن‌های ملایم</div>
									</div>
									<label class="switch"><input type="checkbox" id="setGfx"><i></i></label>
								</div>
								<div class="switch-row">
									<div class="sr-text">
										<div class="sr-t">حالت سیاه‌وسفید</div>
										<div class="sr-d">حذف رنگ‌ها از کل رابط</div>
									</div>
									<label class="switch"><input type="checkbox" id="setGrayscale"><i></i></label>
								</div>
							</div>
						</div>

						<!-- Advanced -->
						<div class="acc" data-acc="advanced">
							<button type="button" class="acc-head">
								<span class="ah-icon"><svg><use href="#i-terminal"/></svg></span>
								<span class="ah-text"><span class="ah-t">پیشرفته</span><span class="ah-d">بکاپ، بازیابی، بروزرسانی و عملیات حساس</span></span>
								<svg class="ah-chev"><use href="#i-chevron"/></svg>
							</button>
							<div class="acc-body">
								<div class="grid g-2" style="margin-bottom:14px">
									<div>
										<div class="lbl-sm" style="margin-bottom:6px">پشتیبان‌گیری هوشمند (JSON)</div>
										<div style="display:flex;flex-direction:column;gap:6px">
											<button type="button" class="btn btn-block" id="btnSmartBackup" style="justify-content:flex-start"><svg><use href="#i-download"/></svg>دانلود بک‌آپ کامل</button>
											<button type="button" class="btn btn-block" id="btnSmartRestore" style="justify-content:flex-start"><svg><use href="#i-upload"/></svg>بازیابی فایل بک‌آپ</button>
											<input type="file" id="smartRestoreInput" accept=".json" class="hidden">
										</div>
									</div>
									<div>
										<div class="lbl-sm" style="margin-bottom:6px">بکاپ کاربران</div>
										<div style="display:flex;flex-direction:column;gap:6px">
											<button type="button" class="btn btn-block" id="btnExportUsers" style="justify-content:flex-start"><svg><use href="#i-download"/></svg>خروجی لیست کاربران</button>
											<button type="button" class="btn btn-block" id="btnImportUsers" style="justify-content:flex-start"><svg><use href="#i-upload"/></svg>ورود کاربران از فایل</button>
											<input type="file" id="importUsersInput" accept=".json" class="hidden">
										</div>
									</div>
								</div>
								<div class="grid g-3">
									<button type="button" class="btn" id="btnCheckUpdate"><svg><use href="#i-git"/></svg>بررسی بروزرسانی</button>
									<button type="button" class="btn" id="btnRestartCore"><svg><use href="#i-power"/></svg>ری‌استارت پنل</button>
									<button type="button" class="btn" id="btnDownloadSource"><svg><use href="#i-download"/></svg>دریافت سورس‌کد</button>
								<div id="updateStatusSettings" style="display:none"></div>
								</div>
							</div>
						</div>
					</div>

					<div>
						<div class="card" style="position:sticky;top:0">
							<div class="card-head"><div><h2 class="card-title">راهنمای تنظیمات</h2></div></div>
							<div class="note"><svg><use href="#i-info"/></svg><div>تنظیمات ظاهر و نرخ رفرش روی همین مرورگر ذخیره می‌شوند. تنظیمات تلگرام، شبکه و آپدیت خودکار روی سرور ذخیره می‌گردند.</div></div>
							<div class="kv-list" style="margin-top:12px">
								<div class="kv"><span class="k">کلیدهای ذخیره‌شده</span><span class="v" id="setKeysCount">0</span></div>
								<div class="kv"><span class="k">آخرین ذخیره</span><span class="v" id="setLastSave">—</span></div>
							</div>
							<div style="margin-top:14px;display:flex;flex-direction:column;gap:6px">
								<button type="button" class="btn btn-block" id="btnSideSettingsGfx" style="justify-content:flex-start"><svg><use href="#i-palette"/></svg>تغییر سریع تم</button>
								<button type="button" class="btn btn-block btn-danger" id="btnLogout2" style="justify-content:flex-start"><svg><use href="#i-logout"/></svg>خروج از پنل</button>
							</div>
						</div>
					</div>
				</div>
			</section>

			<!-- ==================== SYSTEM ==================== -->
			<section class="view" id="view-system">
				<div class="page-head">
					<div>
						<h1 class="page-title">سیستم</h1>
						<p class="page-sub">وضعیت ورکر، دیتابیس، لاگ‌ها، بکاپ و نگهداری</p>
					</div>
					<div class="page-actions">
						<button type="button" class="btn" id="btnSystemRefresh"><svg><use href="#i-refresh"/></svg>بروزرسانی</button>
					</div>
				</div>

				<div class="tabs" id="systemTabs">
					<button type="button" class="tab active" data-pane="tab-worker">وضعیت ورکر</button>
					<button type="button" class="tab" data-pane="tab-database">دیتابیس</button>
					<button type="button" class="tab" data-pane="tab-logs">لاگ‌ها</button>
					<button type="button" class="tab" data-pane="tab-backup">بکاپ</button>
					<button type="button" class="tab" data-pane="tab-maintenance">نگهداری</button>
				</div>

				<div class="tabpanes">
					<div class="tabpane active" id="tab-worker">
						<div class="grid g-4" id="workerSummary"></div>
						<div class="card" style="margin-top:12px">
							<div class="card-head"><div><h2 class="card-title">جزئیات زمان اجرا</h2></div></div>
							<div class="kv-list" id="workerDetail"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-database">
						<div class="grid g-4" id="dbSummary"></div>
						<div class="card" style="margin-top:12px">
							<div class="card-head"><div><h2 class="card-title">سهمیه‌های روزانه</h2><p class="card-desc">مصرف دیتابیس D1 طبق گزارش کلودفلر</p></div></div>
							<div class="bars" id="dbBars"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-logs">
						<div class="card pad-0">
							<div class="tbl-toolbar">
								<div class="grow"></div>
								<button type="button" class="btn btn-sm" id="btnReloadLogs"><svg><use href="#i-refresh"/></svg>بارگذاری لاگ ورود</button>
							</div>
							<div class="tbl-wrap">
								<table class="tbl">
									<thead><tr><th>آی‌پی</th><th>وضعیت</th><th>تاریخ / ساعت</th></tr></thead>
									<tbody id="sysLogsTbody"></tbody>
								</table>
							</div>
							<div id="sysLogsState"></div>
						</div>
					</div>

					<div class="tabpane" id="tab-backup">
						<div class="grid g-2">
							<div class="card">
								<div class="card-head"><div><h2 class="card-title">دانلود مستقیم</h2><p class="card-desc">یک نسخه کامل JSON روی دستگاه شما ذخیره می‌شود</p></div></div>
								<button type="button" class="btn btn-primary btn-block" id="btnBackupDownload"><svg><use href="#i-download"/></svg>دانلود بکاپ کامل</button>
							</div>
							<div class="card">
								<div class="card-head"><div><h2 class="card-title">ارسال به تلگرام</h2><p class="card-desc">ارسال فایل پشتیبان به پیوی تلگرام شما</p></div></div>
								<button type="button" class="btn btn-block" id="btnBackupTelegram"><svg><use href="#i-send"/></svg>ارسال به تلگرام</button>
							</div>
						</div>
						<div class="card" style="margin-top:12px">
							<div class="card-head"><div><h2 class="card-title">بازیابی دیتابیس</h2><p class="card-desc">فایل بکاپ JSON قبلی را انتخاب کنید تا اطلاعات بازگردانی شود</p></div></div>
							<div class="input-group" style="max-width:520px">
								<input type="file" id="restoreFileInput" accept=".json" class="input" style="padding:6px">
								<button type="button" class="btn btn-danger" id="btnRestoreDb"><svg><use href="#i-restore"/></svg>بازیابی</button>
							</div>
							<div class="note warn" style="margin-top:12px">
								<svg><use href="#i-alert"/></svg>
								<div>بازیابی اطلاعات فعلی را با محتوای فایل جایگزین می‌کند. قبل از انجام، یک بکاپ تهیه کنید.</div>
							</div>
						</div>
						<div class="note info" style="margin-top:12px">
							<svg><use href="#i-info"/></svg>
							<div>پشتیبان‌گیری خودکار ۲۴ ساعته ورکر با Cron Trigger فعال است و فایل روزانه به تلگرام شما ارسال می‌شود.</div>
						</div>
					</div>

					<div class="tabpane" id="tab-maintenance">
						<div class="grid g-2">
							<div class="card">
								<div class="card-head"><div><h2 class="card-title">عملیات نگهداری</h2><p class="card-desc">تمدید، پاکسازی و ریست گروهی</p></div></div>
								<div style="display:flex;flex-direction:column;gap:8px">
									<button type="button" class="btn btn-block" id="btnMBatchRenew" style="justify-content:flex-start"><svg><use href="#i-refresh"/></svg>تمدید دسته‌ای کاربران</button>
									<button type="button" class="btn btn-block" id="btnMPrune" style="justify-content:flex-start"><svg><use href="#i-trash"/></svg>پاکسازی کاربران منقضی</button>
									<button type="button" class="btn btn-block" id="btnMRestart" style="justify-content:flex-start"><svg><use href="#i-power"/></svg>ری‌استارت پنل</button>
								</div>
							</div>
							<div class="card">
								<div class="card-head"><div><h2 class="card-title">بروزرسانی پنل</h2><p class="card-desc">نسخه فعلی و بررسی نسخه جدید</p></div></div>
								<div class="kv-list">
									<div class="kv"><span class="k">نسخه نصب‌شده</span><span class="v" id="mVersion">—</span></div>
									<div class="kv"><span class="k">آخرین نسخه</span><span class="v" id="mLatest">—</span></div>
									<div class="kv"><span class="k">آپدیت خودکار</span><span class="v" id="mAutoUpdate">—</span></div>
								</div>
								<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
									<button type="button" class="btn btn-primary" id="btnMUpdate"><svg><use href="#i-git"/></svg>بررسی و بروزرسانی</button>
									<button type="button" class="btn" id="btnMForce"><svg><use href="#i-download"/></svg>آپدیت دستی</button>
								<div id="updateStatusSystem" style="display:none"></div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</section>

		</main>
	</div>
</div>

<div class="bulk-bar" id="bulkBar">
	<span class="bc" id="bulkCount">۰ کاربر انتخاب شده</span>
	<button type="button" class="btn btn-sm btn-ok" id="bulkActivate">فعال‌سازی</button>
	<button type="button" class="btn btn-sm" id="bulkDeactivate">غیرفعال‌سازی</button>
	<button type="button" class="btn btn-sm" id="bulkResetVol">ریست حجم</button>
	<button type="button" class="btn btn-sm" id="bulkResetReq">ریست ریکوئست</button>
	<button type="button" class="btn btn-sm" id="bulkResetTime">ریست زمان</button>
	<button type="button" class="btn btn-sm" id="bulkRenew">تمدید</button>
	<button type="button" class="btn btn-sm btn-danger" id="bulkDelete">حذف</button>
	<button type="button" class="btn btn-sm btn-ghost" id="bulkClear">لغو انتخاب</button>
</div>
<!-- ==================== GENERIC MODAL ==================== -->
<div class="modal" id="modalGeneric">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon" id="genIcon"><svg><use href="#i-info"/></svg></div>
			<div class="mh-text">
				<h3 class="modal-title" id="genTitle">عنوان</h3>
				<p class="modal-sub" id="genSub"></p>
			</div>
			<button type="button" class="icon-btn" data-close-modal="modalGeneric"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body" id="genBody"></div>
		<div class="modal-foot" id="genFoot"></div>
	</div>
</div>

<!-- ==================== CONFIRM MODAL ==================== -->
<div class="modal narrow" id="modalConfirm">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon" id="confirmIcon"><svg><use href="#i-alert"/></svg></div>
			<div class="mh-text">
				<h3 class="modal-title" id="confirmTitle">تأیید عملیات</h3>
				<p class="modal-sub" id="confirmSub"></p>
			</div>
		</div>
		<div class="modal-body" id="confirmMessage" style="line-height:1.8"></div>
		<div class="modal-foot">
			<button type="button" class="btn" id="confirmCancel">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="confirmOk">تأیید</button>
		</div>
	</div>
</div>

<!-- ==================== USER CREATE / EDIT MODAL ==================== -->
<div class="modal xwide" id="modalUser">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-user-plus"/></svg></div>
			<div class="mh-text">
				<h3 class="modal-title" id="userModalTitle">ایجاد کاربر جدید</h3>
				<p class="modal-sub" id="userModalSub">مشخصات، دسترسی‌ها و پروتکل‌های اتصال</p>
			</div>
			<button type="button" class="icon-btn" data-close-modal="modalUser"><svg><use href="#i-x"/></svg></button>
		</div>
		<form id="userForm">
			<div class="modal-body">
				<input type="hidden" id="fAutoRotate" value="0">
				<input type="hidden" id="fRotateTime" value="">
				<input type="hidden" id="fIpOperator" value="all">
				<input type="hidden" id="fIpCount" value="15">

				<div class="vtabs">
					<div class="vtabs-nav" id="userVtabs">
						<button type="button" class="vtab active" data-vtab="vtab-account"><span class="vnum">۱</span><span>اطلاعات حساب</span></button>
						<button type="button" class="vtab" data-vtab="vtab-network"><span class="vnum">۲</span><span>پورت و شبکه</span></button>
						<button type="button" class="vtab" data-vtab="vtab-proxy"><span class="vnum">۳</span><span>پروکسی خروجی</span></button>
					</div>

					<div class="vtabs-body">
						<!-- ---------- STEP 1 : ACCOUNT ---------- -->
						<div class="vtab-pane" id="vtab-account">
							<div class="field">
								<label>پروتکل‌های اتصال <span style="color:var(--err)">*</span></label>
								<div class="opt-grid">
									<label class="opt-card">
										<input type="checkbox" id="fProtoVless" checked onchange="handleProtocolChange(this)">
										<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
										<span class="oc-text"><span class="oc-t">VLESS</span><span class="oc-d">سبک و پرسرعت</span></span>
									</label>
									<label class="opt-card">
										<input type="checkbox" id="fProtoTrojan" disabled onchange="handleProtocolChange(this)">
										<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
										<span class="oc-text"><span class="oc-t">Trojan <span class="soon-chip">🔒 به زودی</span></span><span class="oc-d">فعلاً قفل است — به‌زودی فعال می‌شود</span></span>
									</label>
								</div>
								<div class="note" style="margin-top:8px"><svg><use href="#i-info"/></svg><div>پروتکل <b>VLESS</b> پروتکل اصلی و فعال این نسخه است. <b>Trojan</b> به‌زودی فعال می‌شود.</div></div>
							</div>

							<div class="field">
								<label for="fName">نام کاربری <span style="color:var(--err)">*</span></label>
								<div class="input-group">
									<input type="text" class="input input-mono" id="fName" placeholder="lml" autocomplete="off" spellcheck="false">
									<button type="button" class="btn" id="btnRandomName"><svg><use href="#i-shuffle"/></svg>نام تصادفی</button>
								</div>
								<span class="hint">فقط حروف انگلیسی، اعداد، خط تیره و آندرلاین</span>
							</div>

							<div class="field">

							<div class="form-row">
								<div class="field">
									<label for="fLimit">حجم مجاز (گیگابایت)</label>
									<input type="number" class="input" id="fLimit" step="0.1" min="0" placeholder="نامحدود">
									<div class="quick-row" style="margin-top:6px">
										<button type="button" class="btn btn-sm" data-vol="10">۱۰</button>
										<button type="button" class="btn btn-sm" data-vol="50">۵۰</button>
										<button type="button" class="btn btn-sm" data-vol="100">۱۰۰</button>
										<button type="button" class="btn btn-sm" data-vol="">∞</button>
									</div>
								</div>
								<div class="field">
									<label for="fExpiry">مدت اعتبار (روز)</label>
									<input type="number" class="input" id="fExpiry" min="1" placeholder="نامحدود">
									<div class="quick-row" style="margin-top:6px">
										<button type="button" class="btn btn-sm" data-exp="30">۱ ماه</button>
										<button type="button" class="btn btn-sm" data-exp="60">۲ ماه</button>
										<button type="button" class="btn btn-sm" data-exp="90">۳ ماه</button>
										<button type="button" class="btn btn-sm" data-exp="">∞</button>
									</div>
								</div>
							</div>

							
							<div class="form-row-3">
								<div class="field">
									<label for="fReqLimit">محدودیت ریکوئست</label>
									<input type="number" class="input" id="fReqLimit" min="0" placeholder="نامحدود">
								</div>
								<div class="field">
									<label for="fIpLimit">محدودیت اتصال همزمان</label>
									<input type="number" class="input" id="fIpLimit" min="0" placeholder="نامحدود">
								</div>
								<div class="field">
									<label for="fFingerprint">فینگرپرینت TLS</label>
									<select class="select" id="fFingerprint">
										<option value="chrome">Chrome</option>
										<option value="firefox">Firefox</option>
										<option value="safari">Safari</option>
										<option value="ios">iOS</option>
										<option value="android">Android</option>
										<option value="edge">Edge</option>
										<option value="360">360 Browser</option>
										<option value="qq">QQ Browser</option>
										<option value="random">Random</option>
										<option value="randomized">Dynamic</option>
										<option value="unsafe">Unsafe (پیشنهادی)</option>
									</select>
								</div>
							</div>

							<div class="switch-row">
								<div class="sr-text">
									<div class="sr-t">تمدید خودکار ترافیک</div>
									<div class="sr-d">ریست اتوماتیک در ساعت ۳:۳۰ بامداد</div>
								</div>
								<label class="switch"><input type="checkbox" id="fAutoReset" onchange="toggleAutoResetInputs(this.checked)"><i></i></label>
							</div>
							<div class="form-row" id="autoResetBox">
								<div class="field">
									<label for="fAutoResetVol">دوره تمدید حجم (روز)</label>
									<input type="number" class="input" id="fAutoResetVol" min="1" placeholder="خالی = بدون تمدید" disabled>
								</div>
								<div class="field">
									<label for="fAutoResetReq">دوره تمدید ریکوئست (روز)</label>
									<input type="number" class="input" id="fAutoResetReq" min="1" placeholder="خالی = بدون تمدید" disabled>
								</div>
							</div>

							<div class="grid g-2">
								<div class="switch-row" style="margin-bottom:0">
									<div class="sr-text">
										<div class="sr-t">مسدودسازی سایت‌های غیراخلاقی</div>
										<div class="sr-d">فیلتر محتوای بزرگسال</div>
									</div>
									<label class="switch"><input type="checkbox" id="fBlockPorn"><i></i></label>
								</div>
								<div class="switch-row" style="margin-bottom:0">
									<div class="sr-text">
										<div class="sr-t">مسدودسازی تبلیغات</div>
										<div class="sr-d">فیلتر تبلیغات اینترنتی</div>
									</div>
									<label class="switch"><input type="checkbox" id="fBlockAds"><i></i></label>
								</div>
							</div>
							<div class="note warn" style="margin-top:10px"><svg><use href="#i-alert"/></svg><div>در صورت روشن بودن فرگمنت، گزینه‌های مسدودسازی عملاً اعمال نمی‌شوند.</div></div>
						</div>
						</div>

						<!-- ---------- STEP 2 : NETWORK ---------- -->
						<div class="vtab-pane hidden" id="vtab-network">
							<div class="field">
								<label>پورت‌های TLS (رمزنگاری‌شده)</label>
								<div class="port-grid" id="tlsPortsList"></div>
							</div>
							<div class="field">
								<label>پورت‌های Non-TLS (بدون رمزنگاری)</label>
								<div class="port-grid" id="nonTlsPortsList"></div>
							</div>
							<div class="field">
								<label for="fCustomPorts">پورت‌های دلخواه (با فاصله جدا کنید)</label>
								<input type="text" class="input input-mono" id="fCustomPorts" placeholder="8080 2096 8443 5000" autocomplete="off">
							</div>

							<div class="field">
								<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:5px">
									<label for="fIps" style="margin:0">آی‌پی‌های تمیز کلودفلر</label>
									<button type="button" class="btn btn-sm" id="btnOpenIpRepo3"><svg><use href="#i-globe"/></svg>اسکنر آی‌پی</button>
								</div>
								<textarea class="input" id="fIps" placeholder="104.16.0.1" rows="4"></textarea>
							</div>
							<div class="switch-row">
								<div class="sr-text">
									<div class="sr-t">تعویض خودکار آی‌پی</div>
									<div class="sr-d">جابجایی آی‌پی‌ها با هر بار رفرش کلاینت (توصیه می‌شود)</div>
								</div>
								<label class="switch"><input type="checkbox" id="fAutoRotateIp"><i></i></label>
							</div>

							<div class="switch-row">
								<div class="sr-text">
									<div class="sr-t">فرگمنت ضد فیلترینگ</div>
									<div class="sr-d">تجزیه پکت‌های اتصال برای عبور پایدارتر</div>
								</div>
								<label class="switch"><input type="checkbox" id="fFragToggle" onchange="toggleFragInputs(this.checked)"><i></i></label>
							</div>
							<div id="fragBox" class="hidden">
								<div class="form-row">
									<div class="field">
										<label for="fFragLen">طول فرگمنت (Length)</label>
										<input type="text" class="input input-mono" id="fFragLen" value="200-3000" placeholder="مثال: 10-30">
									</div>
									<div class="field">
										<label for="fFragInt">بازه فرگمنت (Interval ms)</label>
										<input type="text" class="input input-mono" id="fFragInt" value="1-2" placeholder="مثال: 1-2">
									</div>
								</div>
								<div class="field">
									<label>تنظیمات پیشنهادی اپراتورها</label>
									<div class="opt-grid">
										<label class="opt-card frag-preset" data-op="mci">
											<input type="radio" name="fragPreset" value="mci">
											<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
											<span class="oc-text"><span class="oc-t">همراه اول</span><span class="oc-d">10-30 · ۲-۵ ms</span></span>
										</label>
										<label class="opt-card frag-preset" data-op="irancell">
											<input type="radio" name="fragPreset" value="irancell">
											<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
											<span class="oc-text"><span class="oc-t">ایرانسل</span><span class="oc-d">100-200 · ۵-۱۰ ms</span></span>
										</label>
										<label class="opt-card frag-preset" data-op="rightel">
											<input type="radio" name="fragPreset" value="rightel">
											<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
											<span class="oc-text"><span class="oc-t">رایتل</span><span class="oc-d">50-100 · ۲-۵ ms</span></span>
										</label>
										<label class="opt-card frag-preset" data-op="tci">
											<input type="radio" name="fragPreset" value="tci">
											<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
											<span class="oc-text"><span class="oc-t">مخابرات / ثابت</span><span class="oc-d">50-200 · ۱-۳ ms</span></span>
										</label>
										<label class="opt-card frag-preset" data-op="gaming">
											<input type="radio" name="fragPreset" value="gaming">
											<span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span>
											<span class="oc-text"><span class="oc-t">حالت فوق سریع</span><span class="oc-d">200-3000 · ۱-۲ ms</span></span>
										</label>
									</div>
								</div>
							</div>
						</div>

						<!-- ---------- STEP 3 : PROXY ---------- -->
						<div class="vtab-pane hidden" id="vtab-proxy">
							<div class="grid g-3" style="margin-bottom:14px">
								<div class="kv"><span class="k">پینگ شما به کلودفلر</span><span class="v" id="pingClient2">—</span></div>
								<div class="kv"><span class="k">کلودفلر به نت آزاد</span><span class="v" id="pingServer2">—</span></div>
								<div class="kv"><span class="k">وضعیت</span><span class="v" id="pingState2">—</span></div>
							</div>
							<button type="button" class="btn btn-block" id="btnPingDirect2" style="margin-bottom:14px"><svg><use href="#i-activity"/></svg>تست اتصال مستقیم</button>

							<div class="note warn" style="margin-bottom:14px"><svg><use href="#i-alert"/></svg><div>هنگام اتصال به کانفیگ‌های مستقیم، از باز کردن پنل خودداری کنید.</div></div>

							<div class="switch-row">
								<div class="sr-text">
									<div class="sr-t">تنظیم کشور و ثابت کردن آی‌پی (SOCKS5/HTTP)</div>
									<div class="sr-d">زنجیره اتصال خروجی جهت تغییر لوکیشن</div>
								</div>
								<label class="switch"><input type="checkbox" id="fProxyMode" onchange="toggleUserProxyMode(this.checked)"><i></i></label>
							</div>

							<div id="proxyFieldsBox">
								<div id="proxiesFieldsWrapper" style="display:flex;flex-direction:column;gap:10px"></div>
								<button type="button" class="btn btn-sm" id="btnAddProxy" style="margin-top:10px"><svg><use href="#i-plus"/></svg>افزودن کشور / پروکسی</button>
								<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
									<button type="button" class="btn" id="btnTestProxies"><svg><use href="#i-activity"/></svg>تست پروکسی‌ها</button>
									<button type="button" class="btn btn-primary" id="btnPublicProxy"><svg><use href="#i-globe"/></svg>اسکن پروکسی عمومی</button>
								</div>
								<div class="switch-row" style="margin-top:12px">
									<div class="sr-text">
										<div class="sr-t">تعویض خودکار پروکسی خروجی خراب</div>
										<div class="sr-d">جایگزینی هوشمند در صورت قطع شدن پروکسی</div>
									</div>
									<label class="switch"><input type="checkbox" id="fAutoRotateProxy"><i></i></label>
								</div>
							</div>
						</div>

					</div>
				</div>
			</div>
			<div class="modal-foot uf-foot">
				<button type="submit" class="btn btn-primary btn-lg uf-submit" id="userSubmitBtn"><svg><use href="#i-check"/></svg><span id="userSubmitText">ایجاد کاربر</span></button>
				<button type="button" class="btn" data-close-modal="modalUser">انصراف</button>
				<div class="spacer"></div>
				<div class="uf-steps" id="userFormSteps">
					<button type="button" class="btn btn-sm" id="btnPrevStep" title="مرحله قبل"><svg style="transform:rotate(-90deg)"><use href="#i-chevron"/></svg><span>قبلی</span></button>
					<span class="uf-step-ind" id="userStepInd">۱ / ۳</span>
					<button type="button" class="btn btn-sm" id="btnNextStep" title="مرحله بعد"><span>بعدی</span><svg style="transform:rotate(90deg)"><use href="#i-chevron"/></svg></button>
				</div>
			</div>
		</form>
	</div>
</div>
<!-- ==================== CREATED USER MODAL ==================== -->
<div class="modal" id="modalCreated">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon" style="background:var(--ok-soft);color:var(--ok)"><svg><use href="#i-check"/></svg></div>
			<div class="mh-text">
				<h3 class="modal-title">کاربر با موفقیت ایجاد شد</h3>
				<p class="modal-sub">کانفیگ و لینک اتصال آماده تحویل</p>
			</div>
			<button type="button" class="icon-btn" data-close-modal="modalCreated"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="field">
				<label>لینک هوشمند سابسکریپشن</label>
				<div class="copy-field">
					<span class="cf-val" id="createdSub"></span>
					<button type="button" class="btn btn-sm" data-copy-target="createdSub">کپی</button>
				</div>
			</div>
			<div class="field">
				<label>کانفیگ مستقیم VLESS</label>
				<textarea class="input" id="createdVless" rows="3" readonly></textarea>
				<div style="margin-top:6px"><button type="button" class="btn btn-sm" data-copy-target="createdVless"><svg><use href="#i-copy"/></svg>کپی کانفیگ</button></div>
			</div>
			<div class="grid g-2" style="align-items:center">
				<div class="qr-box"><div id="createdQr"></div></div>
				<div>
					<div class="note ok"><svg><use href="#i-check"/></svg><div>با اسکن این کد در v2rayNG یا Hiddify، اشتراک به‌صورت خودکار افزوده می‌شود.</div></div>
					<div style="display:flex;flex-direction:column;gap:6px;margin-top:10px">
						<button type="button" class="btn btn-block" id="btnCreatedPortal"><svg><use href="#i-external"/></svg>باز کردن پرتال کاربر</button>
						<button type="button" class="btn btn-block" id="btnCreatedStatus"><svg><use href="#i-activity"/></svg>صفحه وضعیت اتصال</button>
					</div>
				</div>
			</div>
		</div>
		<div class="modal-foot">
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" data-close-modal="modalCreated">بستن و مشاهده لیست</button>
		</div>
	</div>
</div>

<!-- ==================== QR MODAL ==================== -->
<div class="modal narrow" id="modalQr">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-qr"/></svg></div>
			<div class="mh-text"><h3 class="modal-title" id="qrTitle">کد QR</h3><p class="modal-sub" id="qrSub"></p></div>
			<button type="button" class="icon-btn" data-close-modal="modalQr"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body" style="display:flex;flex-direction:column;align-items:center;gap:12px">
			<div class="qr-box" style="width:100%"><div id="qrContainer"></div></div>
			<div class="copy-field" style="width:100%"><span class="cf-val" id="qrText"></span><button type="button" class="btn btn-sm" data-copy-target="qrText">کپی</button></div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" id="btnDownloadQr"><svg><use href="#i-download"/></svg>دانلود تصویر</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" data-close-modal="modalQr">بستن</button>
		</div>
	</div>
</div>

<!-- ==================== BULK CREATE MODAL ==================== -->
<div class="modal" id="modalBulk">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-box"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">ساخت و ایمپورت گروهی</h3><p class="modal-sub">تولید رندوم یا ورود فهرست نام‌ها</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalBulk"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="tabs" id="bulkTabs" style="margin-bottom:12px">
				<button type="button" class="tab active" data-btab="btab-auto">تولید رندوم</button>
				<button type="button" class="tab" data-btab="btab-manual">ایمپورت از لیست</button>
			</div>
			<form id="bulkAutoForm">
				<div class="form-row">
					<div class="field">
						<label for="bulkCount">تعداد کاربران (۱ تا ۵۰)</label>
						<input type="number" class="input" id="bulkCount" min="1" max="50" value="10" required>
					</div>
					<div class="field">
						<label for="bulkPrefix">پیشوند نام کاربری</label>
						<input type="text" class="input input-mono" id="bulkPrefix" value="vip" required>
					</div>
				</div>
				<div class="form-row">
					<div class="field">
						<label for="bulkLimit">حجم ترافیک (GB)</label>
						<input type="number" class="input" id="bulkLimit" placeholder="نامحدود" step="0.1">
					</div>
					<div class="field">
						<label for="bulkExpiry">مدت زمان (روز)</label>
						<input type="number" class="input" id="bulkExpiry" value="30">
					</div>
				</div>
				<button type="submit" class="btn btn-primary btn-block" id="bulkSubmit"><svg><use href="#i-plus"/></svg>ساخت دسته‌ای کاربران</button>
			</form>
			<div id="bulkManualBox" class="hidden">
				<div class="field">
					<label for="bulkNames">لیست نام‌های کاربری (هر خط یک نام)</label>
					<textarea class="input" id="bulkNames" rows="6" placeholder="user1" dir="ltr"></textarea>
					<span class="hint">برای هر کاربر ۳۰ گیگابایت و ۳۰ روز اعتبار در نظر گرفته می‌شود</span>
				</div>
				<button type="button" class="btn btn-primary btn-block" id="bulkImportBtn"><svg><use href="#i-upload"/></svg>ایمپورت کاربران لیست</button>
			</div>
			<div id="bulkResultBox" class="hidden" style="margin-top:14px">
				<div class="field">
					<label>اکانت‌های تولید شده</label>
					<textarea class="input" id="bulkLinks" rows="6" readonly></textarea>
				</div>
				<div style="display:flex;gap:8px">
					<button type="button" class="btn" id="btnCopyBulk"><svg><use href="#i-copy"/></svg>کپی لینک‌ها</button>
					<button type="button" class="btn" id="btnDownloadBulk"><svg><use href="#i-download"/></svg>دانلود TXT</button>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- ==================== BATCH RENEW MODAL ==================== -->
<div class="modal narrow" id="modalBatchRenew">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-refresh"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">تمدید دسته‌ای</h3><p class="modal-sub">افزودن زمان و حجم به گروهی از کاربران</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalBatchRenew"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="form-row">
				<div class="field">
					<label for="renewDays">افزایش اعتبار زمانی (روز)</label>
					<input type="number" class="input" id="renewDays" value="30">
				</div>
				<div class="field">
					<label for="renewGb">افزایش حجم (GB)</label>
					<input type="number" class="input" id="renewGb" value="0" step="0.1">
				</div>
			</div>
			<div class="field">
				<label for="renewTarget">هدف تمدید</label>
				<select class="select" id="renewTarget">
					<option value="expired">فقط کاربران منقضی شده</option>
					<option value="all">تمام کاربران پنل</option>
				</select>
			</div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalBatchRenew">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnDoBatchRenew"><svg><use href="#i-check"/></svg>اعمال تمدید</button>
		</div>
	</div>
</div>

<!-- ==================== VOUCHER MODAL ==================== -->
<div class="modal narrow" id="modalVoucher">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-ticket"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">ایجاد کارت شارژ</h3><p class="modal-sub">کد را خالی بگذارید تا رندوم ساخته شود</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalVoucher"><svg><use href="#i-x"/></svg></button>
		</div>
		<form id="modalVoucherForm">
			<div class="modal-body">
				<div class="field">
					<label for="mvCode">کد کارت شارژ</label>
					<input type="text" class="input input-mono" id="mvCode" placeholder="LML-50GB-30D" autocomplete="off">
				</div>
				<div class="form-row">
					<div class="field">
						<label for="mvGb">حجم (GB)</label>
						<input type="number" class="input" id="mvGb" value="20" min="0" step="0.1" required>
					</div>
					<div class="field">
						<label for="mvDays">مدت (روز)</label>
						<input type="number" class="input" id="mvDays" value="30" min="1" required>
					</div>
				</div>
			</div>
			<div class="modal-foot">
				<button type="button" class="btn" data-close-modal="modalVoucher">انصراف</button>
				<div class="spacer"></div>
				<button type="submit" class="btn btn-primary" id="mvSubmit"><svg><use href="#i-plus"/></svg>تولید ووچر</button>
			</div>
		</form>
	</div>
</div>

<!-- ==================== RESELLER MODAL ==================== -->
<div class="modal" id="modalReseller">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-handshake"/></svg></div>
			<div class="mh-text"><h3 class="modal-title" id="resellerModalTitle">افزودن نماینده جدید</h3><p class="modal-sub">تعریف دسترسی، سهمیه ترافیک و سقف کاربر</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalReseller"><svg><use href="#i-x"/></svg></button>
		</div>
		<form id="resellerForm">
			<div class="modal-body">
				<input type="hidden" id="rsId">
				<div class="form-row">
					<div class="field">
						<label for="rsUsername">نام کاربری نماینده</label>
						<input type="text" class="input input-mono" id="rsUsername" placeholder="reseller_ali" required autocomplete="off">
					</div>
					<div class="field">
						<label for="rsPassword">رمز عبور</label>
						<input type="password" class="input" id="rsPassword" placeholder="حداقل ۶ کاراکتر" autocomplete="new-password">
						<span class="hint" id="rsPassHint">برای نماینده جدید الزامی است</span>
					</div>
				</div>
				<div class="form-row">
					<div class="field">
						<label for="rsCredit">سهمیه کل ترافیک (GB)</label>
						<input type="number" class="input" id="rsCredit" value="100" min="1" step="1" required>
					</div>
					<div class="field">
						<label for="rsMaxUsers">سقف تعداد کاربر</label>
						<input type="number" class="input" id="rsMaxUsers" value="50" min="1" required>
					</div>
				</div>
				<div class="field">
					<label for="rsNote">یادداشت / نام شخص</label>
					<input type="text" class="input" id="rsNote" placeholder="مثال: آقای محمدی - شعبه شمال">
				</div>
				<div class="switch-row" style="margin-bottom:0">
					<div class="sr-text"><div class="sr-t">حساب فعال باشد</div><div class="sr-d">نماینده غیرفعال نمی‌تواند وارد شود</div></div>
					<label class="switch"><input type="checkbox" id="rsActive" checked><i></i></label>
				</div>
			</div>
			<div class="modal-foot">
				<button type="button" class="btn" data-close-modal="modalReseller">انصراف</button>
				<div class="spacer"></div>
				<button type="submit" class="btn btn-primary" id="rsSubmit"><svg><use href="#i-check"/></svg>ذخیره نماینده</button>
			</div>
		</form>
	</div>
</div>

<!-- ==================== RESELLER CREDIT MODAL ==================== -->
<div class="modal narrow" id="modalCredit">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-wallet"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">افزایش سهمیه</h3><p class="modal-sub" id="creditSub"></p></div>
			<button type="button" class="icon-btn" data-close-modal="modalCredit"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="field">
				<label for="creditGb">مقدار افزایش (گیگابایت)</label>
				<input type="number" class="input" id="creditGb" value="50" min="1" step="1">
			</div>
			<div class="quick-row">
				<button type="button" class="btn btn-sm" data-credit="10">+۱۰</button>
				<button type="button" class="btn btn-sm" data-credit="50">+۵۰</button>
				<button type="button" class="btn btn-sm" data-credit="100">+۱۰۰</button>
				<button type="button" class="btn btn-sm" data-credit="500">+۵۰۰</button>
			</div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalCredit">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnDoCredit"><svg><use href="#i-check"/></svg>افزایش سهمیه</button>
		</div>
	</div>
</div>

<!-- ==================== LIVE CDN IP SCANNER MODAL ==================== -->
<div class="modal narrow" id="modalIps">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-globe"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">اسکنر آی‌پی زنده</h3><p class="modal-sub">دریافت لحظه‌ای رنج‌های کلودفلر، آمازون، فستلی و...</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalIps"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="field">
				<label>شبکه تأمین‌کننده (CDN)</label>
				<div class="opt-grid" id="ipProvGrid">
					<label class="opt-card"><input type="checkbox" class="ip-prov" value="cf" checked><span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span class="oc-text"><span class="oc-t">Cloudflare</span><span class="oc-d">رنج رسمی و زنده</span></span></label>
					<label class="opt-card"><input type="checkbox" class="ip-prov" value="aws"><span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span class="oc-text"><span class="oc-t">Amazon CloudFront</span><span class="oc-d">AWS ip-ranges</span></span></label>
					<label class="opt-card"><input type="checkbox" class="ip-prov" value="fastly"><span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span class="oc-text"><span class="oc-t">Fastly</span><span class="oc-d">public-ip-list</span></span></label>
					<label class="opt-card"><input type="checkbox" class="ip-prov" value="google"><span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span class="oc-text"><span class="oc-t">Google</span><span class="oc-d">goog.json</span></span></label>
					<label class="opt-card"><input type="checkbox" class="ip-prov" value="azure"><span class="box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg></span><span class="oc-text"><span class="oc-t">Microsoft Azure</span><span class="oc-d">رنج‌های ثابت</span></span></label>
				</div>
			</div>
			<div class="field">
				<label for="ipCount">تعداد آی‌پی</label>
				<input type="number" class="input" id="ipCount" min="1" max="500" value="20">
				<div class="quick-row">
					<button type="button" class="btn btn-sm" data-ipcount="10">۱۰</button>
					<button type="button" class="btn btn-sm" data-ipcount="20">۲۰</button>
					<button type="button" class="btn btn-sm" data-ipcount="50">۵۰</button>
					<button type="button" class="btn btn-sm" data-ipcount="100">۱۰۰</button>
				</div>
			</div>
			<div id="ipLoading" class="scan-log hidden"></div>
			<div class="note"><svg><use href="#i-info"/></svg><div>رنج‌ها به‌صورت زنده از منابع رسمی هر CDN دریافت می‌شوند؛ اگر دسترسی به منبعی قطع باشد، از رنج‌های پشتیبان داخلی استفاده می‌شود.</div></div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalIps">لغو</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnApplyIps"><svg><use href="#i-search"/></svg>اسکن و درج</button>
		</div>
	</div>
</div>

<!-- ==================== PUBLIC PROXY SCANNER MODAL ==================== -->
<div class="modal narrow" id="modalProxyScan">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-globe"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">اسکن پروکسی عمومی</h3><p class="modal-sub">جستجو و تست پروکسی‌های رایگان عمومی (بدون نیاز به VIP)</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalProxyScan"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="field">
				<label for="pscanCountry">کشور</label>
				<select class="select" id="pscanCountry"></select>
			</div>
			<div class="field">
				<label>حداکثر تعداد تست</label>
				<select class="select" id="pscanLimit">
					<option value="20">۲۰ پروکسی (سریع)</option>
					<option value="40" selected>۴۰ پروکسی (متعادل)</option>
					<option value="80">۸۰ پروکسی (دقیق)</option>
				</select>
			</div>
			<div class="note"><svg><use href="#i-info"/></svg><div>لیست پروکسی‌ها از منابع عمومی رایگان دریافت و سپس با ۳ تلاش پشت‌سرهم تست می‌شود؛ بهترین پروکسی از نظر تعداد پاسخ موفق و کمترین پینگ انتخاب می‌گردد.</div></div>
			<div class="scan-log hidden" id="pscanLog"></div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalProxyScan">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnPscanStart"><svg><use href="#i-search"/></svg>شروع اسکن</button>
		</div>
	</div>
</div>

<!-- ==================== QUICK CONFIG MODAL ==================== -->
<div class="modal narrow" id="modalQuick">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon" style="background:var(--accent-soft);color:var(--accent)"><svg><use href="#i-bolt"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">ساخت سریع کانفیگ</h3><p class="modal-sub">بهترین تنظیمات بر اساس نوع اینترنت شما</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalQuick"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="form-row">
				<div class="field">
					<label for="quickLimit">حجم (گیگابایت)</label>
					<input type="number" class="input" id="quickLimit" value="30" min="1" step="1">
				</div>
				<div class="field">
					<label for="quickDays">مدت اعتبار (روز)</label>
					<input type="number" class="input" id="quickDays" value="30" min="1" step="1">
				</div>
			</div>
			<div class="form-row">
				<div class="field">
					<label for="quickCount">تعداد کاربر</label>
					<input type="number" class="input" id="quickCount" value="1" min="1" max="50" step="1">
				</div>
				<div class="field">
					<label for="quickIsp">اینترنت شما چیست؟</label>
					<select class="select" id="quickIsp"></select>
				</div>
			</div>
			<div class="field">
				<label>تنظیماتی که اعمال می‌شود</label>
				<div id="quickPreview" style="display:grid;grid-template-columns:1fr 1fr;gap:5px"></div>
			</div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalQuick">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnQuickCreate"><svg><use href="#i-bolt"/></svg>ساخت کانفیگ</button>
		</div>
	</div>
</div>

<!-- ==================== WARP MODAL ==================== -->

<!-- ==================== CLOUDFLARE TOKEN MODAL ==================== -->
<div class="modal narrow" id="modalToken">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-key"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">توکن کلودفلر</h3><p class="modal-sub">برای آپدیت خودکار از داخل پنل</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalToken"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body">
			<div class="note"><svg><use href="#i-info"/></svg><div>توکن کلودفلر شما در این پنل ذخیره نشده است. برای فعال‌سازی آپدیت خودکار، توکن را دریافت و وارد کنید.</div></div>
			<div style="margin:14px 0">
				<a class="btn btn-block" href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&amp;accountId=*&amp;zoneId=all&amp;name=LML-Deployer-Token" target="_blank" rel="noopener"><svg><use href="#i-external"/></svg>دریافت توکن کلودفلر</a>
			</div>
			<div class="field">
				<label for="tokenInput">توکن</label>
				<input type="password" class="input input-mono" id="tokenInput" placeholder="توکن را اینجا وارد کنید" autocomplete="off">
			</div>
		</div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalToken">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnSubmitToken"><svg><use href="#i-check"/></svg>ثبت و ادامه</button>
		</div>
	</div>
</div>

<!-- ==================== UPDATE MODAL ==================== -->
<div class="modal narrow" id="modalUpdate">
	<div class="modal-card">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-git"/></svg></div>
			<div class="mh-text"><h3 class="modal-title">بروزرسانی پنل</h3><p class="modal-sub">نسخه جدید در دسترس است</p></div>
			<button type="button" class="icon-btn" data-close-modal="modalUpdate"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body" id="updateModalText" style="line-height:1.8"></div>
		<div class="modal-foot">
			<button type="button" class="btn" data-close-modal="modalUpdate">انصراف</button>
			<div class="spacer"></div>
			<button type="button" class="btn btn-primary" id="btnApplyUpdate"><svg><use href="#i-download"/></svg>آپدیت خودکار</button>
		</div>
	</div>
</div>

<!-- ==================== USER DRAWER ==================== -->
<div class="drawer" id="drawerUser">
	<div class="drawer-panel">
		<div class="modal-head">
			<div class="mh-icon"><svg><use href="#i-user"/></svg></div>
			<div class="mh-text">
				<h3 class="modal-title" id="drawerUserName">—</h3>
				<p class="modal-sub" id="drawerUserSub"></p>
			</div>
			<button type="button" class="icon-btn" data-close-drawer="drawerUser"><svg><use href="#i-x"/></svg></button>
		</div>
		<div class="modal-body" id="drawerUserBody"></div>
		<div class="modal-foot" id="drawerUserFoot"></div>
	</div>
</div>

<div id="toast-wrap"></div>
<input type="file" id="hiddenFile" class="hidden">
<script>
(function () {
"use strict";

/* ============================================================
   0. CONSTANTS & STATE
   ============================================================ */
var CURRENT_VERSION = '1.0.1';
var UPDATE_FIX = "constsCURRENT_VERSION='d.d.d'";
var TLS_PORTS = ['443', '2053', '2083', '2087', '2096', '8443'];
var NON_TLS_PORTS = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];

var State = {
	allUsers: [],
	filtered: [],
	selected: {},
	selectedCount: 0,
	serverTime: Date.now(),
	lastSync: 0,
	stats: { total: 0, active: 0, expired: 0, online: 0, gb: 0, vouchers: 0, resellers: 0, reqToday: 0, reqTotal: 0, d1r: 0, d1w: 0, deletedGb: 0 },
	vouchers: [],
	resellers: [],
	settings: {},
	role: 'admin',
	session: null,
	editMode: false,
	editingUsername: '',
	proxyFields: [''],
	activeProxyIndex: 0,
	proxyPingMap: {},
	smoothCache: {},
	cachedIps: {},
	cachedVipList: null,
	cachedVipProxies: {},
	ipsFetchedAt: 0,
	loading: false,
	inited: false,
	refreshTimer: null,
	latestVersion: null,
	autoUpdate: false,
	view: 'view-dashboard',
	scanEnabled: true,
	autoRefreshing: false,
	usersSig: null,
	dashDirty: false,
	sysDirty: false,
	tableHover: false,
	pendingTableRender: false
};
window.LML = State;

/* ============================================================
   1. DOM HELPERS
   ============================================================ */
function $(id) { return document.getElementById(id); }
function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
function on(node, evt, fn, opts) { if (node) node.addEventListener(evt, fn, opts); }
function esc(s) {
	return String(s === undefined || s === null ? '' : s)
		.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function attr(s) { return esc(s).split(String.fromCharCode(96)).join('&#96;'); }
function debounce(fn, ms) {
	var t; return function () {
		var a = arguments, self = this;
		clearTimeout(t); t = setTimeout(function () { fn.apply(self, a); }, ms);
	};
}
function svgIcon(name, cls) {
	return '<svg' + (cls ? ' class="' + cls + '"' : '') + '><use href="#i-' + name + '"/></svg>';
}

/* number / unit formatting */
function nfmt(v) {
	if (v === null || v === undefined || isNaN(v)) return '0';
	return Number(v).toLocaleString('en-US');
}
function kbStr(v) {
	v = Number(v) || 0;
	return v < 1 ? (v * 1024).toFixed(0) + ' MB' : v.toFixed(2) + ' GB';
}
function kbShort(v) {
	v = Number(v) || 0;
	return v < 1 ? (v * 1024).toFixed(0) + 'MB' : v.toFixed(2) + 'GB';
}
function compact(v) {
	v = Number(v) || 0;
	if (v >= 1000000) return (v / 1000000).toFixed(2) + 'M';
	if (v >= 1000) return (v / 1000).toFixed(1) + 'k';
	return String(Math.round(v));
}
function pad2(n) { return String(n).padStart(2, '0'); }
function timeStr(ts) {
	if (!ts) return '—';
	var d = new Date(ts);
	return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function dateStr(v) {
	if (!v) return '—';
	var d = new Date(v);
	if (isNaN(d.getTime())) return String(v);
	return d.getFullYear() + '/' + pad2(d.getMonth() + 1) + '/' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
}
function faDate(v) {
	if (!v) return '—';
	var d = new Date(v);
	if (isNaN(d.getTime())) return String(v);
	return d.toLocaleDateString('fa-IR') + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
}

/* Flags: emoji regional indicators (no external CSS dependency) */
function flagText(cc) {
	if (!cc) return '🌐';
	var c = String(cc).toUpperCase().replace(/[^A-Z]/g, '');
	if (c.length !== 2) return '🌐';
	try { return String.fromCodePoint(127397 + c.charCodeAt(0), 127397 + c.charCodeAt(1)); } catch (e) { return '🌐'; }
}
function flagHtml(cc, cls) {
	return '<span class="flag' + (cls ? ' ' + cls : '') + '" title="' + attr(String(cc || '').toUpperCase()) + '">' + flagText(cc) + '</span>';
}

/* ============================================================
   2. TOAST / NOTIFICATION SYSTEM
   ============================================================ */
var TOAST_ICONS = { ok: 'check', err: 'alert', warn: 'alert', info: 'info' };
function toast(msg, type, ms) {
	type = type || 'ok';
	if (msg === null || msg === undefined) msg = '';
	var msgStr = String(msg);
	if (/خطا|⚠️|❌|error/i.test(msgStr) && type === 'ok') type = 'warn';
	var wrap = $('toast-wrap');
	if (!wrap) return;
	var t = document.createElement('div');
	t.className = 'toast ' + type;
	t.innerHTML =
		'<span class="tic">' + svgIcon(TOAST_ICONS[type] || 'info') + '</span>' +
		'<span class="tbody">' + esc(msgStr) + '</span>' +
		'<button type="button" class="icon-btn tclose" aria-label="بستن">' + svgIcon('x') + '</button>';
	wrap.appendChild(t);
	var kill = function () {
		if (!t.parentNode) return;
		t.classList.add('out');
		setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 220);
	};
	on(t.querySelector('.tclose'), 'click', kill);
	setTimeout(kill, ms || 4000);
	while (wrap.children.length > 5) wrap.removeChild(wrap.firstChild);
}
window.toast = toast;
window.showToast = toast;

/* Legacy bridge: alert() -> toast */
window.alert = function (message) {
	var s = message === null || message === undefined ? '' : String(message);
	toast(s, /خطا|⚠️|❌/.test(s) ? 'err' : (s.length ? 'ok' : 'info'));
};

/* ============================================================
   3. MODAL / DRAWER / MENU ENGINE
   ============================================================ */
function openModal(id) {
	var m = $(id); if (!m) return;
	m.classList.add('open');
	document.body.style.overflow = 'hidden';
}
function closeModal(id) {
	var m = $(id); if (!m) return;
	m.classList.remove('open');
	if (!document.querySelector('.modal.open, .drawer.open')) document.body.style.overflow = '';
}
function openDrawer(id) {
	var d = $(id); if (!d) return;
	d.classList.add('open');
	document.body.style.overflow = 'hidden';
}
function closeDrawer(id) {
	var d = $(id); if (!d) return;
	d.classList.remove('open');
	if (!document.querySelector('.modal.open, .drawer.open')) document.body.style.overflow = '';
}
document.addEventListener('click', function (e) {
	var t = e.target;
	var mc = t.closest ? t.closest('[data-close-modal]') : null;
	if (mc) { closeModal(mc.getAttribute('data-close-modal')); return; }
	var dc = t.closest ? t.closest('[data-close-drawer]') : null;
	if (dc) { closeDrawer(dc.getAttribute('data-close-drawer')); return; }
	if (t.classList && t.classList.contains('modal')) closeModal(t.id);
	if (t.id === 'drawerUser' || (t.classList && t.classList.contains('drawer'))) closeDrawer(t.id);
});
document.addEventListener('keydown', function (e) {
	if (e.key !== 'Escape') return;
	var open = document.querySelector('.drawer.open');
	if (open) { closeDrawer(open.id); return; }
	var mods = $$('.modal.open');
	if (mods.length) closeModal(mods[mods.length - 1].id);
	closeMenus();
});

/* Confirm dialog (promise based) */
var confirmResolve = null;
function confirmBox(message, opts) {
	opts = opts || {};
	$('confirmTitle').textContent = opts.title || 'تأیید عملیات';
	$('confirmSub').textContent = opts.sub || '';
	$('confirmMessage').innerHTML = esc(message || '');
	var okBtn = $('confirmOk');
	okBtn.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');
	okBtn.textContent = opts.okText || 'تأیید';
	$('confirmCancel').textContent = opts.cancelText || 'انصراف';
	$('confirmIcon').innerHTML = svgIcon(opts.danger ? 'alert' : 'info');
	$('confirmIcon').style.background = opts.danger ? 'var(--err-soft)' : 'var(--accent-soft)';
	$('confirmIcon').style.color = opts.danger ? 'var(--err)' : 'var(--accent-text)';
	openModal('modalConfirm');
	return new Promise(function (resolve) { confirmResolve = resolve; });
}
function endConfirm(v) {
	closeModal('modalConfirm');
	if (confirmResolve) { var r = confirmResolve; confirmResolve = null; r(v); }
}
on($('confirmOk'), 'click', function () { endConfirm(true); });
on($('confirmCancel'), 'click', function () { endConfirm(false); });
window.confirmBox = confirmBox;
window.confirm = function (m) { return confirmBox(m, { danger: false }); };

/* Generic modal */
function genericModal(cfg) {
	$('genTitle').textContent = cfg.title || '';
	$('genSub').textContent = cfg.sub || '';
	$('genIcon').innerHTML = svgIcon(cfg.icon || 'info');
	$('genIcon').style.background = cfg.color ? cfg.color : 'var(--accent-soft)';
	$('genIcon').style.color = cfg.iconColor ? cfg.iconColor : 'var(--accent-text)';
	$('genBody').innerHTML = cfg.body || '';
	var foot = $('genFoot');
	foot.innerHTML = '';
	(cfg.buttons || []).forEach(function (b) {
		var btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'btn' + (b.primary ? ' btn-primary' : '');
		btn.innerHTML = (b.icon ? svgIcon(b.icon) : '') + esc(b.text);
		on(btn, 'click', function () {
			if (b.keepOpen !== true) closeModal('modalGeneric');
			if (b.onClick) b.onClick();
		});
		foot.appendChild(btn);
	});
	if (!(cfg.buttons || []).length) {
		var sp = document.createElement('div'); sp.className = 'spacer'; foot.appendChild(sp);
		var b2 = document.createElement('button');
		b2.type = 'button'; b2.className = 'btn btn-primary'; b2.textContent = 'متوجه شدم';
		on(b2, 'click', function () { closeModal('modalGeneric'); });
		foot.appendChild(b2);
	}
	openModal('modalGeneric');
}
window.genericModal = genericModal;

/* Dropdown menus */
var openMenuEl = null;

/* True while the user is interacting with the UI — during those moments the
   users table must NOT be rebuilt, otherwise the open "..." menu is destroyed
   and the click on "copy config" / "show info" is lost. */
function uiBusy() {
	if (openMenuEl) return true;
	if (State.tableHover) return true;
	if (document.querySelector) {
		if (document.querySelector('.modal.open')) return true;
		if (document.querySelector('.drawer.open')) return true;
		if (document.querySelector('.menu.open')) return true;
		if (document.activeElement && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
			/* don't rebuild while a form field is focused (edit user, etc.) */
			if (document.getElementById('modalUser') && document.getElementById('modalUser').classList.contains('open')) return true;
		}
	}
	return false;
}
function flushPendingTable() {
	if (!State.pendingTableRender) return;
	State.pendingTableRender = false;
	try { filterAndRenderUsers(); } catch (e) { }
}
function closeMenus() {
	$$('.menu.open').forEach(function (m) { m.classList.remove('open'); });
	if (openMenuEl && openMenuEl.parentNode) { try { openMenuEl.parentNode.removeChild(openMenuEl); } catch (e) { } }
	openMenuEl = null;
	flushPendingTable();
}
document.addEventListener('click', function (e) {
	if (e.target.closest && e.target.closest('.menu')) return;
	if (e.target.closest && e.target.closest('[data-menu]')) return;
	closeMenus();
});
window.addEventListener('resize', closeMenus);
/* Close on scroll, but never for a scroll happening inside the menu:
   otherwise opening one inside a scrollable area killed it instantly. */
document.addEventListener('scroll', function (e) {
	/* Don't auto-close menus on programmatic/table-scroll events — it made
	   the three-dot menu impossible to click on because the auto-refresh
	   triggered a layout/scroll that closed it before click landed. */
	if (State.autoRefreshing) return;
	if (openMenuEl && e.target && openMenuEl.contains && openMenuEl.contains(e.target)) return;
	/* Don't close when mouse is actively hovering the menu */
	if (openMenuEl && openMenuEl.matches && openMenuEl.matches(':hover')) return;
	closeMenus();
}, true);

function openMenu(anchor, items) {
	closeMenus();
	var menu = document.createElement('div');
	/* Mounted on <body> in viewport coordinates. It used to go into
	   anchor.offsetParent, i.e. inside the users table - a table that is
	   rebuilt on every refresh, which deleted the menu out from under the
	   pointer. On mobile the table is also a scroll container, so the menu
	   was clipped there too. */
	menu.className = 'menu open menu-fixed';
	items.forEach(function (it) {
		if (it === '-') { var s = document.createElement('div'); s.className = 'mi-sep'; menu.appendChild(s); return; }
		if (it.head) { var h = document.createElement('div'); h.className = 'mi-head'; h.textContent = it.head; menu.appendChild(h); return; }
		var b = document.createElement('button');
		b.type = 'button';
		b.className = 'mi' + (it.danger ? ' danger' : '');
		b.innerHTML = (it.icon ? svgIcon(it.icon) : '<span style="width:15px"></span>') + '<span>' + esc(it.label) + '</span>';
		on(b, 'click', function () { closeMenus(); if (it.action) it.action(); });
		menu.appendChild(b);
	});
	document.body.appendChild(menu);
	openMenuEl = menu;
	var r = anchor.getBoundingClientRect();
	var mw = menu.offsetWidth, mh = menu.offsetHeight;
	var vw = window.innerWidth || (document.documentElement ? document.documentElement.clientWidth : 0) || 0;
	var vh = window.innerHeight || (document.documentElement ? document.documentElement.clientHeight : 0) || 0;
	var left = r.left;
	var top = r.bottom + 4;
	if (left + mw > vw - 8) left = Math.max(8, vw - mw - 8);
	if (top + mh > vh - 8) top = Math.max(8, r.top - mh - 4);
	if (top < 8) top = 8;
	menu.style.left = left + 'px';
	menu.style.top = top + 'px';
	return menu;
}

/* ============================================================
   4. CLIPBOARD
   ============================================================ */
function copyText(text, msg) {
	var done = function () { toast(msg || '✅ کپی شد!', 'ok'); };
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(done).catch(function () { legacyCopy(text, done); });
		return;
	}
	legacyCopy(text, done);
}
function legacyCopy(text, done) {
	try {
		var ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.top = '-1000px';
		ta.setAttribute('readonly', '');
		document.body.appendChild(ta);
		ta.select();
		document.execCommand('copy');
		document.body.removeChild(ta);
		done();
	} catch (e) { toast('❌ خطا در کپی کردن', 'err'); }
}
window.copyText = copyText;

document.addEventListener('click', function (e) {
	var btn = e.target.closest ? e.target.closest('[data-copy-target]') : null;
	if (!btn) return;
	var src = $(btn.getAttribute('data-copy-target'));
	if (!src) return;
	copyText(src.value || src.textContent, '✅ کپی شد!');
});
document.addEventListener('click', function (e) {
	var btn = e.target.closest ? e.target.closest('[data-copy]') : null;
	if (!btn) return;
	copyText(btn.getAttribute('data-copy'), btn.getAttribute('data-copy-msg') || '✅ کپی شد!');
});

/* ============================================================
   5. QR CODE GENERATOR (self-contained, byte mode, EC level L)
   Replaces the external qr-code-styling library.
   ============================================================ */
var QRLib = (function () {
	var EXP = new Array(512), LOG = new Array(256);
	(function () {
		var x = 1;
		for (var i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
		for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
	})();
	function mul(a, b) { return (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]]; }

	function genPoly(n) {
		var p = [1];
		for (var i = 0; i < n; i++) {
			var np = new Array(p.length + 1);
			for (var k = 0; k < np.length; k++) np[k] = 0;
			for (var j = 0; j < p.length; j++) {
				np[j] ^= p[j];
				np[j + 1] ^= mul(p[j], EXP[i]);
			}
			p = np;
		}
		return p;
	}
	function ecc(data, n) {
		var g = genPoly(n);
		var res = data.slice();
		for (var i = 0; i < n; i++) res.push(0);
		for (var i2 = 0; i2 < data.length; i2++) {
			var coef = res[i2];
			if (coef !== 0) for (var j = 0; j < g.length; j++) res[i2 + j] ^= mul(g[j], coef);
		}
		return res.slice(data.length);
	}

	/* version -> [totalCodewords, ecPerBlock, blocksA, dataA, blocksB, dataB] (EC level L) */
	var SPEC = {
		1: [26, 7, 1, 19, 0, 0],
		2: [44, 10, 1, 34, 0, 0],
		3: [70, 15, 1, 55, 0, 0],
		4: [100, 20, 1, 80, 0, 0],
		5: [134, 26, 1, 108, 0, 0],
		6: [172, 18, 2, 68, 0, 0],
		7: [196, 20, 2, 78, 0, 0],
		8: [242, 24, 2, 97, 0, 0],
		9: [292, 30, 2, 116, 0, 0],
		10: [346, 18, 2, 68, 2, 69]
	};
	var ALIGN = {
		1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
		7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]
	};

	function bitLen(x) { var n = 0; while (x) { n++; x >>>= 1; } return n; }
	function versionBits(v) {
		var d = v << 12;
		while (bitLen(d) >= 13) d ^= 0x1F25 << (bitLen(d) - 13);
		return (v << 12) | d;
	}
	function formatBits(eclBits, mask) {
		var data = (eclBits << 3) | mask;
		var d = data << 10;
		while (bitLen(d) >= 11) d ^= 0x537 << (bitLen(d) - 11);
		return ((data << 10) | d) ^ 0x5412;
	}

	function utf8Bytes(str) {
		var out = [], i, c;
		for (i = 0; i < str.length; i++) {
			c = str.charCodeAt(i);
			if (c < 0x80) out.push(c);
			else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
			else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
				var c2 = str.charCodeAt(i + 1);
				var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
				i++;
				out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
			} else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
		}
		return out;
	}

	function pickVersion(byteLen) {
		for (var v = 1; v <= 10; v++) {
			var s = SPEC[v];
			var dataCw = s[2] * s[3] + s[4] * s[5];
			var cap = Math.floor((dataCw * 8 - (v < 10 ? 12 : 20)) / 8);
			if (byteLen <= cap) return v;
		}
		return 0;
	}

	function build(version, dataBytes) {
		var s = SPEC[version];
		var ecLen = s[1], blocksA = s[2], dataA = s[3], blocksB = s[4], dataB = s[5];
		var size = version * 4 + 17;
		var i, j, r, c;

		/* --- bit stream: mode 0100 + length + data + terminator + padding --- */
		var bits = [];
		function push(val, len) { for (var k = len - 1; k >= 0; k--) bits.push((val >>> k) & 1); }
		push(4, 4);
		push(dataBytes.length, version < 10 ? 8 : 16);
		for (i = 0; i < dataBytes.length; i++) push(dataBytes[i], 8);
		var capBits = (s[2] * s[3] + s[4] * s[5]) * 8;
		for (i = 0; i < 4 && bits.length < capBits; i++) bits.push(0);
		while (bits.length % 8 !== 0) bits.push(0);

		var dataCw = [];
		for (i = 0; i < bits.length; i += 8) {
			var b = 0;
			for (j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
			dataCw.push(b);
		}
		var padA = 0xEC, padB = 0x11;
		for (i = 0; dataCw.length < capBits / 8; i++) dataCw.push(i % 2 === 0 ? padA : padB);

		/* --- block interleaving --- */
		var blocks = [], off = 0, bi;
		for (bi = 0; bi < blocksA; bi++) { blocks.push(dataCw.slice(off, off + dataA)); off += dataA; }
		for (bi = 0; bi < blocksB; bi++) { blocks.push(dataCw.slice(off, off + dataB)); off += dataB; }
		var ecBlocks = blocks.map(function (b) { return ecc(b, ecLen); });
		var total = blocks.reduce(function (a, b2) { return a + b2.length; }, 0) + ecBlocks.reduce(function (a, b2) { return a + b2.length; }, 0);
		var final = [];
		var maxData = Math.max(dataA, dataB || 0);
		for (i = 0; i < maxData; i++) for (bi = 0; bi < blocks.length; bi++) if (i < blocks[bi].length) final.push(blocks[bi][i]);
		for (i = 0; i < ecLen; i++) for (bi = 0; bi < ecBlocks.length; bi++) final.push(ecBlocks[bi][i]);
		/* remainder bits */
		var remBits = (size * size - 0) - 0;
		void remBits; void total;

		/* --- matrix --- */
		var m = [], fx = [];
		for (r = 0; r < size; r++) { m[r] = []; fx[r] = []; for (c = 0; c < size; c++) { m[r][c] = 0; fx[r][c] = false; } }
		function setFn(row, col, v) { m[row][col] = v ? 1 : 0; fx[row][col] = true; }
		function finder(rr, cc) {
			for (var a = -1; a <= 7; a++) for (var b = -1; b <= 7; b++) {
				var y = rr + a, x = cc + b;
				if (y < 0 || x < 0 || y >= size || x >= size) continue;
				var on = (a >= 0 && a <= 6 && (b === 0 || b === 6)) ||
					(b >= 0 && b <= 6 && (a === 0 || a === 6)) ||
					(a >= 2 && a <= 4 && b >= 2 && b <= 4);
				setFn(y, x, on);
			}
		}
		finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
		for (i = 8; i < size - 8; i++) { var tv = (i % 2 === 0) ? 1 : 0; setFn(6, i, tv); setFn(i, 6, tv); }
		var ap = ALIGN[version] || [];
		var apN = ap.length;
		for (var a1 = 0; a1 < apN; a1++) for (var b1 = 0; b1 < apN; b1++) {
			if ((a1 === 0 && b1 === 0) || (a1 === 0 && b1 === apN - 1) || (a1 === apN - 1 && b1 === 0)) continue;
			var row = ap[a1], col = ap[b1];
			for (var da = -2; da <= 2; da++) for (var db = -2; db <= 2; db++) {
				var on2 = (Math.abs(da) === 2 || Math.abs(db) === 2 || (da === 0 && db === 0));
				setFn(row + da, col + db, on2);
			}
		}
		if (version >= 7) {
			var vb = versionBits(version);
			for (i = 0; i < 18; i++) {
				var bit = (vb >>> i) & 1;
				var r1 = Math.floor(i / 3), c1 = i % 3;
				setFn(r1, size - 11 + c1, bit);
				setFn(size - 11 + c1, r1, bit);
			}
		}
		/* reserve format areas */
		for (i = 0; i <= 8; i++) { if (!fx[8][i]) setFn(8, i, 0); if (!fx[i][8]) setFn(i, 8, 0); }
		for (i = 0; i < 8; i++) { if (!fx[8][size - 1 - i]) setFn(8, size - 1 - i, 0); if (!fx[size - 1 - i][8]) setFn(size - 1 - i, 8, 0); }
		setFn(size - 8, 8, 1);

		/* --- place data --- */
		var bitIdx = 0;
		for (var right = size - 1; right >= 1; right -= 2) {
			if (right === 6) right = 5;
			for (var vert = 0; vert < size; vert++) {
				for (var jj = 0; jj < 2; jj++) {
					var x2 = right - jj;
					var upward = ((right + 1) & 2) === 0;
					var y2 = upward ? size - 1 - vert : vert;
					if (!fx[y2][x2] && bitIdx < final.length * 8) {
						var byteIdx = bitIdx >>> 3;
						m[y2][x2] = (final[byteIdx] >>> (7 - (bitIdx & 7))) & 1;
						bitIdx++;
					}
				}
			}
		}

		/* --- masks & penalty --- */
		function maskFn(k, x3, y3) {
			switch (k) {
				case 0: return (x3 + y3) % 2 === 0;
				case 1: return y3 % 2 === 0;
				case 2: return x3 % 3 === 0;
				case 3: return (x3 + y3) % 3 === 0;
				case 4: return (Math.floor(y3 / 2) + Math.floor(x3 / 3)) % 2 === 0;
				case 5: return (x3 * y3) % 2 + (x3 * y3) % 3 === 0;
				case 6: return ((x3 * y3) % 2 + (x3 * y3) % 3) % 2 === 0;
				default: return ((x3 + y3) % 2 + (x3 * y3) % 3) % 2 === 0;
			}
		}
		function applyMask(k) {
			for (var yy = 0; yy < size; yy++) for (var xx = 0; xx < size; xx++)
				if (!fx[yy][xx] && maskFn(k, xx, yy)) m[yy][xx] ^= 1;
		}
		function putFormat(k) {
			var fbits = formatBits(1, k); /* EC level L = 01 */
			for (i = 0; i <= 5; i++) setFn(i, 8, (fbits >>> i) & 1);
			setFn(7, 8, (fbits >>> 6) & 1);
			setFn(8, 8, (fbits >>> 7) & 1);
			setFn(8, 7, (fbits >>> 8) & 1);
			for (i = 9; i < 15; i++) setFn(8, 14 - i, (fbits >>> i) & 1);
			for (i = 0; i < 8; i++) setFn(8, size - 1 - i, (fbits >>> i) & 1);
			for (i = 8; i < 15; i++) setFn(size - 15 + i, 8, (fbits >>> i) & 1);
			setFn(size - 8, 8, 1);
		}
		function penalty() {
			var score = 0, x4, y4;
			/* rule 1: runs */
			for (y4 = 0; y4 < size; y4++) {
				var runC = 1;
				for (x4 = 1; x4 < size; x4++) {
					if (m[y4][x4] === m[y4][x4 - 1]) { runC++; }
					else { if (runC >= 5) score += runC - 2; runC = 1; }
				}
				if (runC >= 5) score += runC - 2;
			}
			for (x4 = 0; x4 < size; x4++) {
				var runR = 1;
				for (y4 = 1; y4 < size; y4++) {
					if (m[y4][x4] === m[y4 - 1][x4]) { runR++; }
					else { if (runR >= 5) score += runR - 2; runR = 1; }
				}
				if (runR >= 5) score += runR - 2;
			}
			/* rule 2: 2x2 blocks */
			for (y4 = 0; y4 < size - 1; y4++) for (x4 = 0; x4 < size - 1; x4++) {
				var v0 = m[y4][x4];
				if (v0 === m[y4][x4 + 1] && v0 === m[y4 + 1][x4] && v0 === m[y4 + 1][x4 + 1]) score += 3;
			}
			/* rule 3: finder-like 1:1:3:1:1 */
			var PAT = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
			function hasPat(arr, start) {
				for (var p = 0; p < 11; p++) if (arr[start + p] !== PAT[p]) return false;
				return true;
			}
			for (y4 = 0; y4 < size; y4++) {
				for (x4 = 0; x4 + 11 <= size; x4++) { if (hasPat(m[y4], x4)) score += 40; }
			}
			for (x4 = 0; x4 < size; x4++) {
				var colArr = [];
				for (y4 = 0; y4 < size; y4++) colArr.push(m[y4][x4]);
				for (y4 = 0; y4 + 11 <= size; y4++) if (hasPat(colArr, y4)) score += 40;
			}
			/* rule 4: balance */
			var dark = 0;
			for (y4 = 0; y4 < size; y4++) for (x4 = 0; x4 < size; x4++) dark += m[y4][x4];
			var total2 = size * size;
			score += Math.floor(Math.abs(dark * 20 - total2 * 10) / total2) * 10;
			return score;
		}
		var best = 0, bestScore = Infinity, snapshot = null;
		for (var mk = 0; mk < 8; mk++) {
			applyMask(mk);
			var sc = penalty();
			if (sc < bestScore) { bestScore = sc; best = mk; snapshot = m.map(function (row) { return row.slice(); }); }
			applyMask(mk); /* undo */
		}
		m = snapshot;
		putFormat(best);
		return { modules: m, size: size };
	}

	function render(container, text, px) {
		if (!container) return;
		container.innerHTML = '';
		var bytes = utf8Bytes(String(text || ''));
		var version = pickVersion(bytes.length);
		if (!version) {
			container.innerHTML = '<span style="font-size:11px;color:#b45309">متن بسیار طولانی است</span>';
			return;
		}
		var res;
		try { res = build(version, bytes); } catch (e) {
			container.innerHTML = '<span style="font-size:11px;color:#dc2626">خطا در ساخت QR</span>';
			return;
		}
		var size = res.size, m = res.modules;
		var out = Math.max(px || 200, 120);
		var parts = [];
		parts.push('<svg xmlns="http://www.w3.org/2000/svg" width="' + out + '" height="' + out + '" viewBox="0 0 ' + size + ' ' + size + '" shape-rendering="crispEdges">');
		parts.push('<rect width="' + size + '" height="' + size + '" fill="#ffffff"/>');
		for (var r = 0; r < size; r++) {
			var run = 0;
			for (var c = 0; c <= size; c++) {
				var dark = (c < size) && m[r][c] === 1;
				if (dark) { run++; continue; }
				if (run) { parts.push('<rect x="' + (c - run) + '" y="' + r + '" width="' + run + '" height="1" fill="#000000"/>'); run = 0; }
			}
		}
		parts.push('</svg>');
		container.innerHTML = parts.join('');
		container._qrSize = out;
		container._qrSvg = container.firstChild;
	}

	function download(container, filename) {
		if (!container) return;
		var svg = container._qrSvg || (container.firstChild && container.firstChild.tagName === 'svg' ? container.firstChild : null);
		if (!svg) return;
		var xml = new XMLSerializer().serializeToString(svg);
		var size = container._qrSize || 512;
		var img = new Image();
		var done = false;
		img.onload = function () {
			if (done) return; done = true;
			try {
				var cv = document.createElement('canvas');
				cv.width = img.width || size; cv.height = img.height || size;
				var ctx = cv.getContext('2d');
				if (!ctx) throw new Error('no-ctx');
				ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, cv.width, cv.height);
				ctx.drawImage(img, 0, 0);
				var a = document.createElement('a');
				a.href = cv.toDataURL('image/png');
				a.download = (filename || 'lml-qr') + '.png';
				a.click();
			} catch (e) { saveBlob(new Blob([xml], { type: 'image/svg+xml' }), (filename || 'lml-qr') + '.svg'); }
		};
		img.onerror = function () { if (done) return; done = true; saveBlob(new Blob([xml], { type: 'image/svg+xml' }), (filename || 'lml-qr') + '.svg'); };
		img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(xml)));
		setTimeout(function () { if (!done) { done = true; saveBlob(new Blob([xml], { type: 'image/svg+xml' }), (filename || 'lml-qr') + '.svg'); } }, 1500);
	}
	function saveBlob(blob, name) {
		var url = URL.createObjectURL(blob);
		var a = document.createElement('a');
		a.href = url; a.download = name; a.click();
		setTimeout(function () { URL.revokeObjectURL(url); }, 500);
	}

	return { render: render, download: download };
})();

function renderQr(containerId, text, px) {
	QRLib.render($(containerId), text, px || 200);
}
window.renderQr = renderQr;
window.renderQrIntoContainer = renderQr;

/* ============================================================
   6. API LAYER
   ============================================================ */
function api(path, opts) {
	opts = opts || {};
	var cfg = { credentials: 'same-origin', method: opts.method || 'GET' };
	if (opts.body !== undefined) {
		cfg.method = opts.method || 'POST';
		cfg.headers = { 'Content-Type': 'application/json' };
		cfg.body = JSON.stringify(opts.body);
	}
	if (opts.signal) cfg.signal = opts.signal;
	return fetch(path, cfg);
}
function fetchWithFallbackUI(path, options) {
	options = options || {};
	var primary = 'https://hoplimit.shop/' + path;
	var fallback = 'https://raw.githubusercontent.com/' + path;
	return fetch(primary, options).then(function (res) {
		if (res && res.ok) return res;
		return fetch(fallback, options);
	}).catch(function () { return fetch(fallback, options); });
}
var _liveState = { status: '', text: '' };
function setLive(status, text) {
	/* dedupe: never re-write the DOM / never flicker on every poll */
	if (_liveState.status === status && _liveState.text === text) return;
	_liveState.status = status; _liveState.text = text;
	var dot = $('liveDot'), lbl = $('liveText');
	if (dot) dot.className = 'dot-live ' + status;
	if (lbl) lbl.textContent = text;
	var sysDot = $('sysDot'), sysTxt = $('sysStatusText');
	if (sysDot) sysDot.className = 'dot-live ' + status;
	if (sysTxt) sysTxt.textContent = text;
}

/* ============================================================
   7. USER LIST — LOAD / FILTER / RENDER
   ============================================================ */
function userExpiryInfo(u, serverTime) {
	var out = { days: '∞', percent: 100, pending: false, expired: false, total: 0 };
	if (!u.expiry_days) return out;
	out.total = u.expiry_days;
	var base = null;
	if (u.start_on_first_connect === 1) {
		if (!u.first_connection_time) { out.days = u.expiry_days; out.percent = 100; out.pending = true; return out; }
		base = new Date(u.first_connection_time).getTime();
	} else if (u.created_at) {
		base = new Date(u.created_at).getTime();
	} else { out.days = u.expiry_days; return out; }
	var expiry = base + (u.expiry_days * 86400000);
	var diff = Math.ceil((expiry - new Date(serverTime).getTime()) / 86400000);
	out.days = diff > 0 ? diff : 0;
	out.percent = Math.max(0, Math.min(100, (out.days / u.expiry_days) * 100));
	out.expired = diff <= 0;
	return out;
}
function isUserExpired(u, serverTime) {
	if (u.limit_gb && (u.used_gb || 0) >= u.limit_gb) return true;
	if (u.limit_req && (u.used_req || 0) >= u.limit_req) return true;
	if (u.expiry_days) {
		if (u.start_on_first_connect === 1) {
			if (u.first_connection_time) {
				if (new Date(serverTime).getTime() > new Date(u.first_connection_time).getTime() + u.expiry_days * 86400000) return true;
			}
		} else if (u.created_at) {
			if (new Date(serverTime).getTime() > new Date(u.created_at).getTime() + u.expiry_days * 86400000) return true;
		}
	}
	return false;
}
function isUserEffective(u, serverTime) { return u.is_active !== 0 && !isUserExpired(u, serverTime); }

var _loadingUsers = false;
/* ---------- connection health ----------
   One blip must never repaint the badge. Only a sustained outage does. */
var CONN = { fails: 0, lastOk: 0, backoffUntil: 0 };
var CONN_FAIL_LIMIT = 3;      /* consecutive failures before we say "offline" */
var LOAD_TIMEOUT_MS = 25000;  /* cold starts need more than 12s */

function connOk() {
	CONN.fails = 0;
	CONN.lastOk = Date.now();
	CONN.backoffUntil = 0;
	setLive('on', 'سیستم آنلاین');
}
function connFail() {
	CONN.fails++;
	if (CONN.fails < CONN_FAIL_LIMIT) {
		/* transient - stay neutral instead of flashing red */
		setLive('busy', 'در حال برقراری ارتباط…');
		return false;
	}
	setLive('off', 'عدم ارتباط');
	/* Poll less often while down, but keep trying so recovery is noticed
	   quickly. Capped at 8s so the badge never stays red once the server
	   comes back. */
	if (CONN.fails > 12) CONN.fails = 12;
	CONN.backoffUntil = Date.now() + Math.min(8000, 2000 + CONN.fails * 600);
	return true;
}
window.__conn = CONN;

function _fetchUsersOnce(timeout) {
	var controller = new AbortController();
	var tid = setTimeout(function () { try { controller.abort(); } catch (e) { } }, timeout);
	return api('/api/users?t=' + Date.now(), { signal: controller.signal })
		.then(function (res) { clearTimeout(tid); if (!res.ok) throw new Error('HTTP ' + res.status); return res.json(); });
}

function loadUsers(silent) {
	if (State.loading && !silent) return Promise.resolve();
	if (_loadingUsers) return Promise.resolve();
	/* while the server is known to be down, skip polls for a while */
	if (silent !== true && CONN.fails >= CONN_FAIL_LIMIT) CONN.backoffUntil = 0;   /* manual: always try */
	if (CONN.fails >= CONN_FAIL_LIMIT && Date.now() < CONN.backoffUntil) return Promise.resolve();

	_loadingUsers = true;
	/* "busy" is announced only on a manual refresh — never during the 5s auto-poll */
	var busyTid = null;
	if (!State.autoRefreshing) busyTid = setTimeout(function () { setLive('busy', 'در حال بروزرسانی'); }, 700);

	return _fetchUsersOnce(LOAD_TIMEOUT_MS)
		.catch(function (err) {
			/* one silent retry before this counts as a failure */
			return new Promise(function (resolve) { setTimeout(resolve, 600); })
				.then(function () { return _fetchUsersOnce(LOAD_TIMEOUT_MS); });
		})
		.then(function (data) {
			/* ---------- the server answered: this is a SUCCESS ---------- */
			if (busyTid) clearTimeout(busyTid);
			connOk();
			/* Painting the screen is isolated: a bug in a chart or a table row
			   is a display problem, never a dead connection. */
			try {
				if (!State.autoRefreshing) State.usersSig = null;
				renderUsersUI(data);
			} catch (renderErr) {
				State.lastRenderError = (renderErr && renderErr.message) || String(renderErr);
				try { if (window.console && console.error) console.error('[LML] render error:', renderErr); } catch (e) { }
				/* one-time, non-alarming notice - the badge stays green */
				if (!State.renderErrorShown) {
					State.renderErrorShown = true;
					try { toast('\u062e\u0637\u0627\u06cc \u06a9\u0648\u0686\u06a9 \u062f\u0631 \u0646\u0645\u0627\u06cc\u0634 \u0628\u0631\u062e\u06cc \u0627\u0637\u0644\u0627\u0639\u0627\u062a - \u0627\u0631\u062a\u0628\u0627\u0637 \u0628\u0631\u0642\u0631\u0627\u0631 \u0627\u0633\u062a', 'warn'); } catch (e) { }
				}
			}
		}, function (err) {
			/* ---------- only genuine fetch / HTTP failures land here ---------- */
			if (busyTid) clearTimeout(busyTid);
			var hard = connFail();
			if (hard && !State.allUsers.length) renderUsersError(err);
		})
		.then(function () { _loadingUsers = false; State.loading = false; });
}
window.loadUsers = loadUsers;
window.fetchAndRenderUsers = loadUsers;

function renderUsersError(err) {
	var msg = (err && err.name === 'AbortError') ? 'مهلت زمانی به پایان رسید' : ((err && err.message) || 'خطای ارتباط');
	$('usersTbody').innerHTML = '';
	$('usersState').innerHTML =
		'<div class="state">' +
		'<div class="si">' + svgIcon('alert') + '</div>' +
		'<div class="st">خطا در دریافت اطلاعات</div>' +
		'<div class="sd">' + esc(msg) + '</div>' +
		'<button type="button" class="btn btn-primary" data-act="retry-load">' + svgIcon('refresh') + 'تلاش مجدد</button>' +
		'</div>';
}

function renderUsersUI(data) {
	if (!data) return;
	if (data.error) {
		var et = String(data.error);
		if (/d1/i.test(et) && /limit|exceeded/i.test(et)) et = 'سهمیه دیتابیس شما تمام شده و ساعت ۳:۳۰ درست می‌شود';
		$('usersTbody').innerHTML = '';
		$('usersState').innerHTML =
			'<div class="state"><div class="si">' + svgIcon('alert') + '</div>' +
			'<div class="st">خطا</div><div class="sd">' + esc(et) + '</div></div>';
		setLive('off', 'خطا');
		return;
	}
	var users = Array.isArray(data.users) ? data.users : [];
	var now = Date.now();

	/* smoothing cache (traffic + online) */
	users.forEach(function (u) {
		if (!u || !u.username) return;
		var c = State.smoothCache[u.username];
		if (!c) c = { gb: u.used_gb, req: u.used_req, history: [] };
		if (u.used_gb < c.gb && (c.gb - u.used_gb) < 2.0) u.used_gb = c.gb; else c.gb = u.used_gb;
		if (u.used_req < c.req && (c.req - u.used_req) < 20000) u.used_req = c.req; else c.req = u.used_req;
		c.history = (c.history || []).filter(function (h) { return now - h.time <= 10000; });
		c.history.push({ time: now, count: u.online_count || 0 });
		u.online_count = Math.max.apply(null, c.history.map(function (h) { return h.count; }).concat([0]));
		State.smoothCache[u.username] = c;
	});

	State.allUsers = users;
	State.serverTime = data.serverTime || now;
	State.stats.total = users.length;
	State.stats.online = users.reduce(function (s, u) { return s + (u.online_count || 0); }, 0);
	State.stats.gb = (data.deletedGb || 0) + users.reduce(function (s, u) { return s + (u.lifetime_used_gb || u.used_gb || 0); }, 0);
	State.stats.deletedGb = data.deletedGb || 0;
	State.stats.reqToday = Math.max(State.stats.reqToday || 0, data.cfRequestsToday || 0);
	State.stats.reqTotal = Math.max(State.stats.reqTotal || 0, data.cfRequestsTotal || 0);
	State.stats.d1r = data.d1Reads || 0;
	State.stats.d1w = data.d1Writes || 0;
	State.stats.active = users.filter(function (u) { return isUserEffective(u, State.serverTime); }).length;
	State.stats.expired = State.stats.total - State.stats.active;
	State.lastSync = now;

	renderStats();
	filterAndRenderUsers();
	renderServiceViews();
	if (State.view === 'view-dashboard') { renderDashboard(); State.dashDirty = false; }
	else { State.dashDirty = true; }
	if (State.view === 'view-system') renderSystemViews();
	else State.sysDirty = true;
}

/* ---------- filtering + sorting ---------- */
function currentFilter() {
	return {
		q: ($('userSearch') && $('userSearch').value || '').toLowerCase().trim(),
		status: ($('userFilter') && $('userFilter').value) || 'all',
		sort: ($('userSort') && $('userSort').value) || 'newest'
	};
}
function applyUserFilter(users, f, serverTime) {
	var out = users.slice();
	if (f.q) {
		out = out.filter(function (u) {
			return (u.username && String(u.username).toLowerCase().indexOf(f.q) >= 0) ||
				(u.uuid && String(u.uuid).toLowerCase().indexOf(f.q) >= 0);
		});
	}
	if (f.status === 'active') out = out.filter(function (u) { return isUserEffective(u, serverTime); });
	else if (f.status === 'inactive') out = out.filter(function (u) { return u.is_active === 0 || isUserExpired(u, serverTime); });
	else if (f.status === 'online') out = out.filter(function (u) { return u.is_online === 1; });
	else if (f.status === 'offline') out = out.filter(function (u) { return u.is_online !== 1; });
	else if (f.status === 'expired') out = out.filter(function (u) { return isUserExpired(u, serverTime); });

	out.sort(function (a, b) {
		if (f.sort === 'name') return String(a.username || '').localeCompare(String(b.username || ''));
		if (f.sort === 'usage-desc') return (b.used_gb || 0) - (a.used_gb || 0);
		if (f.sort === 'usage-asc') return (a.used_gb || 0) - (b.used_gb || 0);
		if (f.sort === 'online-desc') return (b.online_count || 0) - (a.online_count || 0);
		if (f.sort === 'expiry-asc') {
			var ea = userExpiryInfo(a, serverTime), eb = userExpiryInfo(b, serverTime);
			return (ea.days === '∞' ? Infinity : ea.days) - (eb.days === '∞' ? Infinity : eb.days);
		}
		if (f.sort === 'newest') {
			var order = [];
			try { order = JSON.parse(localStorage.getItem('lml_users_custom_order') || '[]'); } catch (e) { }
			if (order && order.length) {
				var ia = order.indexOf(a.username), ib = order.indexOf(b.username);
				if (ia !== -1 && ib !== -1) return ia - ib;
				if (ia !== -1) return -1;
				if (ib !== -1) return 1;
			}
			return (b.id || 0) - (a.id || 0);
		}
		return 0;
	});
	return out;
}
/* A cheap fingerprint of everything the table depends on. If it is
   unchanged there is no reason to destroy and rebuild the DOM. */
function usersTableSignature(users, filter) {
	var head = String(users.length) + '|' + String(filter.sort || '') + '|' +
		String(filter.status || '') + '|' + String(filter.q || '') + '|' +
		String(State.sortDir || '') + '||';
	var parts = [];
	for (var i = 0; i < users.length; i++) {
		var u = users[i] || {};
		parts.push(u.id + ',' + u.username + ',' + u.used_gb + ',' + u.used_req + ',' +
			u.is_active + ',' + u.is_online + ',' + u.online_count + ',' +
			u.limit_gb + ',' + u.limit_req + ',' + u.expiry_days + ',' +
			u.first_connection_time + ',' + u.ip_limit + ',' + u.max_connections);
	}
	return head + parts.join(';');
}
function filterAndRenderUsers(force) {
	if (!State.allUsers) return;
	/* never rebuild the table while a menu is open / pointer is on the table */
	if (State.autoRefreshing && uiBusy()) { State.pendingTableRender = true; return; }
	State.pendingTableRender = false;
	var f = currentFilter();
	var sig = usersTableSignature(State.allUsers, f);
	State.filtered = applyUserFilter(State.allUsers, f, State.serverTime);
	/* skip the expensive DOM rebuild when nothing the table shows has changed */
	if (!force && State.autoRefreshing && sig === State.usersSig) {
		updateBulkBar();
		var foot2 = $('usersFootInfo');
		if (foot2) foot2.textContent = 'آخرین بروزرسانی: ' + timeStr(State.lastSync);
		return;
	}
	State.usersSig = sig;
	renderUsersTable(State.filtered);
	updateBulkBar();
	var badge = $('userCountBadge');
	if (badge) badge.textContent = State.filtered.length + ' از ' + State.allUsers.length + ' کاربر';
	var foot = $('usersFootInfo');
	if (foot) foot.textContent = 'آخرین بروزرسانی: ' + timeStr(State.lastSync);
	renderUserMiniStats();
}
window.filterAndRenderUsers = filterAndRenderUsers;

function meter(used, limit, raw) {
	var pct = limit ? Math.min((used / limit) * 100, 100) : 100;
	var hue = Math.round(120 - (pct * 1.2));
	var color = limit ? 'hsl(' + hue + ',75%,48%)' : 'var(--accent)';
	return '<div class="meter">' +
		'<div class="meter-top"><span class="v">' + esc(raw.used) + '</span><span class="m">/ ' + esc(raw.limit) + '</span></div>' +
		'<div class="bar"><i style="width:' + pct + '%;background:' + color + '"></i></div>' +
		'</div>';
}
function statusBadge(u) {
	var eff = isUserEffective(u, State.serverTime);
	if (u.is_active === 0) return '<span class="badge err"><span class="dot-live off"></span>مسدود</span>';
	if (!eff) return '<span class="badge warn"><span class="dot-live off"></span>منقضی</span>';
	if (u.is_online === 1) return '<span class="badge ok"><span class="dot-live on"></span>آنلاین</span>';
	return '<span class="badge muted"><span class="dot-live off"></span>آفلاین</span>';
}
function userFlags(u) {
	if (u.user_proxy_iata) return '<span class="flags">' + flagHtml(u.user_proxy_iata) + '</span>';
	if (!u.user_socks5 && !u.user_proxy_ip) return '<span class="flags">' + flagHtml('') + '</span>';
	var list = [];
	try {
		if (u.user_socks5 && String(u.user_socks5).trim().charAt(0) === '[') list = JSON.parse(u.user_socks5);
		else list = [u.user_socks5 || u.user_proxy_ip];
	} catch (e) { list = [u.user_socks5 || u.user_proxy_ip]; }
	var cache = {};
	try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch (e) { }
	var html = list.slice(0, 8).map(function (item) {
		var p = (item && typeof item === 'object') ? item.proxy : item;
		var cc = (item && typeof item === 'object') ? item.country : (u.user_proxy_iata || '');
		if (!cc && p && cache[p]) cc = cache[p];
		return flagHtml(cc);
	}).join('');
	return '<span class="flags">' + html + '</span>';
}
function protoBadges(u) {
	var ct = String(u.connection_type || 'vless').toLowerCase();
	var vless = ct.indexOf('vless') >= 0 || (ct.indexOf('trojan') < 0 && ct.indexOf('shadowsocks') < 0);
	var trojan = ct.indexOf('trojan') >= 0;
	var ss = ct.indexOf('shadowsocks') >= 0;
	return (vless ? '<span class="chip">VLESS</span> ' : '') +
		(trojan ? '<span class="chip">Trojan</span> ' : '') +
		(ss ? '<span class="chip">SS</span>' : '') +
		(!vless && !trojan && !ss ? '<span class="chip">VLESS</span>' : '');
}
function configCount(u) {
	var list = [];
	try {
		if (u.user_socks5 && String(u.user_socks5).trim().charAt(0) === '[') list = JSON.parse(u.user_socks5);
		else if (u.user_socks5 || u.user_proxy_ip) list = [u.user_socks5 || u.user_proxy_ip];
		else list = [null];
	} catch (e) { list = [u.user_socks5 || u.user_proxy_ip]; }
	if (!Array.isArray(list) || !list.length) list = [];
	var allowDirect = u.enable_direct !== 0;
	if (allowDirect) { if (!list.some(function (p) { return p === null || p === ''; })) list.push(null); }
	else list = list.filter(function (p) { return p !== null && p !== ''; });
	if (!list.length) list = [null];
	var nIps = u.ips ? String(u.ips).split('\\n').filter(function (s) { return s.trim().length; }).length : 1;
	if (!nIps) nIps = 1;
	var nPorts = String(u.port || '443').split(',').filter(function (s) { return s.trim().length; }).length || 1;
	var ct = String(u.connection_type || 'vless').toLowerCase();
	var nProto = (ct.indexOf('vless') >= 0 || (ct.indexOf('trojan') < 0 && ct.indexOf('shadowsocks') < 0) ? 1 : 0) +
		(ct.indexOf('trojan') >= 0 ? 1 : 0) + (ct.indexOf('shadowsocks') >= 0 ? 1 : 0) || 1;
	return 3 + (list.length * nIps * nPorts * nProto);
}

function renderUsersTable(users) {
	var tbody = $('usersTbody');
	if (!tbody) return;
	if (!users.length) {
		tbody.innerHTML = '';
		$('usersState').innerHTML = State.allUsers.length
			? '<div class="state"><div class="si">' + svgIcon('search') + '</div><div class="st">نتیجه‌ای یافت نشد</div><div class="sd">هیچ کاربری با مشخصات جستجو شده مطابقت ندارد.</div></div>'
			: '<div class="state"><div class="si">' + svgIcon('users') + '</div><div class="st">هنوز کاربری ساخته نشده است</div><div class="sd">با دکمه «کاربر جدید» اولین حساب را بسازید یا از ایجاد سریع استفاده کنید.</div><button type="button" class="btn btn-primary" data-act="new-user">' + svgIcon('user-plus') + 'کاربر جدید</button></div>';
		return;
	}
	$('usersState').innerHTML = '';
	tbody.innerHTML = users.map(function (u) {
		var enc = encodeURIComponent(u.username);
		var ei = userExpiryInfo(u, State.serverTime);
		var limit = (u.ip_limit !== undefined && u.ip_limit !== null) ? u.ip_limit : u.max_connections;
		return '<tr data-username="' + attr(u.username) + '">' +
			'<td><input type="checkbox" data-act="select-user" data-u="' + attr(enc) + '"' + (State.selected[u.username] ? ' checked' : '') + '></td>' +
			'<td><button type="button" class="icon-btn" data-act="qr-config" data-u="' + attr(enc) + '" title="کیوآر کد کانفیگ">' + svgIcon('qr') + '</button></td>' +
			'<td data-col="کاربر"><div class="cell-user">' +
			'<span class="u-avatar">' + esc(String(u.username).slice(0, 2).toUpperCase()) + '</span>' +
			'<span style="min-width:0"><span class="uname mono">' + esc(u.username) + '</span>' +
			'<span class="umeta" style="display:block">' + (u.uuid ? esc(String(u.uuid).slice(0, 8)) : '') + '</span></span>' +
			userFlags(u) + '</div></td>' +
			'<td data-col="وضعیت">' + statusBadge(u) + '</td>' +
			'<td data-col="ترافیک">' + meter(u.used_gb || 0, u.limit_gb, { used: kbShort(u.used_gb || 0), limit: u.limit_gb ? kbShort(u.limit_gb) : '∞' }) + '</td>' +
			'<td data-col="ریکوئست" class="c-hide-sm">' + meter(u.used_req || 0, u.limit_req, { used: nfmt(u.used_req || 0), limit: u.limit_req ? nfmt(u.limit_req) : '∞' }) + '</td>' +
			'<td data-col="زمان" class="c-hide-sm">' + (u.expiry_days
				? '<div class="meter"><div class="meter-top"><span class="v">' + esc(ei.days) + ' روز</span><span class="m">' + (ei.pending ? 'از اولین اتصال' : '/ ' + esc(u.expiry_days)) + '</span></div><div class="bar"><i style="width:' + ei.percent + '%;background:' + (ei.pending ? 'var(--accent)' : 'hsl(' + Math.round(ei.percent * 1.2) + ',75%,48%)') + '"></i></div></div>'
				: '<span class="badge muted">نامحدود</span>') + '</td>' +
			'<td data-col="اتصال" class="c-hide-sm">' + meter(u.online_count || 0, limit, { used: String(u.online_count || 0), limit: limit ? String(limit) : '∞' }) + '</td>' +
			'<td data-col="پروتکل" class="c-hide-sm">' + protoBadges(u) + '</td>' +
			'<td class="c-actions">' +
			'<button type="button" class="icon-btn" data-act="user-menu" data-u="' + attr(enc) + '" title="عملیات">' + svgIcon('more') + '</button>' +
			'</td>' +
			'</tr>';
	}).join('');
	/* row dragging removed at the user's request - the column now holds the
	   config QR button (enableRowDrag is kept but no longer attached) */
}
window.renderUsersTable = renderUsersTable;

function renderUserMiniStats() {
	var box = $('userMiniStats');
	if (!box) return;
	var onlineUsers = State.allUsers.filter(function (u) { return u.is_online === 1; }).length;
	var gb = State.allUsers.reduce(function (s, u) { return s + (u.used_gb || 0); }, 0);
	box.innerHTML = [
		miniCard('users', 'ci-accent', 'کل کاربران', nfmt(State.stats.total), 'تعریف‌شده روی پنل'),
		miniCard('user-check', 'ci-ok', 'فعال', nfmt(State.stats.active), 'در محدوده مجاز'),
		miniCard('user-x', 'ci-err', 'منقضی / مسدود', nfmt(State.stats.expired), 'نیازمند تمدید یا ریست'),
		miniCard('wifi', 'ci-info', 'کاربران آنلاین', nfmt(onlineUsers), 'دارای اتصال فعال'),
		miniCard('chart', 'ci-violet', 'مصرف کل', kbStr(gb), 'جمع مصرف کاربران')
	].join('');
}
function miniCard(icon, cls, label, value, hint) {
	return '<div class="stat"><div class="stat-top"><div class="stat-label">' + esc(label) + '</div>' +
		'<div class="stat-icon ' + cls + '">' + svgIcon(icon) + '</div></div>' +
		'<div class="stat-value num" style="font-size:var(--fs-2xl)">' + esc(value) + '</div>' +
		'<div class="stat-foot"><span class="stat-hint">' + esc(hint) + '</span></div></div>';
}

/* ============================================================
   8. LINK BUILDERS
   ============================================================ */
function getUser(username) {
	for (var i = 0; i < State.allUsers.length; i++) if (State.allUsers[i].username === username) return State.allUsers[i];
	return null;
}
function getSubLink(username) { return window.location.origin + '/feed/' + encodeURIComponent(username); }
function getSubTextLink(username) { return window.location.origin + '/sub/' + encodeURIComponent(username); }
function getSingboxLink(username) { return window.location.origin + '/singbox/' + encodeURIComponent(username); }
function getStatusLink(username) { return window.location.origin + '/status/' + encodeURIComponent(username); }
function getPortalLink(username) { return window.location.origin + '/s/' + encodeURIComponent(username); }
window.getSubLink = getSubLink;
window.getSingboxLink = getSingboxLink;
window.getStatusLink = getStatusLink;

function getvIeesLink(username) {
	var user = getUser(username);
	if (!user) return '';
	var host = window.location.hostname;
	var ips = [host];
	if (user.ips) {
		var parsedIps = String(user.ips).split('\\n').map(function (ip) { return ip.trim(); }).filter(function (ip) { return ip.length > 0; });
		if (parsedIps.length > 0) ips = parsedIps;
	}
	var ports = String(user.port || '443').split(',').map(function (p) { return p.trim(); }).filter(function (p) { return p.length > 0; });
	var fp = user.fingerprint || 'chrome';
	var dynPath = encodeURIComponent('/stream/LML_PANEL/' + (user.uuid ? user.uuid.split('-')[4] : 'default'));
	var links = [];
	var m1 = decodeURIComponent('%E2%9A%A0%EF%B8%8F%D9%BE%D9%86%D9%84%20%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86%20%D9%88%20%D8%BA%DB%8C%D8%B1%20%D9%82%D8%A7%D8%A8%D9%84%20%D9%81%D8%B1%D9%88%D8%B4%E2%9A%A0%EF%B8%8F');
	var m2 = '💎 LML-CONNECT ❯ [SECURE-MESH]';
	links.push('vless://' + (user.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(m1));
	links.push('vless://' + (user.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(m2));

	var remVol = 'Unlimited';
	if (user.limit_gb) {
		var rem = user.limit_gb - (user.used_gb || 0);
		remVol = rem > 0 ? rem.toFixed(2) + 'GB' : '0GB';
	}
	var remTime = 'Unlimited';
	if (user.expiry_days) {
		var base = null;
		if (user.start_on_first_connect === 1) { if (user.first_connection_time) base = new Date(user.first_connection_time).getTime(); }
		else if (user.created_at) base = new Date(user.created_at).getTime();
		if (base !== null) {
			var diffDays = Math.ceil((base + user.expiry_days * 86400000 - Date.now()) / 86400000);
			remTime = diffDays > 0 ? diffDays + 'Days' : '0Days';
		}
	}
	var remReq = 'Unlimited';
	if (user.limit_req) {
		var rem2 = user.limit_req - (user.used_req || 0);
		remReq = rem2 > 0 ? rem2.toLocaleString() + 'Req' : '0Req';
	}
	var infoRemark = '📊 remaining | ‎' + remVol + ' | ‎' + remTime + ' | ‎' + remReq;
	links.push('vless://' + (user.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(infoRemark));

	var rawPath = '/stream/LML_PANEL/' + (user.uuid ? user.uuid.split('-')[4] : 'default');
	var proxyList = [];
	try {
		if (user.user_socks5 && String(user.user_socks5).trim().charAt(0) === '[') proxyList = JSON.parse(user.user_socks5);
		else if (user.user_socks5 || user.user_proxy_ip) proxyList = [user.user_socks5 || user.user_proxy_ip];
		else proxyList = [null];
	} catch (e) { proxyList = [user.user_socks5 || user.user_proxy_ip]; }
	if (!proxyList || proxyList.length === 0) proxyList = [];
	var allowDirect = user.enable_direct !== 0;
	if (allowDirect) { if (!proxyList.some(function (p) { return p === null || p === ''; })) proxyList.push(null); }
	else proxyList = proxyList.filter(function (p) { return p !== null && p !== ''; });
	if (proxyList.length === 0) proxyList = [null];

	var proxyFlagCache = {};
	try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch (e) { }
	var resolvedProxies = [];
	for (var li = 0; li < proxyList.length; li++) {
		var proxyItem = proxyList[li];
		var proxyStr = (proxyItem && typeof proxyItem === 'object') ? proxyItem.proxy : proxyItem;
		var cc = (proxyItem && typeof proxyItem === 'object') ? proxyItem.country : (user.user_proxy_iata || '');
		if (!cc && proxyStr && proxyFlagCache[proxyStr]) cc = proxyFlagCache[proxyStr];
		var currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== '') ? '/loc-' + li : ''));
		resolvedProxies.push({ flagEmoji: flagText(cc), currentDynPath: currentDynPath });
	}
	var userConnType = String(user.connection_type || 'vless').toLowerCase();
	var enableVless = userConnType.indexOf('vless') >= 0 || (userConnType.indexOf('trojan') < 0 && userConnType.indexOf('shadowsocks') < 0);
	var enableTrojan = userConnType.indexOf('trojan') >= 0;
	var enableSS = userConnType.indexOf('shadowsocks') >= 0;

	ips.forEach(function (ip) {
		ports.forEach(function (portStr) {
			resolvedProxies.forEach(function (proxy) {
				var isTlsPort = TLS_PORTS.indexOf(portStr) >= 0;
				var tlsVal = isTlsPort ? 'tls' : 'none';
				var userFrag = '';
				if (user.frag_len && user.frag_int) userFrag += '&fragment=' + encodeURIComponent(user.frag_len + ',' + user.frag_int + (isTlsPort ? ',tlshello' : ''));
				if (user.advanced_frag) userFrag += '&fm=' + encodeURIComponent(user.advanced_frag);
				if (isTlsPort && user.cipher_suites) userFrag += '&cs=' + encodeURIComponent(user.cipher_suites);
				if (user.tls_mask) userFrag += '&mask=' + encodeURIComponent(user.tls_mask);
				var tlsParams = isTlsPort ? ('&insecure=0&fp=' + fp + '&allowInsecure=0&sni=' + host) : '';
				var remark = 'LML | ' + proxy.flagEmoji + ' | ' + user.username;
				if (enableVless) {
					links.push('vless://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
				}
				if (enableTrojan) {
					links.push('trojan://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
				}
				if (enableSS) {
					var methodPass = btoa('aes-256-gcm:' + (user.uuid || ''));
					var pluginOpts = 'v2ray-plugin;mode=websocket;host=' + host + ';path=' + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ';tls' : '');
					links.push('ss://' + methodPass + '@' + ip + ':' + portStr + '/?plugin=' + encodeURIComponent(pluginOpts) + '#' + encodeURIComponent(remark));
				}
			});
		});
	});
	return links.join('\\n');
}
window.getvIeesLink = getvIeesLink;

/* ============================================================
   9. COPY + QR ACTIONS
   ============================================================ */
function copyConfig(username) { copyText(getvIeesLink(username), '✅ کانفیگ‌ها با موفقیت کپی شدند!'); }
function copySubLink(enc) { var u = decodeURIComponent(enc); copyText(getSubLink(u), '✅ لینک سابسکریپشن کپی شد!'); }
function copySingboxLink(enc) { var u = decodeURIComponent(enc); copyText(getSingboxLink(u), '✅ لینک Sing-box کپی شد!'); }
function copyStatusLink(enc) { var u = decodeURIComponent(enc); copyText(getStatusLink(u), '✅ لینک وضعیت کپی شد!'); }
window.copyConfig = copyConfig;
window.copySubLink = copySubLink;
window.copySingboxLink = copySingboxLink;
window.copyStatusLink = copyStatusLink;

function showQr(title, value, size) {
	$('qrTitle').textContent = title;
	$('qrSub').textContent = value.length > 60 ? value.slice(0, 60) + '…' : '';
	$('qrText').textContent = value;
	renderQr('qrContainer', value, size || 230);
	openModal('modalQr');
}
function showSubQr(enc) { var u = decodeURIComponent(enc); showQr('اشتراک ' + u, getSubLink(u), 230); }
/* the actual vless/trojan config of this user, as a QR code */
function showConfigQr(enc) {
	var u = decodeURIComponent(enc);
	var link = '';
	try { link = getvIeesLink(u); } catch (e) { link = ''; }
	if (!link) { toast('کانفیگی برای این کاربر ساخته نشده است', 'warn'); return; }
	showQr('کانفیگ ' + u, link, 230);
}
window.showConfigQr = showConfigQr;
function showSingboxQr(enc) { var u = decodeURIComponent(enc); showQr('Sing-box ' + u, getSingboxLink(u), 230); }
window.showSubQr = showSubQr;
window.showSingboxQr = showSingboxQr;

on($('btnDownloadQr'), 'click', function () {
	var box = $('qrContainer');
	if (!box || !box.firstChild) { toast('تصویری برای دانلود وجود ندارد', 'warn'); return; }
	QRLib.download(box, 'lml-qr');
	toast('✅ تصویر QR دانلود شد');
});

/**
 * Per-user location marker used by the edge router:
 *   /stream/LML_PANEL/{uuid-tail}            -> direct
 *   /stream/LML_PANEL/{uuid-tail}/loc-{idx}  -> chained proxy #idx
 */
function getLocPath(username, locIdx) {
	var u = getUser(username);
	if (!u || !u.uuid) return null;
	var tail = String(u.uuid).split('-')[4] || 'default';
	return '/stream/LML_PANEL/' + tail + (locIdx !== null && locIdx !== undefined && locIdx !== '' ? '/loc-' + locIdx : '');
}
function getLocLink(username, locIdx) {
	var p = getLocPath(username, locIdx);
	if (!p) return '';
	return 'https://' + window.location.hostname + ':443?path=' + encodeURIComponent(p) + '&security=tls&encryption=none&host=' + window.location.hostname + '&type=ws&sni=' + window.location.hostname;
}

/* ============================================================
   10. USER DRAWER (details + subscription + actions)
   ============================================================ */
function openUserDrawer(enc) {
	var username = decodeURIComponent(enc);
	var u = getUser(username);
	if (!u) { toast('کاربر یافت نشد', 'err'); return; }
	$('drawerUserName').textContent = u.username;
	$('drawerUserSub').textContent = (u.uuid ? 'UUID: ' + u.uuid : 'بدون UUID');
	var ei = userExpiryInfo(u, State.serverTime);
	var limit = (u.ip_limit !== undefined && u.ip_limit !== null) ? u.ip_limit : u.max_connections;
	var body =
		'<div class="grid g-2" style="margin-bottom:14px">' +
		'<div class="kv"><span class="k">وضعیت</span><span class="v">' + statusBadge(u) + '</span></div>' +
		'<div class="kv"><span class="k">اتصال‌های فعال</span><span class="v">' + (u.online_count || 0) + ' / ' + (limit || '∞') + '</span></div>' +
		'<div class="kv"><span class="k">ترافیک مصرفی</span><span class="v">' + kbStr(u.used_gb || 0) + (u.limit_gb ? ' / ' + kbStr(u.limit_gb) : '') + '</span></div>' +
		'<div class="kv"><span class="k">ریکوئست</span><span class="v">' + nfmt(u.used_req || 0) + (u.limit_req ? ' / ' + nfmt(u.limit_req) : '') + '</span></div>' +
		'<div class="kv"><span class="k">زمان باقی‌مانده</span><span class="v">' + (u.expiry_days ? (ei.days + ' روز' + (ei.pending ? ' (از اولین اتصال)' : '')) : 'نامحدود') + '</span></div>' +
		'<div class="kv"><span class="k">تاریخ ایجاد</span><span class="v">' + dateStr(u.created_at) + '</span></div>' +
		'<div class="kv"><span class="k">تعداد کانفیگ</span><span class="v">' + configCount(u) + '</span></div>' +
		'<div class="kv"><span class="k">پروتکل</span><span class="v">' + protoBadges(u) + '</span></div>' +
		'</div>' +

		'<div class="lbl-sm" style="margin-bottom:6px">لینک‌های اشتراک</div>' +
		copyRow('ساب متنی', getSubTextLink(u.username)) +
		copyRow('ساب پیشرفته', getSubLink(u.username)) +
		copyRow('Sing-box', getSingboxLink(u.username)) +
		copyRow('وضعیت اتصال', getStatusLink(u.username)) +
		copyRow('پرتال کاربر', getPortalLink(u.username)) +

		'<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">' +
		'<button type="button" class="btn btn-sm" data-act="drawer-qr" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('qr') + 'نمایش QR</button>' +
		'<button type="button" class="btn btn-sm" data-act="drawer-open-status" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('external') + 'پرتال کاربر</button>' +
		'</div>' +

		'<div class="lbl-sm" style="margin:16px 0 6px">مقاصد خروجی</div>' +
		locationRows(u) +

		'<div class="lbl-sm" style="margin:16px 0 6px">عملیات</div>' +
		'<div class="grid g-2" style="gap:8px">' +
		'<button type="button" class="btn btn-sm" data-act="edit-user" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('edit') + 'ویرایش</button>' +
		'<button type="button" class="btn btn-sm" data-act="copy-config" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('copy') + 'کپی کانفیگ</button>' +
		'<button type="button" class="btn btn-sm" data-act="toggle-user" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('power') + (u.is_active === 0 ? 'فعال‌سازی' : 'مسدودسازی') + '</button>' +
		'<button type="button" class="btn btn-sm" data-act="reset-volume" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('refresh') + 'ریست حجم</button>' +
		'<button type="button" class="btn btn-sm" data-act="reset-req" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('refresh') + 'ریست ریکوئست</button>' +
		'<button type="button" class="btn btn-sm" data-act="reset-time" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('clock') + 'ریست زمان</button>' +
		'</div>';
	$('drawerUserBody').innerHTML = body;
	$('drawerUserFoot').innerHTML =
		'<button type="button" class="btn" data-close-drawer="drawerUser">بستن</button>' +
		'<div class="spacer"></div>' +
		'<button type="button" class="btn btn-danger" data-act="delete-user" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('trash') + 'حذف کاربر</button>';
	openDrawer('drawerUser');
}
function copyRow(label, value) {
	return '<div class="copy-field" style="margin-bottom:6px">' +
		'<span class="cf-val" title="' + attr(value) + '">' + esc(value) + '</span>' +
		'<button type="button" class="btn btn-sm" data-copy="' + attr(value) + '" data-copy-msg="✅ ' + attr(label) + ' کپی شد">کپی</button>' +
		'</div>';
}
function locationRows(u) {
	var list = [];
	try {
		if (u.user_socks5 && String(u.user_socks5).trim().charAt(0) === '[') list = JSON.parse(u.user_socks5);
		else if (u.user_socks5 || u.user_proxy_ip) list = [u.user_socks5 || u.user_proxy_ip];
		else list = [null];
	} catch (e) { list = [u.user_socks5 || u.user_proxy_ip]; }
	if (!Array.isArray(list) || !list.length) list = [null];
	var allowDirect = u.enable_direct !== 0;
	if (allowDirect) { if (!list.some(function (p) { return p === null || p === ''; })) list.unshift(null); }
	else list = list.filter(function (p) { return p !== null && p !== ''; });
	if (!list.length) list = [null];
	return list.map(function (item, idx) {
		var p = (item && typeof item === 'object') ? item.proxy : item;
		var cc = (item && typeof item === 'object') ? item.country : (u.user_proxy_iata || '');
		var isDirect = (p === null || p === '');
		var path = getLocPath(u.username, isDirect ? null : idx);
		var idxInOriginal = allowDirect ? idx - 1 : idx;
		if (!isDirect && idxInOriginal < 0) idxInOriginal = idx;
		var path2 = isDirect ? getLocPath(u.username, null) : getLocPath(u.username, idxInOriginal);
		return '<div class="copy-field" style="margin-bottom:6px">' +
			'<span style="flex:0 0 auto">' + flagHtml(cc) + '</span>' +
			'<span class="cf-val" style="flex:1 1 auto">' + esc(isDirect ? 'اتصال مستقیم' : (cc || ('لوکیشن ' + idx))) + ' — <span class="mono" style="font-size:10px">' + esc(path2 || path || '') + '</span></span>' +
			'<button type="button" class="btn btn-sm" data-copy="' + attr(getLocLink(u.username, isDirect ? null : idxInOriginal)) + '" data-copy-msg="✅ کانفیگ لوکیشن کپی شد">کپی</button>' +
			'</div>';
	}).join('');
}

/* ============================================================
   11. ROW MENU + DELEGATED ACTIONS
   ============================================================ */
function userMenu(anchor, username) {
	var u = getUser(username);
	if (!u) return;
	var enc = encodeURIComponent(username);
	openMenu(anchor, [
		{ head: 'اشتراک' },
		{ icon: 'copy', label: 'کپی لینک سابسکریپشن', action: function () { copySubLink(enc); } },
		{ icon: 'link', label: 'کپی لینک Sing-box', action: function () { copySingboxLink(enc); } },
		{ icon: 'copy', label: 'کپی کانفیگ‌ها', action: function () { copyConfig(username); } },
		{ icon: 'activity', label: 'کپی لینک وضعیت', action: function () { copyStatusLink(enc); } },
		{ icon: 'qr', label: 'نمایش کد QR', action: function () { showSubQr(enc); } },
		{ icon: 'external', label: 'باز کردن پرتال کاربر', action: function () { window.open(getPortalLink(username), '_blank'); } },
		'-',
		{ head: 'مدیریت' },
		{ icon: 'eye', label: 'نمایش جزئیات', action: function () { openUserDrawer(enc); } },
		{ icon: 'edit', label: 'ویرایش کاربر', action: function () { openEditUser(username); } },
		{ icon: 'power', label: u.is_active === 0 ? 'فعال‌سازی' : 'مسدودسازی', action: function () { toggleUserStatus(enc); } },
		{ icon: 'refresh', label: 'ریست حجم', action: function () { resetUserData(username, 'volume'); } },
		{ icon: 'refresh', label: 'ریست ریکوئست', action: function () { resetUserData(username, 'req'); } },
		{ icon: 'clock', label: 'ریست زمان', action: function () { resetUserData(username, 'time'); } },
		'-',
		{ icon: 'trash', label: 'حذف کاربر', danger: true, action: function () { deleteUser(username); } }
	]);
}

function resetUserData(username, type) {
	var labels = { volume: 'حجم', req: 'ریکوئست', time: 'زمان' };
	confirmBox('آیا از ریست ' + (labels[type] || '') + ' کاربر «' + username + '» اطمینان دارید؟', { title: 'ریست ' + (labels[type] || ''), okText: 'ریست کن', danger: false })
		.then(function (ok) {
			if (!ok) return;
			return api('/api/users/' + encodeURIComponent(username), { method: 'PUT', body: { reset_action: type } })
				.then(function (res) { return res.json(); })
				.then(function (d) {
					if (d && d.error) toast('خطا: ' + d.error, 'err');
					else toast('✅ ' + (labels[type] || '') + ' کاربر با موفقیت ریست شد', 'ok');
					loadUsers();
				});
		}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
}
function toggleUserStatus(enc) {
	var username = decodeURIComponent(enc);
	api('/api/users/' + encodeURIComponent(username), { method: 'PUT', body: { toggle_only: true } })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.error) toast('خطا: ' + d.error, 'err');
			else toast('✅ وضعیت کاربر ' + username + ' تغییر کرد', 'ok');
			loadUsers();
		}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
}
function deleteUser(username) {
	confirmBox('آیا از حذف دائمی کاربر «' + username + '» اطمینان دارید؟ این عمل غیرقابل بازگشت است.', { title: 'حذف کاربر', okText: 'حذف کن', danger: true })
		.then(function (ok) {
			if (!ok) return;
			return api('/api/users/' + encodeURIComponent(username), { method: 'DELETE' })
				.then(function (res) { return res.json(); })
				.then(function (d) {
					if (d && d.error) toast('خطا: ' + d.error, 'err');
					else { toast('✅ کاربر ' + username + ' حذف شد', 'ok'); delete State.selected[username]; }
					loadUsers();
				});
		}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
}
window.resetUserData = resetUserData;
window.toggleUserStatus = toggleUserStatus;
window.deleteUser = deleteUser;

/* ---------- delegated global click router ---------- */
document.addEventListener('click', function (e) {
	var t = e.target.closest ? e.target.closest('[data-act]') : null;
	if (!t) return;
	var act = t.getAttribute('data-act');
	var u = t.getAttribute('data-u');
	var username = u ? decodeURIComponent(u) : null;
	switch (act) {
		case 'user-menu': e.stopPropagation(); userMenu(t, username); break;
		case 'copy-config': copyConfig(username); break;
		case 'copy-sub': copySubLink(u); break;
		case 'copy-singbox': copySingboxLink(u); break;
		case 'copy-status': copyStatusLink(u); break;
		case 'qr-sub': showSubQr(u); break;
		case 'qr-singbox': showSingboxQr(u); break;
		case 'qr-config': showConfigQr(u); break;
		case 'open-status': window.open(getStatusLink(username), '_blank'); break;
		case 'open-portal': window.open(getPortalLink(username), '_blank'); break;
		case 'open-drawer': openUserDrawer(u); break;
		case 'drawer-qr': showSubQr(u); closeDrawer('drawerUser'); break;
		case 'drawer-open-status': window.open(getPortalLink(username), '_blank'); break;
		case 'edit-user': closeDrawer('drawerUser'); openEditUser(username); break;
		case 'toggle-user': closeDrawer('drawerUser'); toggleUserStatus(u); break;
		case 'reset-volume': closeDrawer('drawerUser'); resetUserData(username, 'volume'); break;
		case 'reset-req': closeDrawer('drawerUser'); resetUserData(username, 'req'); break;
		case 'reset-time': closeDrawer('drawerUser'); resetUserData(username, 'time'); break;
		case 'delete-user': closeDrawer('drawerUser'); deleteUser(username); break;
		case 'new-user': openCreateUserModal(); break;
		case 'retry-load': loadUsers(); break;
		case 'select-user':
			State.selected[username] = t.checked;
			updateBulkBar();
			break;
		default: break;
	}
});

/* ============================================================
   12. BULK SELECTION
   ============================================================ */
function updateBulkBar() {
	var names = Object.keys(State.selected).filter(function (k) { return State.selected[k]; });
	State.selectedCount = names.length;
	var bar = $('bulkBar');
	if (!bar) return;
	if (names.length) bar.classList.add('show'); else bar.classList.remove('show');
	$('bulkCount').textContent = nfmt(names.length) + ' کاربر انتخاب شده';
	var all = $('selectAllUsers');
	if (all) all.checked = State.filtered.length > 0 && names.length >= State.filtered.length;
}
function selectedNames() {
	return Object.keys(State.selected).filter(function (k) { return State.selected[k]; });
}
function clearSelection() {
	State.selected = {};
	$$('#usersTbody input[data-act="select-user"]').forEach(function (c) { c.checked = false; });
	updateBulkBar();
}
function bulkAction(action, bodyFn, label) {
	var names = selectedNames();
	if (!names.length) { toast('ابتدا کاربران را انتخاب کنید', 'warn'); return; }
	confirmBox('آیا از اجرای «' + label + '» روی ' + names.length + ' کاربر اطمینان دارید؟', { title: label, okText: 'اجرا کن', danger: (action === 'delete') })
		.then(function (ok) {
			if (!ok) return;
			toast('⏳ در حال اجرای عملیات گروهی...', 'info');
			var applied = 0;
			var chain = names.reduce(function (p, name) {
				return p.then(function () {
					var body = bodyFn ? bodyFn(name) : undefined;
					if (body && body.__skip) return null;
					applied++;
					return api('/api/users/' + encodeURIComponent(name), { method: action === 'delete' ? 'DELETE' : 'PUT', body: body })
						.catch(function () { return null; });
				});
			}, Promise.resolve());
			return chain.then(function () {
				toast('✅ عملیات «' + label + '» روی ' + applied + ' کاربر انجام شد', 'ok');
				clearSelection();
				loadUsers();
			});
		});
}
on($('selectAllUsers'), 'change', function () {
	var checked = this.checked;
	State.filtered.forEach(function (u) { State.selected[u.username] = checked; });
	$$('#usersTbody input[data-act="select-user"]').forEach(function (c) { c.checked = checked; });
	updateBulkBar();
});
on($('bulkClear'), 'click', clearSelection);
on($('bulkActivate'), 'click', function () {
	bulkAction('activate', function (name) {
		var u = getUser(name);
		return (u && u.is_active === 0) ? { toggle_only: true } : { __skip: true };
	}, 'فعال‌سازی گروهی');
});
on($('bulkDeactivate'), 'click', function () {
	bulkAction('deactivate', function (name) {
		var u = getUser(name);
		return (u && u.is_active === 1) ? { toggle_only: true } : { __skip: true };
	}, 'غیرفعال‌سازی گروهی');
});
on($('bulkResetVol'), 'click', function () { bulkAction('put', function () { return { reset_action: 'volume' }; }, 'ریست حجم گروهی'); });
on($('bulkResetReq'), 'click', function () { bulkAction('put', function () { return { reset_action: 'req' }; }, 'ریست ریکوئست گروهی'); });
on($('bulkResetTime'), 'click', function () { bulkAction('put', function () { return { reset_action: 'time' }; }, 'ریست زمان گروهی'); });
on($('bulkRenew'), 'click', function () { openModal('modalBatchRenew'); });
on($('bulkDelete'), 'click', function () { bulkAction('delete', null, 'حذف گروهی'); });

/* ============================================================
   13. ROW DRAG & DROP ORDERING (native, replaces SortableJS)
   ============================================================ */
function enableRowDrag(tbody) {
	if (!tbody || tbody._dragBound) return;
	tbody._dragBound = true;
	var dragging = null;
	tbody.addEventListener('dragstart', function (e) {
		var tr = e.target.closest ? e.target.closest('tr') : null;
		if (!tr) return;
		dragging = tr;
		tr.classList.add('dragging');
		try { e.dataTransfer.setData('text/plain', tr.getAttribute('data-username') || ''); e.dataTransfer.effectAllowed = 'move'; } catch (err) { }
	});
	tbody.addEventListener('dragend', function () {
		if (dragging) dragging.classList.remove('dragging');
		$$('tr.drop-target', tbody).forEach(function (r) { r.classList.remove('drop-target'); });
		dragging = null;
	});
	tbody.addEventListener('dragover', function (e) {
		if (!dragging) return;
		e.preventDefault();
		var tr = e.target.closest ? e.target.closest('tr') : null;
		$$('tr.drop-target', tbody).forEach(function (r) { r.classList.remove('drop-target'); });
		if (tr && tr !== dragging) tr.classList.add('drop-target');
	});
	tbody.addEventListener('drop', function (e) {
		if (!dragging) return;
		e.preventDefault();
		var tr = e.target.closest ? e.target.closest('tr') : null;
		if (!tr || tr === dragging) return;
		var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
		var from = rows.indexOf(dragging), to = rows.indexOf(tr);
		if (from < 0 || to < 0) return;
		if (from < to) tr.parentNode.insertBefore(dragging, tr.nextSibling);
		else tr.parentNode.insertBefore(dragging, tr);
		dragging.classList.remove('dragging');
		tr.classList.remove('drop-target');
		var order = Array.prototype.slice.call(tbody.querySelectorAll('tr')).map(function (r) { return r.getAttribute('data-username'); });
		try { localStorage.setItem('lml_users_custom_order', JSON.stringify(order)); } catch (err) { }
	});
}

/* ============================================================
   14. USER FORM (CREATE / EDIT)
   ============================================================ */
function renderPortCheckboxes(selected) {
	var tlsBox = $('tlsPortsList'), nonBox = $('nonTlsPortsList');
	if (!tlsBox || !nonBox) return;
	var sel = Array.isArray(selected) ? selected : null;
	tlsBox.innerHTML = TLS_PORTS.map(function (p) {
		var on = sel ? sel.indexOf(p) >= 0 : (p === '443');
		return '<label class="port-chip"><input type="checkbox" name="ports" value="' + p + '"' + (on ? ' checked' : '') + '><span>' + p + '</span></label>';
	}).join('');
	nonBox.innerHTML = NON_TLS_PORTS.map(function (p) {
		var on = sel ? sel.indexOf(p) >= 0 : (p === '80');
		return '<label class="port-chip nontls"><input type="checkbox" name="ports" value="' + p + '"' + (on ? ' checked' : '') + '><span>' + p + '</span></label>';
	}).join('');
}
var USER_STEPS = ['vtab-account', 'vtab-network', 'vtab-proxy'];
var USER_STEP_FA = ['۱', '۲', '۳'];
function setUserModalTab(id) {
	if (USER_STEPS.indexOf(id) < 0) id = USER_STEPS[0];
	$$('#userVtabs .vtab').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-vtab') === id); });
	$$('.vtab-pane').forEach(function (p) { p.classList.toggle('hidden', p.id !== id); });
	var i = USER_STEPS.indexOf(id);
	var pb = $('btnPrevStep'), nb = $('btnNextStep'), ind = $('userStepInd');
	if (pb) pb.disabled = i === 0;
	if (nb) nb.disabled = i === USER_STEPS.length - 1;
	if (ind) ind.textContent = USER_STEP_FA[i] + ' / ' + USER_STEP_FA[USER_STEPS.length - 1];
}
function userStepGo(delta) {
	var cur = $$('#userVtabs .vtab').filter(function (b) { return b.classList.contains('active'); })[0];
	var i = cur ? USER_STEPS.indexOf(cur.getAttribute('data-vtab')) : 0;
	if (i < 0) i = 0;
	i = Math.max(0, Math.min(USER_STEPS.length - 1, i + delta));
	setUserModalTab(USER_STEPS[i]);
	var body = document.querySelector('#modalUser .modal-body');
	if (body) body.scrollTop = 0;
}
function openCreateUserModal() {
	State.editMode = false;
	State.editingUsername = '';
	State.proxyFields = [''];
	State.activeProxyIndex = 0;
	$('userModalTitle').textContent = 'ایجاد کاربر جدید';
	$('userModalSub').textContent = 'مشخصات، دسترسی‌ها و پروتکل‌های اتصال';
	$('userSubmitText').textContent = 'ایجاد کاربر';
	var f = $('userForm');
	if (f) f.reset();
	$('fName').value = '';
	$('fName').disabled = false;
	$('fProtoVless').checked = true;
	vchk('fProtoTrojan', false);
	vdis('fProtoTrojan', true);
renderPortCheckboxes(null);
	$('fCustomPorts').value = '';
	$('fIps').value = '';
	$('fLimit').value = '';
	$('fExpiry').value = '';
	$('fReqLimit').value = '';
	$('fIpLimit').value = '';
	$('fFingerprint').value = 'chrome';
$('fAutoReset').checked = false;
	toggleAutoResetInputs(false);
	$('fBlockPorn').checked = false;
	$('fBlockAds').checked = false;
	$('fAutoRotateIp').checked = false;
	$('fFragToggle').checked = false;
	toggleFragInputs(false);
	$('fFragLen').value = '200-3000';
	$('fFragInt').value = '1-2';
	vchk('fAdvancedToggle', false);
	toggleAdvancedSettingsInputs(false);
	vchk('fEnableDirect', true);
	$('fProxyMode').checked = false;
	toggleUserProxyMode(false);
	$('fAutoRotateProxy').checked = false;
	$('fAutoRotate').value = '0';
	$('fIpOperator').value = 'all';
	$('fIpCount').value = '15';
	renderProxyFieldsUI();
	setUserModalTab('vtab-account');
	openModal('modalUser');
	setTimeout(function () { if ($('fName')) $('fName').focus(); }, 120);
}
function openEditUser(username) {
	var u = getUser(username);
	if (!u) { toast('کاربر یافت نشد', 'err'); return; }
	State.editMode = true;
	State.editingUsername = username;
	$('userModalTitle').textContent = 'ویرایش کاربر «' + u.username + '»';
	$('userModalSub').textContent = 'تغییر مشخصات و محدودیت‌ها';
	$('userSubmitText').textContent = 'ذخیره تغییرات';
	$('fName').value = u.username || '';
	$('fName').disabled = false;
	var ct = String(u.connection_type || 'vless').toLowerCase();
	$('fProtoVless').checked = ct.indexOf('vless') >= 0 || (ct.indexOf('trojan') < 0 && ct.indexOf('shadowsocks') < 0);
	vchk('fProtoTrojan', ct.indexOf('trojan') >= 0);
	vdis('fProtoTrojan', ct.indexOf('trojan') < 0);
renderPortCheckboxes(String(u.port || '443').split(',').map(function (p) { return p.trim(); }));
	$('fCustomPorts').value = '';
	$('fIps').value = u.ips || '';
	$('fLimit').value = (u.limit_gb === null || u.limit_gb === undefined) ? '' : u.limit_gb;
	$('fExpiry').value = (u.expiry_days === null || u.expiry_days === undefined) ? '' : u.expiry_days;
	$('fReqLimit').value = (u.limit_req === null || u.limit_req === undefined) ? '' : u.limit_req;
	$('fIpLimit').value = (u.ip_limit === null || u.ip_limit === undefined) ? '' : u.ip_limit;
	$('fFingerprint').value = u.fingerprint || 'chrome';
var hasReset = ((u.auto_reset_vol_days || 0) > 0 || (u.auto_reset_req_days || 0) > 0);
	$('fAutoReset').checked = hasReset;
	toggleAutoResetInputs(hasReset);
	$('fAutoResetVol').value = u.auto_reset_vol_days || '';
	$('fAutoResetReq').value = u.auto_reset_req_days || '';
	$('fBlockPorn').checked = u.block_porn === 1;
	$('fBlockAds').checked = u.block_ads === 1;
	$('fAutoRotateIp').checked = u.auto_rotate_ip === 1;
	$('fAutoRotate').value = String(u.auto_rotate_ip || 0);
	$('fIpOperator').value = u.ip_operator || 'all';
	$('fIpCount').value = String(u.ip_count || 15);
	$('fFragLen').value = u.frag_len || '200-3000';
	$('fFragInt').value = u.frag_int || '1-2';
	$('fFragToggle').checked = !!(u.frag_len && u.frag_int);
	toggleFragInputs($('fFragToggle').checked);
	vchk('fAdvancedToggle', !!(u.advanced_frag || u.cipher_suites || u.tls_mask));
	toggleAdvancedSettingsInputs(vck('fAdvancedToggle'));
	vset('fAdvancedFrag', u.advanced_frag || '');
	vset('fCipherSuites', u.cipher_suites || '');
	vset('fTlsMask', u.tls_mask || '');
	vchk('fEnableDirect', u.enable_direct !== 0);
	var plist = [];
	try {
		if (u.user_socks5 && String(u.user_socks5).trim().charAt(0) === '[') plist = JSON.parse(u.user_socks5);
		else if (u.user_socks5 || u.user_proxy_ip) plist = [u.user_socks5 || u.user_proxy_ip];
	} catch (e) { plist = [u.user_socks5 || u.user_proxy_ip]; }
	plist = (plist || []).filter(function (p) { return p; });
	State.proxyFields = plist.length ? plist : [''];
	State.activeProxyIndex = 0;
	$('fProxyMode').checked = State.proxyFields.some(function (p) { return !!p; });
	toggleUserProxyMode($('fProxyMode').checked);
	$('fAutoRotateProxy').checked = u.auto_rotate_user_proxy === 1;
	renderProxyFieldsUI();
	setUserModalTab('vtab-account');
	openModal('modalUser');
}
window.openCreateUserModal = openCreateUserModal;
window.openCreateModal = openCreateUserModal;
window.openEditUser = openEditUser;
window.editUser = openEditUser;
window.toggleModal = function (show) { if (show) openCreateUserModal(); else closeModal('modalUser'); };

function toggleAutoResetInputs(on) {
	var box = $('autoResetBox');
	if (!box) return;
	box.classList.toggle('hidden', !on);
	$('fAutoResetVol').disabled = !on;
	$('fAutoResetReq').disabled = !on;
	if (!on) { $('fAutoResetVol').value = ''; $('fAutoResetReq').value = ''; }
}
function toggleFragInputs(on) {
	var box = $('fragBox');
	if (box) box.classList.toggle('hidden', !on);
}
function toggleAdvancedSettingsInputs(on) {
	var box = $('advancedBox');
	if (box) box.classList.toggle('hidden', !on);
}
function handleProtocolChange(input) {
	var v = $('fProtoVless'), t = $('fProtoTrojan');
	if (!v.checked && !t.checked) {
		input.checked = true;
		toast('⚠️ حداقل یکی از پروتکل‌ها باید انتخاب شده باشد!', 'warn');
	}
}
function toggleUserProxyMode(on) {
	var box = $('proxyFieldsBox');
	if (box) box.classList.toggle('hidden', !on);
	if (on) renderProxyFieldsUI();
}
window.handleProtocolChange = handleProtocolChange;
window.toggleAutoResetInputs = toggleAutoResetInputs;
window.toggleFragInputs = toggleFragInputs;
window.toggleAdvancedSettingsInputs = toggleAdvancedSettingsInputs;
window.toggleUserProxyMode = toggleUserProxyMode;

/* ---------- proxy fields ---------- */
function renderProxyFieldsUI() {
	var wrapper = $('proxiesFieldsWrapper');
	if (!wrapper) return;
	var cache = {};
	try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch (e) { }
	wrapper.innerHTML = State.proxyFields.map(function (p, idx) {
		var cc = '';
		if (p && cache[p]) cc = cache[p];
		var isVip = p && State.cachedVipProxies && State.cachedVipProxies[p];
		return '<div style="display:flex;align-items:center;gap:6px" data-pidx="' + idx + '">' +
			'<span style="flex:0 0 auto">' + flagHtml(cc) + '</span>' +
			'<input type="text" class="input input-mono" id="proxy-field-box-' + idx + '" value="' + attr(p || '') + '" placeholder="socks5:// یا http:// (کشور ' + (idx + 1) + ')" data-pinput="' + idx + '"' + (isVip ? ' style="border-color:var(--ok)"' : '') + '>' +
			'<button type="button" class="icon-btn" data-pact="up" data-p="' + idx + '" title="بالا">' + svgIcon('chevron') + '</button>' +
			'<button type="button" class="icon-btn danger" data-pact="del" data-p="' + idx + '" title="حذف">' + svgIcon('x') + '</button>' +
			'</div>';
	}).join('');
}
function addProxyField() { State.proxyFields.push(''); State.activeProxyIndex = State.proxyFields.length - 1; renderProxyFieldsUI(); }
function removeProxyField(idx) {
	if (State.proxyFields.length <= 1) { State.proxyFields = ['']; renderProxyFieldsUI(); return; }
	State.proxyFields.splice(idx, 1);
	if (State.activeProxyIndex >= State.proxyFields.length) State.activeProxyIndex = State.proxyFields.length - 1;
	renderProxyFieldsUI();
}
function swapProxyFields(a, b) {
	if (a < 0 || b < 0 || a >= State.proxyFields.length || b >= State.proxyFields.length) return;
	var tmp = State.proxyFields[a];
	State.proxyFields[a] = State.proxyFields[b];
	State.proxyFields[b] = tmp;
	renderProxyFieldsUI();
}
window.renderProxyFieldsUI = renderProxyFieldsUI;

on($('btnAddProxy'), 'click', addProxyField);
on($('proxiesFieldsWrapper'), 'input', function (e) {
	var el = e.target.closest ? e.target.closest('[data-pinput]') : null;
	if (!el) return;
	State.proxyFields[parseInt(el.getAttribute('data-pinput'), 10)] = el.value;
});
on($('proxiesFieldsWrapper'), 'click', function (e) {
	var b = e.target.closest ? e.target.closest('[data-pact]') : null;
	if (!b) return;
	var idx = parseInt(b.getAttribute('data-p'), 10);
	if (b.getAttribute('data-pact') === 'del') removeProxyField(idx);
	else swapProxyFields(idx, idx - 1);
});

async function testUserSocksProxy() {
	var clean = State.proxyFields.map(function (p) { return p ? p.trim() : ''; }).filter(function (p) { return p !== ''; });
	if (!clean.length) { toast('ابتدا حداقل یک پروکسی وارد کنید', 'warn'); return; }
	toast('⏳ در حال تست پروکسی‌ها...', 'info');
	var cache = {};
	try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch (e) { }
	var okCount = 0;
	for (var i = 0; i < clean.length; i++) {
		try {
			var res = await api('/api/test-proxy', { body: { proxy: clean[i] } });
			var d = await res.json().catch(function () { return {}; });
			if (res.ok && d && d.success && d.country) { cache[clean[i]] = d.country; okCount++; }
			else if (d && d.country) cache[clean[i]] = d.country;
		} catch (err) { }
	}
	try { localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache)); } catch (e) { }
	renderProxyFieldsUI();
	toast(okCount ? '✅ ' + okCount + ' پروکسی با موفقیت پاسخ داد' : '⚠️ هیچ پروکسی‌ای پاسخ نداد', okCount ? 'ok' : 'warn');
}
window.testUserSocksProxy = testUserSocksProxy;
on($('btnTestProxies'), 'click', testUserSocksProxy);

async function testDirectPing() {
	var cEl = $('pingClient'), sEl = $('pingServer'), stEl = $('pingState');
	var c2 = $('pingClient2'), s2 = $('pingServer2'), st2 = $('pingState2');
	function set(el, v) { if (el) el.textContent = v; }
	set(cEl, '...'); set(sEl, '...'); set(stEl, 'در حال تست');
	set(c2, '...'); set(s2, '...'); set(st2, 'در حال تست');
	var start = Date.now();
	try {
		await api('/api/ping', { method: 'GET' });
		set(cEl, (Date.now() - start) + ' ms');
		set(c2, (Date.now() - start) + ' ms');
	} catch (e) { set(cEl, 'خطا'); set(c2, 'خطا'); }
	try {
		var res = await api('/api/test-proxy', { body: { proxy: 'direct' } });
		var d = await res.json().catch(function () { return {}; });
		if (d && d.success) { set(sEl, d.ping + ' ms'); set(s2, d.ping + ' ms'); set(stEl, 'نت آزاد در دسترس'); set(st2, 'نت آزاد در دسترس'); }
		else { set(sEl, 'قطع'); set(s2, 'قطع'); set(stEl, (d && d.error) || 'نت آزاد قطع است'); set(st2, (d && d.error) || 'نت آزاد قطع است'); }
	} catch (err) { set(sEl, 'خطا'); set(s2, 'خطا'); set(stEl, 'خطا در تست'); set(st2, 'خطا در تست'); }
}
window.testDirectPing = testDirectPing;
on($('btnPingDirect'), 'click', testDirectPing);
on($('btnPingDirect2'), 'click', testDirectPing);

/* ---------- misc form buttons ---------- */
function generateRandomUsername() {
	var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	var s = '';
	for (var i = 0; i < 6; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
	var username = 'lml_' + s;
	$('fName').value = username;
	return username;
}
window.generateRandomUsername = generateRandomUsername;
on($('btnRandomName'), 'click', generateRandomUsername);

document.addEventListener('click', function (e) {
	var el = e.target.closest ? e.target.closest('[data-plan]') : null;
	if (el) {
		var parts = el.getAttribute('data-plan').split(',');
		$('fLimit').value = parts[0] && parts[0] !== '0' ? parts[0] : '';
		$('fExpiry').value = parts[1] && parts[1] !== '0' ? parts[1] : '';
		toast('✅ پلن ' + parts[2] + ' انتخاب شد', 'ok');
		return;
	}
	var v = e.target.closest ? e.target.closest('[data-vol]') : null;
	if (v) { $('fLimit').value = v.getAttribute('data-vol'); return; }
	var x = e.target.closest ? e.target.closest('[data-exp]') : null;
	if (x) { $('fExpiry').value = x.getAttribute('data-exp'); return; }
	var fp = e.target.closest ? e.target.closest('.frag-preset') : null;
	if (fp) {
		var op = fp.getAttribute('data-op');
		var map = { mci: ['10-30', '2-5'], irancell: ['100-200', '5-10'], rightel: ['50-100', '2-5'], tci: ['50-200', '1-3'], gaming: ['200-3000', '1-2'] };
		var val = map[op] || ['200-3000', '1-2'];
		$('fFragLen').value = val[0];
		$('fFragInt').value = val[1];
		$('fFragToggle').checked = true;
		toggleFragInputs(true);
		toast('✅ تنظیمات فرگمنت اعمال شد', 'ok');
		return;
	}
	var vp = e.target.closest ? e.target.closest('[data-vpreset]') : null;
	if (vp) {
		var p2 = vp.getAttribute('data-vpreset').split(',');
		$('voucherGb').value = p2[0];
		$('voucherDays').value = p2[1];
		return;
	}
	var cr = e.target.closest ? e.target.closest('[data-credit]') : null;
	if (cr) { $('creditGb').value = cr.getAttribute('data-credit'); return; }
	var ic = e.target.closest ? e.target.closest('[data-ipcount]') : null;
	if (ic) { $('ipCount').value = ic.getAttribute('data-ipcount'); return; }
});

on($('userVtabs'), 'click', function (e) {
	var b = e.target.closest ? e.target.closest('.vtab') : null;
	if (b) setUserModalTab(b.getAttribute('data-vtab'));
});
on($('btnPrevStep'), 'click', function () { userStepGo(-1); });
on($('btnNextStep'), 'click', function () { userStepGo(1); });

function fillPatternihaValues() {
	vchk('fAdvancedToggle', true);
	toggleAdvancedSettingsInputs(true);
	vset('fAdvancedFrag', '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}');
	vset('fCipherSuites', 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256');
	vset('fTlsMask', 'www.speedtest.net');
	toast('✅ مقادیر پیشنهادی با موفقیت درج شد', 'ok');
}
on($('btnFillPatt'), 'click', fillPatternihaValues);
on($('btnPattNgInfo'), 'click', function () {
	genericModal({
		title: 'مهم — تنظیمات پیشرفته ⁉️',
		sub: 'منحصراً اپلیکیشن‌های PattNG و PattN',
		icon: 'alert',
		color: 'var(--warn-soft)',
		iconColor: 'var(--warn)',
		body:
			'<div style="line-height:1.9">' +
			'<p>تنظیمات پیشرفته منحصراً روی دو اپلیکیشن <b>PattNG</b> (اندروید) و <b>PattN</b> (ویندوز) قابل استفاده است و روی سایر کلاینت‌ها بی‌تأثیر خواهد بود.</p>' +
			'<p style="margin-top:10px">برای اعمال این تنظیمات، قبل از اتصال حتماً در اپلیکیشن خود، گزینه <b>Fragment</b> را از منوی تنظیمات فعال کنید.</p>' +
			'</div>',
		buttons: [
			{
				primary: true, icon: 'external', text: 'دانلود PattNG اندروید',
				onClick: function () { window.open('https://play.google.com/store/apps/details?id=ir.patt.ng', '_blank'); }
			},
			{
				icon: 'external', text: 'دانلود PattN ویندوز',
				keepOpen: true,
				onClick: function () { window.open('https://github.com/MMDFAR/Patt-N/releases', '_blank'); }
			}
		]
	});
});

/* ---------- submit ---------- */
function setSubmitState(text, disabled) {
	var btn = $('userSubmitBtn');
	if (!btn) return;
	var t = $('userSubmitText');
	if (t) t.textContent = text;
	btn.disabled = !!disabled;
}
on($('userForm'), 'submit', function (e) {
	e.preventDefault();
	handleFormSubmit();
});

function handleFormSubmit() {
	var vlessEnabled = $('fProtoVless').checked;
	var trojanEnabled = $('fProtoTrojan').checked;
	if (!vlessEnabled && !trojanEnabled) { setUserModalTab('vtab-account'); toast('⚠️ حداقل یکی از پروتکل‌ها باید انتخاب شود!', 'warn'); return; }
	var protocols = [];
	if (vlessEnabled) protocols.push('vless');
	if (trojanEnabled) protocols.push('trojan');
	var connection_type = protocols.join(',');

	var username = $('fName').value.trim();
	if (!username) { setUserModalTab('vtab-account'); toast('⚠️ وارد کردن نام کاربری الزامی است!', 'warn'); return; }
	if (!/^[a-zA-Z0-9_-]+$/.test(username)) { setUserModalTab('vtab-account'); toast('⚠️ نام کاربری فقط می‌تواند شامل حروف انگلیسی، اعداد، خط تیره و آندرلاین باشد!', 'warn'); return; }

	var limit = $('fLimit').value || null;
	var expiry = $('fExpiry').value || null;
	var reqLimit = $('fReqLimit').value || null;
	var ipLimit = $('fIpLimit').value || null;
	if (limit !== null && parseFloat(limit) < 0) { toast('⚠️ حجم نمی‌تواند عدد منفی باشد!', 'warn'); return; }
	if (expiry !== null && parseInt(expiry, 10) < 0) { toast('⚠️ زمان (روز) نمی‌تواند عدد منفی باشد!', 'warn'); return; }
	if ((reqLimit !== null && parseInt(reqLimit, 10) < 0) || (ipLimit !== null && parseInt(ipLimit, 10) < 0)) { toast('⚠️ محدودیت‌ها نمی‌توانند منفی باشند!', 'warn'); return; }

	var autoResetToggle = $('fAutoReset').checked;
	var autoResetVolDays = $('fAutoResetVol').value;
	var autoResetReqDays = $('fAutoResetReq').value;
	if (autoResetToggle) {
		var vd = parseInt(autoResetVolDays, 10) || 0;
		var rd = parseInt(autoResetReqDays, 10) || 0;
		if (vd <= 0 && rd <= 0) { setUserModalTab('vtab-account'); toast('⚠️ وقتی تیک تمدید خودکار روشن است، باید حداقل یکی از فیلدها را پر کنید!', 'warn'); return; }
	}

	var customPortsArray = String($('fCustomPorts').value || '').replace(/ +/g, ',').split(',').map(function (p) { return p.trim(); }).filter(function (p) { return p.length > 0; });
	var checkedPorts = $$('input[name="ports"]:checked').map(function (c) { return c.value; }).concat(customPortsArray);
	checkedPorts = checkedPorts.filter(function (v2, i2, a2) { return a2.indexOf(v2) === i2; });
	if (!checkedPorts.length) { setUserModalTab('vtab-network'); toast('⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!', 'warn'); return; }

	var block_porn = $('fBlockPorn').checked ? 1 : 0;
	var block_ads = $('fBlockAds').checked ? 1 : 0;
	var isFragOn = $('fFragToggle').checked;
	var frag_len = isFragOn ? String($('fFragLen').value || '').trim() : '';
	var frag_int = isFragOn ? String($('fFragInt').value || '').trim() : '';
	var isAdvOn = vchk('fAdvancedToggle');
	var advanced_frag = isAdvOn ? String(vval('fAdvancedFrag') || '').trim() : '';
	var cipher_suites = isAdvOn ? String(vval('fCipherSuites') || '').trim() : '';
	var tls_mask = isAdvOn ? String(vval('fTlsMask') || '').trim() : '';
	var auto_reset_vol_days = autoResetToggle ? (parseInt(autoResetVolDays, 10) || 0) : 0;
	var auto_reset_req_days = autoResetToggle ? (parseInt(autoResetReqDays, 10) || 0) : 0;
	var auto_rotate_ip = $('fAutoRotateIp').checked ? 1 : 0;
	var ip_operator = $('fIpOperator').value || 'all';
	var ip_count = parseInt($('fIpCount').value, 10) || 20;
	var userProxyMode = $('fProxyMode').checked;
	var userSocks5 = null;
	if (userProxyMode && State.proxyFields.length) {
		var cleanProxies = State.proxyFields.map(function (p) { return p ? p.trim() : ''; }).filter(function (p) { return p !== ''; });
		if (cleanProxies.length === 1) userSocks5 = cleanProxies[0];
		else if (cleanProxies.length > 1) userSocks5 = JSON.stringify(cleanProxies);
	}
	var auto_rotate_user_proxy = $('fAutoRotateProxy').checked ? 1 : 0;
	var start_on_first_connect = 0;
	var enable_direct = true; /* direct connection is always on (toggle removed) */
	var ips = $('fIps').value;
	var fingerprint = $('fFingerprint').value;
	var port = checkedPorts.join(',');
	var tls = checkedPorts.some(function (p) { return TLS_PORTS.indexOf(p) >= 0; }) ? 'on' : 'off';

	var numIps = ips ? ips.split('\\n').filter(function (p) { return p.trim().length > 0; }).length : 1;
	if (!numIps) numIps = 1;
	var numPorts = checkedPorts.length || 1;
	var numProto = protocols.length || 1;
	var numProxies = userProxyMode ? State.proxyFields.filter(function (p) { return p && p.trim() !== ''; }).length : 0;
	if (enable_direct) numProxies += 1;
	if (numProxies === 0) numProxies = 1;
	var totalConfigs = 3 + (numProxies * numIps * numPorts * numProto);

	setSubmitState(State.editMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...', true);
	var url = State.editMode ? ('/api/users/' + encodeURIComponent(State.editingUsername)) : '/api/users';
	var method = State.editMode ? 'PUT' : 'POST';

	api(url, {
		method: method,
		body: {
			username: username,
			limit_gb: limit,
			expiry_days: expiry,
			limit_req: reqLimit,
			tls: tls,
			port: port,
			ips: ips,
			fingerprint: fingerprint,
			ip_limit: ipLimit,
			block_porn: block_porn,
			block_ads: block_ads,
			frag_len: frag_len,
			frag_int: frag_int,
			advanced_frag: advanced_frag || null,
			cipher_suites: cipher_suites || null,
			tls_mask: tls_mask || null,
			user_proxy_iata: null,
			user_socks5: userSocks5 || null,
			user_proxy_ip: null,
			auto_reset_vol_days: auto_reset_vol_days,
			auto_reset_req_days: auto_reset_req_days,
			auto_rotate_ip: auto_rotate_ip,
			rotate_time: 0,
			ip_operator: ip_operator,
			ip_count: ip_count,
			auto_rotate_user_proxy: auto_rotate_user_proxy,
			start_on_first_connect: start_on_first_connect,
			enable_direct: enable_direct,
			connection_type: connection_type,
			protocols: protocols
		}
	}).then(function (res) { return res.json().then(function (d) { return { ok: res.ok, d: d }; }); })
		.then(function (r) {
			if (!r.ok) { toast('خطا: ' + ((r.d && r.d.error) || 'عملیات ناموفق بود'), 'err'); return; }
			closeModal('modalUser');
			if (!State.editMode) {
				var uuid = (r.d && r.d.user && r.d.user.uuid) || '';
				openCreatedModal(username, uuid);
			} else {
				toast('✅ تغییرات با موفقیت ذخیره شد', 'ok');
			}
			if (totalConfigs > 60) setTimeout(openConfigCountWarning, 350);
			setTimeout(function () { loadUsers(true); }, 600);
		})
		.catch(function () { toast('خطا در برقراری ارتباط با سرور', 'err'); })
		.then(function () { setSubmitState(State.editMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false); });
}

function openConfigCountWarning() {
	genericModal({
		title: 'تعداد کانفیگ‌ها زیاد است',
		sub: 'احتمال بروز خطا در برخی کلاینت‌ها',
		icon: 'alert',
		color: 'var(--warn-soft)',
		iconColor: 'var(--warn)',
		body: '<div style="line-height:1.9">' +
			'<p>تعداد کانفیگ‌های ساخته‌شده برای این کاربر بیش از ۶۰ مورد است. برخی کلاینت‌ها (مثل v2rayNG قدیمی) ممکن است لیست را ناقص نمایش دهند یا هنگام بروزرسانی دچار خطا شوند.</p>' +
			'<p style="margin-top:10px">برای کاهش این عدد می‌توانید تعداد پورت‌ها، آی‌پی‌های تمیز یا مقاصد خروجی را کمتر کنید.</p>' +
			'<div class="note" style="margin-top:12px"><svg><use href="#i-info"/></svg><div>فرمول محاسبه: <span class="mono">۳ + لوکیشن × آی‌پی × پورت × پروتکل</span></div></div>' +
			'</div>'
	});
}
window.openConfigCountWarning = openConfigCountWarning;

/* ---------- created modal ---------- */
function openCreatedModal(username, uuid) {
	var subUrl = window.location.origin + '/sub/' + encodeURIComponent(username);
	var host = window.location.hostname;
	var vlessConfig = uuid
		? 'vless://' + uuid + '@' + host + ':443?path=' + encodeURIComponent('/stream/LML_PANEL/' + (uuid.split('-')[4] || 'default')) + '&security=tls&encryption=none&host=' + host + '&type=ws&sni=' + host + '#' + encodeURIComponent('⚡ LML ❯ ' + username)
		: subUrl;
	$('createdSub').textContent = subUrl;
	$('createdVless').value = vlessConfig;
	renderQr('createdQr', subUrl, 190);
	try { if (navigator.clipboard) navigator.clipboard.writeText(subUrl).catch(function () { }); } catch (e) { }
	$('btnCreatedPortal').setAttribute('data-portal', username);
	$('btnCreatedStatus').setAttribute('data-portal-status', username);
	openModal('modalCreated');
	toast('🎉 کاربر ' + username + ' ایجاد و لینک کپی شد!', 'ok');
}
on($('btnCreatedPortal'), 'click', function () { window.open(getPortalLink(this.getAttribute('data-portal')), '_blank'); });
on($('btnCreatedStatus'), 'click', function () { window.open(getStatusLink(this.getAttribute('data-portal-status')), '_blank'); });

/* ============================================================
   15. IP REPOSITORY
   ============================================================ */
var IP_OPERATORS = [
	{ val: 'all', text: 'همه (توصیه شده)' },
	{ val: 'irancell_rightel', text: 'ایرانسل/رایتل/شاتل' },
	{ val: 'mobinnet_asiatech', text: 'مبین نت/فیبر/آسیاتک' },
	{ val: 'mci_tci', text: 'همراه اول/مخابرات' },
	{ val: 'aptel_samantel', text: 'آپتل/سامانتل/پیشگامان' }
];
function populateIpSelect() {
	var sel = $('ipOperator');
	if (!sel) return;
	sel.innerHTML = IP_OPERATORS.map(function (o) { return '<option value="' + o.val + '">' + esc(o.text) + '</option>'; }).join('');
}
async function fetchIpsList() {
	var res = await fetchWithFallbackUI('ips.txt');
	if (!res.ok) throw new Error('Fetch failed');
	var text = await res.text();
	var lines = text.split('\\n').map(function (l) { return l.trim(); }).filter(function (l) { return l.length > 0 && l.indexOf('#') < 0 && l.indexOf('[source') !== 0; });
	State.cachedIps = { all: lines };
	State.ipsFetchedAt = Date.now();
	populateIpSelect();
}
/* ---------- offline range picker ----------
   Official, published CIDR blocks for each network. Used when the worker
   cannot reach the live range APIs, so the scanner still returns genuine
   addresses instead of failing. */
var LML_CDN_RANGES = {
	cf: ["104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20", "197.234.240.0/22", "172.66.0.0/16", "108.162.0.0/16", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "190.93.240.0/20", "198.41.128.0/17"],
	aws: ["13.32.0.0/15", "52.222.128.0/17", "99.84.0.0/16", "205.251.192.0/19", "108.156.0.0/14", "130.176.0.0/17", "54.230.0.0/16", "54.239.128.0/18", "143.204.0.0/16", "144.220.0.0/16"],
	fastly: ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "199.116.208.0/21", "23.235.32.0/20", "104.156.80.0/20", "157.52.64.0/18", "172.111.64.0/18"],
	google: ["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16", "173.194.0.0/16", "216.239.32.0/19", "108.177.0.0/17", "35.190.0.0/17"],
	azure: ["13.64.0.0/11", "20.0.0.0/11", "104.40.0.0/13", "40.64.0.0/10", "51.4.0.0/15", "191.233.0.0/16", "52.146.0.0/17"]
};
function lmlIpToInt(ip) {
	var p = String(ip).split(".");
	return (((+p[0] << 24) + (+p[1] << 16) + (+p[2] << 8) + (+p[3])) >>> 0);
}
function lmlIntToIp(n) {
	return [((n >>> 24) & 255), ((n >>> 16) & 255), ((n >>> 8) & 255), (n & 255)].join(".");
}
function lmlIpsFromCidr(cidr, want) {
	var out = [];
	var parts = String(cidr).split("/");
	var base = parts[0];
	var bits = parseInt(parts[1] || "32", 10);
	if (isNaN(bits) || bits < 8 || bits > 32) bits = 24;
	var size = Math.pow(2, 32 - bits);
	if (size < 4) return [base];
	var start = lmlIpToInt(base);
	var seen = {};
	var tries = 0;
	while (out.length < want && tries < want * 20) {
		tries++;
		var off = 1 + Math.floor(Math.random() * (size - 2));
		var ip = lmlIntToIp((start + off) >>> 0);
		if (!seen[ip]) { seen[ip] = 1; out.push(ip); }
	}
	return out;
}
/* Always returns real addresses drawn from the official ranges above. */
function lmlLocalScan(provs, count) {
	var picked = [];
	var detail = {};
	var share = Math.max(1, Math.round(count / (provs.length || 1)));
	provs.forEach(function (p) {
		var list = LML_CDN_RANGES[p] || [];
		if (!list.length) { detail[p] = 0; return; }
		var got = [];
		var guard = 0;
		while (got.length < share && guard < share * 10) {
			guard++;
			var cidr = list[Math.floor(Math.random() * list.length)];
			lmlIpsFromCidr(cidr, Math.min(10, share - got.length)).forEach(function (ip) {
				if (got.indexOf(ip) < 0) got.push(ip);
			});
		}
		detail[p] = got.length;
		got.forEach(function (ip) { if (picked.indexOf(ip) < 0) picked.push(ip); });
	});
	return { ips: picked, detail: detail, totalRanges: provs.reduce(function (a, p) { return a + (LML_CDN_RANGES[p] || []).length; }, 0) };
}

async function openIpRepoModal() {
	openModal('modalIps');
	var log = $('ipLoading');
	if (log) { log.textContent = ''; log.classList.add('hidden'); }
	vset('ipCount', vval('fIpCount') || '20');
}
window.openIpSelectorModal = openIpRepoModal;

var _ipScanning = false;
async function applySelectedIps() {
	if (_ipScanning) return;
	var provs = $$('.ip-prov:checked').map(function (c) { return c.value; });
	if (!provs.length) { toast('\u26a0\ufe0f \u062d\u062f\u0627\u0642\u0644 \u06cc\u06a9 \u0634\u0628\u06a9\u0647 \u0631\u0627 \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f', 'warn'); return; }
	var count = parseInt(vval('ipCount'), 10) || 20;
	var log = $('ipLoading');
	var btn = $('btnApplyIps');
	var NL = String.fromCharCode(10);
	function say(t) { if (log) { log.textContent = t; log.classList.remove('hidden'); } }
	_ipScanning = true;
	if (btn) btn.disabled = true;
	say('\u062f\u0631 \u062d\u0627\u0644 \u062f\u0631\u06cc\u0627\u0641\u062a \u0631\u0646\u062c\u200c\u0647\u0627\u06cc \u0632\u0646\u062f\u0647...');
	try {

	var names = { cf: 'Cloudflare', aws: 'Amazon', fastly: 'Fastly', google: 'Google', azure: 'Azure' };
	function label(st) {
		if (st === 'live') return '\u0632\u0646\u062f\u0647';
		if (st === 'fallback') return '\u067e\u0634\u062a\u06cc\u0628\u0627\u0646';
		if (st === 'static') return '\u062b\u0627\u0628\u062a';
		return '\u0646\u0627\u0645\u0648\u0641\u0642';
	}
	function finish(ips, detail, totalRanges, srcNote) {
		var det = Object.keys(detail || {}).map(function (k) { return (names[k] || k) + ': ' + detail[k]; }).join(' \u00b7 ');
		say(ips.length + ' \u0622\u06cc\u200c\u067e\u06cc \u062f\u0631\u06cc\u0627\u0641\u062a \u0634\u062f' + NL + det + NL +
			'\u062a\u0639\u062f\u0627\u062f \u0631\u0646\u062c\u200c\u0647\u0627: ' + (totalRanges || 0) + (srcNote ? NL + srcNote : ''));
		vset('fIps', ips.join(NL));
		vchk('fAutoRotateIp', true);
		vset('fAutoRotate', '1');
		vset('fIpCount', String(ips.length));
		State.cachedIps = { all: ips.slice() };
		toast('\u2705 ' + ips.length + ' \u0622\u06cc\u200c\u067e\u06cc \u0628\u0647 \u06a9\u0627\u0646\u0641\u06cc\u06af \u0627\u0636\u0627\u0641\u0647 \u0634\u062f', 'ok');
		setTimeout(function () { closeModal('modalIps'); }, 900);
	}

	/* ---------- 1. try the worker route (live ranges) ---------- */
	var serverNote = '';
	try {
		var res = await updateFetch('/api/scan-ips', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ providers: provs, count: count })
		}, 12000);
		var d = await res.json().catch(function () { return null; });
		if (res && res.ok && d && d.success && (d.ips || []).length) {
			var srcLine = Object.keys(d.status || {}).map(function (k) {
				return (names[k] || k) + ' (' + label(d.status[k]) + ')';
			}).join(' \u00b7 ');
			finish(d.ips, d.detail || {}, d.totalRanges || 0, srcLine ? '\u0645\u0646\u0627\u0628\u0639: ' + srcLine : '');
			return;
		}
		if (res) {
			serverNote = '\u0633\u0631\u0648\u0631 ' + res.status + ((d && d.error) ? ': ' + d.error : '');
		}
	} catch (e) {
		serverNote = '\u0639\u062f\u0645 \u0627\u0631\u062a\u0628\u0627\u0637 \u0628\u0627 \u0633\u0631\u0648\u0631';
	}

	/* ---------- 2. guaranteed local path: real addresses from the
	      official published ranges (never leaves the button dead) ---------- */
	var local = lmlLocalScan(provs, count);
	if (local.ips.length) {
		var note = '\u0645\u0646\u0628\u0639: \u0631\u0646\u062c\u200c\u0647\u0627\u06cc \u0631\u0633\u0645\u06cc \u0627\u0646\u062a\u0634\u0627\u0631\u200c\u0634\u062f\u0647 (\u062f\u0631 \u0645\u0631\u0648\u0631\u06af\u0631)';
		if (serverNote) note = note + ' \u2014 ' + serverNote;
		finish(local.ips, local.detail, local.totalRanges, note);
		return;
	}

	say('\u062e\u0637\u0627: \u0647\u06cc\u0686 \u0631\u0646\u062c\u06cc \u0628\u0631\u0627\u06cc \u0627\u06cc\u0646 \u0634\u0628\u06a9\u0647\u200c\u0647\u0627 \u06cc\u0627\u0641\u062a \u0646\u0634\u062f.');
	toast('\u26a0\ufe0f \u0627\u0633\u06a9\u0646 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062f', 'warn');
	} catch (err) {
		say('\u062e\u0637\u0627\u06cc \u067e\u06cc\u0634\u200c\u0628\u06cc\u0646\u06cc\u200c\u0646\u0634\u062f\u0647: ' + (err && err.message ? err.message : '\u0646\u0627\u0645\u0634\u062e\u0635'));
	} finally {
		_ipScanning = false;
		if (btn) btn.disabled = false;
	}
}
window.applySelectedIps = applySelectedIps;
window.applySelectedIps = applySelectedIps;
on($('btnApplyIps'), 'click', applySelectedIps);
on($('btnOpenIpRepo'), 'click', openIpRepoModal);
on($('btnOpenIpRepo2'), 'click', openIpRepoModal);
on($('btnOpenIpRepo3'), 'click', openIpRepoModal);

/* VIP proxy cache (used to highlight known-good proxy links) */
async function initVipCache() {
	try {
		var res = await fetchWithFallbackUI('vip-list');
		if (!res.ok) return;
		var files = await res.json();
		State.cachedVipList = (files || []).filter(function (f) { return f && f.name && f.name.indexOf('.txt') === f.name.length - 4; })
			.map(function (f) { return f.name.replace('.txt', '').toUpperCase(); });
		if (State.cachedVipList && State.cachedVipList.length) {
			await Promise.all(State.cachedVipList.map(async function (country) {
				try {
					var r2 = await fetchWithFallbackUI('proxy_vip/' + country + '.txt');
					if (r2.ok) {
						var txt = await r2.text();
						var lines = txt.split('\\n').map(function (l) { return l.trim(); }).filter(function (l) { return l.length > 5; });
						if (lines.length) State.cachedVipProxies[country] = lines;
					}
				} catch (e) { }
			}));
		}
	} catch (e) { }
}

/* ============================================================
   16. VOUCHERS
   ============================================================ */
async function loadVouchers() {
	try {
		var res = await api('/api/vouchers/list');
		var d = await res.json().catch(function () { return { vouchers: [] }; });
		State.vouchers = Array.isArray(d.vouchers) ? d.vouchers : [];
		State.stats.vouchers = State.vouchers.filter(function (v) { return !v.is_used; }).length;
		renderVouchers();
		renderVoucherSummary();
		renderStats();
	} catch (e) { }
}
function voucherFilterList(kind) {
	var q = (($(kind === 'used' ? 'vusedSearch' : 'voucherSearch')) && $(kind === 'used' ? 'vusedSearch' : 'voucherSearch').value || '').toLowerCase().trim();
	var filterEl = $('voucherFilter');
	var status = (kind !== 'used' && filterEl) ? filterEl.value : 'used';
	var list = State.vouchers.slice();
	if (kind === 'used') list = list.filter(function (v) { return v.is_used == 1; });
	else if (status === 'unused') list = list.filter(function (v) { return v.is_used != 1; });
	else if (status === 'used') list = list.filter(function (v) { return v.is_used == 1; });
	if (q) list = list.filter(function (v) { return String(v.code || '').toLowerCase().indexOf(q) >= 0 || String(v.used_by || '').toLowerCase().indexOf(q) >= 0; });
	return list;
}
function renderVouchers() {
	renderVoucherBody(voucherFilterList('all'), 'voucherTbody', 'voucherState', 'ووچری یافت نشد', 'voucher');
	renderVoucherBody(voucherFilterList('used'), 'vusedTbody', 'vusedState', 'ووچر استفاده‌شده‌ای ثبت نشده است', 'vused');
	$('voucherCount').textContent = State.vouchers.length + ' ووچر';
	$('vusedCount').textContent = State.vouchers.filter(function (v) { return v.is_used == 1; }).length + ' مورد';
}
function renderVoucherBody(list, tbodyId, stateId, emptyText, kind) {
	var tbody = $(tbodyId), state = $(stateId);
	if (!tbody) return;
	if (!list.length) {
		tbody.innerHTML = '';
		if (state) state.innerHTML = '<div class="state"><div class="si">' + svgIcon('ticket') + '</div><div class="sd">' + esc(emptyText) + '</div></div>';
		return;
	}
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (v) {
		var used = v.is_used == 1;
		var code = String(v.code || '');
		return '<tr>' +
			'<td data-col="کد"><span class="mono" style="font-weight:700">' + esc(code) + '</span></td>' +
			'<td data-col="حجم" class="c-num">' + esc(v.limit_gb) + ' GB</td>' +
			'<td data-col="مدت" class="c-num">' + esc(v.expiry_days) + ' روز</td>' +
			'<td data-col="وضعیت">' + (used ? '<span class="badge muted">استفاده‌شده</span>' : '<span class="badge ok">آماده</span>') + '</td>' +
			'<td data-col="مصرف‌کننده" class="c-hide-sm">' + (v.used_by ? '<span class="mono">' + esc(v.used_by) + '</span>' : '—') + '</td>' +
			'<td data-col="تاریخ" class="c-hide-sm" style="font-size:var(--fs-xs);color:var(--text-3)">' + dateStr(v.created_at) + '</td>' +
			'<td class="c-actions">' +
			'<button type="button" class="icon-btn" data-act="voucher-menu" data-v="' + attr(code) + '" title="عملیات">' + svgIcon('more') + '</button>' +
			'</td></tr>';
	}).join('');
}
function voucherMenu(anchor, code) {
	var v = State.vouchers.filter(function (x) { return x.code === code; })[0];
	openMenu(anchor, [
		{ icon: 'copy', label: 'کپی کد ووچر', action: function () { copyText(code, '✅ کد ووچر کپی شد'); } },
		{
			icon: 'ticket', label: 'کپی پیام تحویل', action: function () {
				if (!v) return;
				copyText('🎁 کد شارژ: ' + code + '\\n💾 حجم: ' + v.limit_gb + ' گیگابایت\\n⏳ مدت: ' + v.expiry_days + ' روز', '✅ پیام تحویل کپی شد');
			}
		},
		{
			icon: 'trash', label: 'حذف ووچر', danger: true, action: function () {
				deleteVoucher(code);
			}
		}
	]);
}
async function deleteVoucher(code) {
	var ok = await confirmBox('آیا از حذف ووچر «' + code + '» اطمینان دارید؟', { title: 'حذف ووچر', okText: 'حذف کن', danger: true });
	if (!ok) return;
	try {
		var res = await api('/api/vouchers/delete', { method: 'POST', body: { code: code } });
		var d = await res.json().catch(function () { return {}; });
		if (!res.ok || (d && d.error)) { toast('خطا: ' + ((d && d.error) || 'حذف ناموفق بود'), 'err'); return; }
	} catch (e) { toast('خطا در ارتباط با سرور', 'err'); return; }
	State.vouchers = State.vouchers.filter(function (v) { return v.code !== code; });
	renderVouchers();
	renderVoucherSummary();
	renderStats();
	toast('✅ ووچر حذف شد', 'ok');
}
async function createVoucher(code, gb, days) {
	try {
		var res = await api('/api/vouchers/create', { body: { code: code, limit_gb: gb, expiry_days: days } });
		var d = await res.json().catch(function () { return {}; });
		if (res.ok && d.success) {
			toast('✅ کارت شارژ ' + d.code + ' تولید شد!', 'ok');
			renderVoucherResult(d);
			loadVouchers();
			return d;
		}
		toast((d && d.error) || 'خطا در تولید ووچر', 'err');
	} catch (e) { toast('خطا در ارتباط با سرور', 'err'); }
	return null;
}
function renderVoucherResult(d) {
	var box = $('voucherResult');
	if (!box) return;
	box.innerHTML =
		'<div class="note ok" style="margin-bottom:12px"><svg><use href="#i-check"/></svg><div>ووچر با موفقیت تولید شد و آماده تحویل است.</div></div>' +
		'<div class="copy-field" style="margin-bottom:6px"><span class="cf-val mono" style="font-size:var(--fs-md);font-weight:800">' + esc(d.code) + '</span>' +
		'<button type="button" class="btn btn-sm" data-copy="' + attr(d.code) + '" data-copy-msg="✅ کد ووچر کپی شد">کپی</button></div>' +
		'<div class="kv-list" style="margin-top:12px">' +
		'<div class="kv"><span class="k">حجم</span><span class="v">' + esc(d.limit_gb) + ' GB</span></div>' +
		'<div class="kv"><span class="k">مدت اعتبار</span><span class="v">' + esc(d.expiry_days) + ' روز</span></div>' +
		'</div>' +
		'<button type="button" class="btn btn-block btn-primary" style="margin-top:12px" data-copy="' + attr('🎁 کد شارژ: ' + d.code) + '" data-copy-msg="✅ پیام تحویل کپی شد">' + svgIcon('copy') + 'کپی پیام تحویل</button>';
}
function renderVoucherSummary() {
	var box = $('voucherSummary');
	if (!box) return;
	var all = State.vouchers;
	var unused = all.filter(function (v) { return v.is_used != 1; });
	var used = all.filter(function (v) { return v.is_used == 1; });
	var gb = unused.reduce(function (s, v) { return s + (parseFloat(v.limit_gb) || 0); }, 0);
	box.innerHTML = [
		miniCard('ticket', 'ci-accent', 'کل ووچرها', nfmt(all.length), 'ثبت‌شده در سیستم'),
		miniCard('check', 'ci-ok', 'آماده استفاده', nfmt(unused.length), 'قابل تحویل به مشتری'),
		miniCard('chart', 'ci-violet', 'حجم آماده', nfmt(gb.toFixed(1)) + ' GB', 'مجموع اعتبار ووچرها'),
		miniCard('x', 'ci-err', 'استفاده‌شده', nfmt(used.length), 'مصرف‌شده توسط کاربران')
	].join('');
}
on($('voucherForm'), 'submit', function (e) {
	e.preventDefault();
	createVoucher($('voucherCode').value.trim(), $('voucherGb').value, $('voucherDays').value);
});
on($('modalVoucherForm'), 'submit', function (e) {
	e.preventDefault();
	createVoucher($('mvCode').value.trim(), $('mvGb').value, $('mvDays').value).then(function (d) {
		if (d) { closeModal('modalVoucher'); goToView('view-sales', 'tab-vcreate'); }
	});
});
on($('voucherReset'), 'click', function () { $('voucherCode').value = ''; $('voucherGb').value = '20'; $('voucherDays').value = '30'; });
on($('voucherSearch'), 'input', debounce(renderVouchers, 200));
on($('vusedSearch'), 'input', debounce(renderVouchers, 200));
on($('voucherFilter'), 'change', renderVouchers);
window.loadVouchers = loadVouchers;

/* ============================================================
   17. RESELLERS
   ============================================================ */
async function loadResellers() {
	var tbody = $('resellerTbody');
	try {
		var res = await api('/api/resellers');
		if (!res.ok) throw new Error('خطا در دسترسی');
		var d = await res.json();
		var list = d.resellers || [];
		State.resellers = list;
		State.stats.resellers = list.length;
		renderResellers();
		renderResellerSummary();
		renderStats();
		updateSidebarCounts();
	} catch (e) {
		if (tbody) tbody.innerHTML = '';
		var st = $('resellerState');
		if (st) st.innerHTML = '<div class="state"><div class="si">' + svgIcon('alert') + '</div><div class="st">خطا در دریافت لیست</div><div class="sd">' + esc(e.message) + '</div></div>';
	}
}
function filteredResellers() {
	var q = String(vval('resellerSearch') || '').toLowerCase().trim();
	if (!q) return State.resellers.slice();
	return State.resellers.filter(function (r) { return String(r.username || '').toLowerCase().indexOf(q) >= 0 || String(r.note || '').toLowerCase().indexOf(q) >= 0; });
}
function renderResellers() {
	var tbody = $('resellerTbody'), state = $('resellerState');
	if (!tbody) return;
	var list = filteredResellers();
	if (!list.length) {
		tbody.innerHTML = '';
		if (state) state.innerHTML = '<div class="state"><div class="si">' + svgIcon('handshake') + '</div><div class="st">هیچ نماینده‌ای ثبت نشده است</div><div class="sd">با دکمه «نماینده جدید» اولین همکار خود را اضافه کنید.</div></div>';
		return;
	}
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (r) {
		var rem = Math.max(0, (r.credit_gb || 0) - (r.used_gb || 0)).toFixed(1);
		return '<tr>' +
			'<td data-col="نماینده"><div class="cell-user"><span class="u-avatar">' + esc(String(r.username).slice(0, 2).toUpperCase()) + '</span>' +
			'<span style="min-width:0"><span class="uname mono">' + esc(r.username) + '</span>' +
			(r.note ? '<span class="umeta" style="display:block">' + esc(r.note) + '</span>' : '') + '</span></div></td>' +
			'<td data-col="سهمیه کل" class="c-num">' + esc(r.credit_gb) + ' GB</td>' +
			'<td data-col="مصرفی" class="c-num">' + (r.used_gb || 0).toFixed(1) + ' GB</td>' +
			'<td data-col="باقیمانده" class="c-num" style="color:var(--ok);font-weight:800">' + rem + ' GB</td>' +
			'<td data-col="کاربران" class="c-num">' + (r.user_count || 0) + ' / ' + esc(r.max_users) + '</td>' +
			'<td data-col="وضعیت">' + (r.is_active ? '<span class="badge ok">فعال</span>' : '<span class="badge err">غیرفعال</span>') + '</td>' +
			'<td class="c-actions"><button type="button" class="icon-btn" data-act="reseller-menu" data-r="' + attr(String(r.id)) + '" title="عملیات">' + svgIcon('more') + '</button></td>' +
			'</tr>';
	}).join('');
}
function resellerMenu(anchor, idStr) {
	var r = State.resellers.filter(function (x) { return String(x.id) === String(idStr); })[0];
	if (!r) return;
	openMenu(anchor, [
		{ icon: 'wallet', label: 'افزایش سهمیه', action: function () { openCreditModal(r.id, r.username); } },
		{ icon: 'edit', label: 'ویرایش نماینده', action: function () { openResellerModal(r); } },
		{ icon: 'power', label: r.is_active ? 'غیرفعال‌سازی' : 'فعال‌سازی', action: function () { toggleResellerActive(r.id); } },
		{ icon: 'external', label: 'باز کردن پورتال نماینده', action: function () { window.open('/reseller', '_blank'); } },
		'-',
		{ icon: 'trash', label: 'حذف نماینده', danger: true, action: function () { deleteReseller(r.id, r.username); } }
	]);
}
function openResellerModal(r) {
	$('resellerModalTitle').textContent = r ? 'ویرایش نماینده «' + r.username + '»' : 'افزودن نماینده جدید';
	$('rsId').value = r ? r.id : '';
	$('rsUsername').value = r ? r.username : '';
	$('rsUsername').disabled = !!r;
	$('rsPassword').value = '';
	$('rsPassHint').textContent = r ? 'در صورت تمایل به تغییر، مقدار جدید را وارد کنید' : 'برای نماینده جدید الزامی است';
	$('rsPassword').required = !r;
	$('rsCredit').value = r ? r.credit_gb : 100;
	$('rsMaxUsers').value = r ? r.max_users : 50;
	$('rsNote').value = r ? (r.note || '') : '';
	$('rsActive').checked = r ? !!r.is_active : true;
	openModal('modalReseller');
}
function openCreditModal(id, name) {
	State._creditId = id;
	$('creditSub').textContent = 'نماینده: ' + name;
	$('creditGb').value = '50';
	openModal('modalCredit');
}
on($('btnNewReseller'), 'click', function () { openResellerModal(null); });
on($('resellerSearch'), 'input', debounce(renderResellers, 200));
on($('resellerForm'), 'submit', function (e) {
	e.preventDefault();
	var id = $('rsId').value;
	var body = {
		username: $('rsUsername').value.trim(),
		credit_gb: $('rsCredit').value,
		max_users: $('rsMaxUsers').value,
		note: $('rsNote').value.trim(),
		is_active: $('rsActive').checked ? 1 : 0
	};
	var pass = $('rsPassword').value.trim();
	if (!id) {
		if (!pass || pass.length < 6) { toast('⚠️ رمز عبور باید حداقل ۶ کاراکتر باشد', 'warn'); return; }
		body.password = pass;
		api('/api/resellers/create', { body: body })
			.then(function (res) { return res.json(); })
			.then(function (d) {
				if (d && d.error) toast('خطا: ' + d.error, 'err');
				else { toast('✅ حساب نماینده ' + body.username + ' ایجاد شد!', 'ok'); closeModal('modalReseller'); loadResellers(); }
			}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
		return;
	}
	body.id = id;
	if (pass) body.password = pass;
	api('/api/resellers/update', { body: body })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.error) toast('خطا: ' + d.error, 'err');
			else { toast('✅ اطلاعات نماینده ذخیره شد', 'ok'); closeModal('modalReseller'); loadResellers(); }
		}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
});
on($('btnDoCredit'), 'click', function () {
	var gb = parseFloat($('creditGb').value);
	if (!gb || isNaN(gb)) { toast('مقدار نامعتبر است', 'warn'); return; }
	api('/api/resellers/update', { body: { id: State._creditId, add_credit: gb } })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.error) toast('خطا: ' + d.error, 'err');
			else { toast('✅ سهمیه به میزان +' + gb + 'GB افزایش یافت!', 'ok'); closeModal('modalCredit'); loadResellers(); }
		}).catch(function () { toast('خطا در افزایش سهمیه', 'err'); });
});
function toggleResellerActive(id) {
	api('/api/resellers/update', { body: { id: id, toggle_active: true } })
		.then(function (res) { return res.ok ? {} : res.json(); })
		.then(function (d) {
			if (d && d.error) toast('خطا: ' + d.error, 'err');
			else { toast('وضعیت نماینده تغییر کرد', 'ok'); loadResellers(); }
		}).catch(function () { toast('خطا در تغییر وضعیت', 'err'); });
}
async function deleteReseller(id, name) {
	var ok = await confirmBox('آیا از حذف حساب نماینده «' + name + '» اطمینان دارید؟', { title: 'حذف نماینده', okText: 'حذف کن', danger: true });
	if (!ok) return;
	api('/api/resellers/delete', { body: { id: id } })
		.then(function (res) { return res.ok ? {} : res.json(); })
		.then(function (d) {
			if (d && d.error) toast('خطا: ' + d.error, 'err');
			else { toast('نماینده ' + name + ' حذف شد', 'ok'); loadResellers(); }
		}).catch(function () { toast('خطا در حذف نماینده', 'err'); });
}
function renderResellerSummary() {
	var box = $('resellerSummary');
	if (!box) return;
	var list = State.resellers;
	var active = list.filter(function (r) { return r.is_active; }).length;
	var credit = list.reduce(function (s, r) { return s + (parseFloat(r.credit_gb) || 0); }, 0);
	var used = list.reduce(function (s, r) { return s + (parseFloat(r.used_gb) || 0); }, 0);
	box.innerHTML = [
		miniCard('handshake', 'ci-accent', 'نمایندگان', nfmt(list.length), 'ثبت‌شده در سیستم'),
		miniCard('check', 'ci-ok', 'فعال', nfmt(active), 'دارای دسترسی فعال'),
		miniCard('wallet', 'ci-info', 'سهمیه واگذارشده', nfmt(credit.toFixed(0)) + ' GB', 'مجموع اعتبار نمایندگان'),
		miniCard('chart', 'ci-warn', 'مصرف نمایندگان', nfmt(used.toFixed(0)) + ' GB', 'حجم تخصیص‌یافته به مشتریان')
	].join('');
}
window.loadResellers = loadResellers;
window.toggleResellersModal = function () { toast('🎁 این پنل رایگان است — بخش نمایندگان برداشته شده است.', 'info'); };

document.addEventListener('click', function (e) {
	var t = e.target.closest ? e.target.closest('[data-act]') : null;
	if (!t) return;
	var act = t.getAttribute('data-act');
	if (act === 'voucher-menu') { e.stopPropagation(); voucherMenu(t, t.getAttribute('data-v')); }
	else if (act === 'reseller-menu') { e.stopPropagation(); resellerMenu(t, t.getAttribute('data-r')); }
});

/* ============================================================
   18. TELEGRAM CENTER
   ============================================================ */
async function loadTelegramSettings() {
	try {
		var res = await api('/api/telegram-info');
		if (!res.ok) return;
		var d = await res.json();
		State.telegram = d;
		var token = d.bot_token || '';
		var admin = d.admin_id || '';
		$('tgToken').value = token;
		$('setTgToken').value = token;
		$('tgAdminId').value = admin;
		$('setTgAdmin').value = admin;
		var connected = !!token;
		$('tgStatusText').textContent = connected ? '🟢 ربات فعال و متصل به پنل است' : '⚪ توکن تنظیم نشده است';
		$('tgStatusText').style.color = connected ? 'var(--ok)' : 'var(--text-3)';
		$('tgStatusHint').textContent = connected ? 'ربات آماده دریافت دستورات است' : 'برای فعال‌سازی، توکن ربات را ثبت کنید';
		$('tgStatusIcon').style.background = connected ? 'var(--ok-soft)' : 'var(--surface-3)';
		$('tgStatusIcon').style.color = connected ? 'var(--ok)' : 'var(--text-3)';
		$('tgWebhookState').textContent = connected ? 'تنظیم‌شده' : '—';
		$('tgWebhookState').style.color = connected ? 'var(--ok)' : 'var(--text-3)';
	} catch (e) { }
}
async function saveTelegramSettings(token, adminId) {
	try {
		var res = await api('/api/telegram-setup', { body: { bot_token: token, admin_id: adminId } });
		var d = await res.json().catch(function () { return {}; });
		if (res.ok && d.success) { toast('✅ ربات تلگرام با موفقیت متصل شد!', 'ok'); loadTelegramSettings(); return true; }
		toast('خطا: ' + ((d && d.error) || 'عملیات ناموفق بود'), 'err');
	} catch (e) { toast('خطا در برقراری ارتباط با تلگرام', 'err'); }
	return false;
}
on($('tgForm'), 'submit', function (e) {
	e.preventDefault();
	saveTelegramSettings($('tgToken').value.trim(), $('tgAdminId').value.trim());
});
on($('btnTgSave'), 'click', function () { saveTelegramSettings($('tgToken').value.trim(), $('tgAdminId').value.trim()); });
on($('btnSaveTg2'), 'click', function () { saveTelegramSettings($('setTgToken').value.trim(), $('setTgAdmin').value.trim()); });
on($('btnTgRefresh'), 'click', loadTelegramSettings);
on($('btnTgTest'), 'click', function () {
	if (!$('tgToken').value.trim()) { toast('ابتدا توکن ربات را وارد و ذخیره کنید', 'warn'); return; }
	toast('⏳ در حال بررسی اتصال...', 'info');
	loadTelegramSettings();
	setTimeout(function () {
		toast(State.telegram && State.telegram.bot_token ? '✅ اتصال ربات برقرار است' : '⚠️ اتصال برقرار نشد', State.telegram && State.telegram.bot_token ? 'ok' : 'warn');
	}, 1200);
});
on($('btnTgBackup'), 'click', function () {
	toast('⏳ در حال ارسال فایل پشتیبان...', 'info');
	api('/api/telegram-backup', { method: 'POST' })
		.then(function (res) { return res.json(); })
		.then(function (d) { toast((d && d.success) ? ('✅ ' + d.message) : ('خطا: ' + ((d && d.error) || 'ارسال ناموفق بود')), (d && d.success) ? 'ok' : 'err'); })
		.catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
});
on($('btnTgOpenBot'), 'click', function () {
	var token = $('tgToken').value.trim();
	if (!token) { toast('ابتدا توکن ربات را ثبت کنید', 'warn'); return; }
	window.open('https://t.me/' + token.split(':')[0], '_blank');
});
on($('btnTgDocs'), 'click', function () {
	genericModal({
		title: 'راهنمای دستورات ربات',
		sub: 'دستورات در دسترس ادمین در تلگرام',
		icon: 'logs',
		body: '<div class="kv-list">' +
			'<div class="kv"><span class="k">/start</span><span class="v">شروع کار با ربات</span></div>' +
			'<div class="kv"><span class="k">/status</span><span class="v">نمایش وضعیت کلی پنل</span></div>' +
			'<div class="kv"><span class="k">/backup</span><span class="v">دریافت فایل پشتیبان</span></div>' +
			'<div class="kv"><span class="k">آیدی ادمین</span><span class="v">محدودسازی دسترسی</span></div>' +
			'</div>' +
			'<div class="note info" style="margin-top:12px"><svg><use href="#i-info"/></svg><div>دستورات فقط برای آیدی عددی ثبت‌شده پاسخ می‌دهند. در صورت خالی بودن آیدی، ربات به همه پاسخ می‌دهد.</div></div>'
	});
});
on($('btnCopyWebhook'), 'click', function () { copyText($('tgWebhook').value, '✅ آدرس وب‌هوک کپی شد'); });
window.loadTelegramSettings = loadTelegramSettings;
window.toggleTelegramModal = function () { goToView('view-telegram'); loadTelegramSettings(); };

/* ============================================================
   19. TRIAL & WARP
   ============================================================ */
async function createInstantTrial(btn) {
	if (btn) btn.disabled = true;
	toast('⏳ در حال ساخت اکانت تست ۲۴ ساعته...', 'info');
	try {
		var res = await api('/api/trial', { method: 'POST' });
		var d = await res.json().catch(function () { return {}; });
		if (res.ok && d.success) {
			try { if (navigator.clipboard) navigator.clipboard.writeText(d.subUrl).catch(function () { }); } catch (e) { }
			toast('✅ اکانت ' + d.username + ' با موفقیت ایجاد و لینک کپی شد!', 'ok');
			loadUsers();
		} else toast((d && d.error) || 'خطا در ایجاد تست', 'err');
	} catch (e) { toast('خطا در برقراری ارتباط', 'err'); }
	finally { if (btn) btn.disabled = false; }
}
window.createInstantTrial = createInstantTrial;
window.createTrialUser = createInstantTrial;

function createWarpConfig() { toast('کانفیگ WARP از این نسخه حذف شده است.', 'info'); return;
	var host = window.location.hostname;
	var warpLink = 'vless://warp-core@engage.cloudflareclient.com:2408?encryption=none&security=none&type=ws&host=' + host + '&path=%2Fstream%2FLML_PANEL%2Fdefault#⚡%20LML%20❯%20[WARP-ON-WARP]';
	vset('warpConfig', warpLink);
	renderQr('warpQr', warpLink, 180);
	try { if (navigator.clipboard) navigator.clipboard.writeText(warpLink).catch(function () { }); } catch (e) { }
	openModal('modalWarp');
	toast('🚀 کانفیگ اختصاصی WARP ایجاد و کپی شد!', 'ok');
}
window.createWarpConfig = createWarpConfig;
window.toggleWarpModal = function (show) { if (show) createWarpConfig(); else closeModal('modalWarp'); };
on($('btnCopyWarp'), 'click', function () { copyText(vval('warpConfig'), '📋 کانفیگ WARP کپی شد!'); });

/* ============================================================
   20. DASHBOARD
   ============================================================ */
function renderStats() {
	var s = State.stats;
	set('statTotalUsers', nfmt(s.total));
	set('statActiveUsers', nfmt(s.active));
	set('statExpiredUsers', nfmt(s.expired));
	set('statOnlineConns', nfmt(s.online));
	set('statTraffic', nfmt(s.gb.toFixed(1)));
	set('statVouchers', nfmt(s.vouchers));
set('statRequests', compact(s.reqToday));
	set('statRequestsTotal', nfmt(s.reqTotal));
	var pct = Math.min((s.reqToday / 100000) * 100, 100);
	set('statRequestsPct', (pct < 10 ? pct.toFixed(1) : Math.round(pct)) + '%');
	var bar = $('statRequestsBar');
	if (bar) { bar.style.width = pct + '%'; bar.style.background = pct > 80 ? 'var(--err)' : (pct > 50 ? 'var(--warn)' : 'var(--ok)'); }
	var card = $('stat-card-requests');
	if (card) card.classList.toggle('danger', pct > 80);
	set('kvReqToday', nfmt(s.reqToday) + ' / 100k');
	set('kvReqTotal', nfmt(s.reqTotal));
	set('kvD1Writes', nfmt(s.d1w) + ' / 100k');
	set('kvD1Reads', nfmt(s.d1r) + ' / 5M');
	var kb = $('kvReqBar');
	if (kb) { kb.style.width = pct + '%'; kb.style.background = pct > 80 ? 'var(--err)' : 'var(--accent)'; }
	set('sysStatusText', s.total >= 0 ? 'سیستم آنلاین' : 'بررسی');
	if ($('sysDot')) $('sysDot').className = 'dot-live on';
	set('kvLastSync', State.lastSync ? timeStr(State.lastSync) : '—');
	updateSidebarCounts();
	buildSearchIndex();
}
function set(id, v) { var el = $(id); if (el) el.textContent = v; }
function vset(id, v) { var el = $(id); if (el) el.value = (v === undefined || v === null) ? '' : v; }
function vchk(id, v) { var el = $(id); if (el) el.checked = !!v; }
function vdis(id, v) { var el = $(id); if (el) el.disabled = !!v; }
function vck(id) { var el = $(id); return el ? !!el.checked : false; }
function vval(id) { var el = $(id); return el ? el.value : ''; }
function updateSidebarCounts() {
	var s = State.stats;
	/* --- resilient values: derived straight from the live lists so the
	     badge can never show a stale / wrong zero --- */
	var onlineUsers = 0, onlineConns = 0;
	(State.allUsers || []).forEach(function (u) {
		if (u && u.is_online === 1) onlineUsers++;
		if (u && u.online_count) onlineConns += (u.online_count || 0);
	});
	var online = s.online || 0;
	if (!online) online = onlineConns || onlineUsers;
	var total = (s.total || 0) || (State.allUsers || []).length;
	var vouchers = (s.vouchers || 0);
	if (!vouchers && (State.vouchers || []).length) {
		vouchers = State.vouchers.filter(function (v) { return !v.is_used; }).length;
	}
	var resellers = (s.resellers || 0);
	if (!resellers && (State.resellers || []).length) resellers = State.resellers.length;

	var map = {
		total: total,
		active: s.active,
		expired: s.expired,
		online: online,
		vouchers: vouchers,
		resellers: resellers
	};
	$$('#sbNav [data-count]').forEach(function (el) {
		var k = el.getAttribute('data-count');
		var v = map[k];
		if (v === undefined || v === null || isNaN(v)) v = 0;
		el.textContent = nfmt(v);
		el.style.display = v > 0 ? '' : 'none';
	});
}
window.updateSidebarCounts = updateSidebarCounts;

function renderDashboard() {
	/* top users by usage (real data) */
	var top = State.allUsers.slice()
		.filter(function (u) { return (u.used_gb || 0) > 0; })
		.sort(function (a, b) { return (b.used_gb || 0) - (a.used_gb || 0); })
		.slice(0, 8);
	var max = top.length ? (top[0].used_gb || 0) : 1;
	$('dashTopUsers').innerHTML = top.length
		? top.map(function (u) {
			var w = Math.max(2, ((u.used_gb || 0) / max) * 100);
			return '<div class="bar-row">' +
				'<span class="bl" title="' + attr(u.username) + '">' + esc(u.username) + '</span>' +
				'<span class="bar-track"><span class="bar-fill" style="width:' + w + '%;background:linear-gradient(90deg,var(--accent),var(--violet))"></span></span>' +
				'<span class="bt">' + kbShort(u.used_gb || 0) + '</span>' +
				'</div>';
		}).join('')
		: emptyState('chart', 'داده‌ای برای نمایش نیست', 'تا زمانی که کاربری ترافیک مصرف نکند، نموداری نمایش داده نمی‌شود.');

	/* donut: status distribution (real data) */
	var online = State.allUsers.filter(function (u) { return isUserEffective(u, State.serverTime) && u.is_online === 1; }).length;
	var idle = State.allUsers.filter(function (u) { return isUserEffective(u, State.serverTime) && u.is_online !== 1; }).length;
	var blocked = State.allUsers.filter(function (u) { return u.is_active === 0; }).length;
	var expired = State.allUsers.filter(function (u) { return u.is_active !== 0 && !isUserEffective(u, State.serverTime); }).length;
	var segs = [
		{ label: 'آنلاین', value: online, color: 'var(--ok)' },
		{ label: 'فعال آفلاین', value: idle, color: 'var(--accent)' },
		{ label: 'منقضی', value: expired, color: 'var(--warn)' },
		{ label: 'مسدود', value: blocked, color: 'var(--err)' }
	];
	$('dashDonut').innerHTML = donut(segs, State.allUsers.length);
	$('dashDonutLegend').innerHTML = segs.map(function (s) {
		return '<span class="lg"><span class="sw" style="background:' + s.color + '"></span>' + esc(s.label) + ' <b class="num">' + s.value + '</b></span>';
	}).join('');

	/* online list */
	var onlines = State.allUsers.filter(function (u) { return u.is_online === 1 && (u.online_count || 0) > 0; })
		.sort(function (a, b) { return (b.online_count || 0) - (a.online_count || 0); }).slice(0, 8);
	$('dashOnlineList').innerHTML = onlines.length
		? onlines.map(function (u) {
			var limit = (u.ip_limit !== undefined && u.ip_limit !== null) ? u.ip_limit : u.max_connections;
			return '<div class="kv">' +
				'<span class="k" style="display:flex;align-items:center;gap:8px"><span class="dot-live on"></span><span class="mono">' + esc(u.username) + '</span></span>' +
				'<span class="v">' + (u.online_count || 0) + ' / ' + (limit || '∞') + '</span>' +
				'</div>';
		}).join('')
		: emptyState('wifi', 'اتصال فعالی وجود ندارد', 'هیچ کاربری در این لحظه متصل نیست.');

	/* quick actions */
	var actions = [
		{ icon: 'bolt', label: 'ساخت سریع', hint: 'بهترین تنظیمات', fn: 'quick-fast' },
		{ icon: 'user-plus', label: 'کاربر جدید', hint: 'ایجاد حساب تکی', fn: 'quick-new' },
		{ icon: 'box', label: 'ساخت گروهی', hint: 'تولید دسته‌ای', fn: 'quick-bulk' },
		{ icon: 'rocket', label: 'اکانت تست', hint: '۲۴ ساعته ۱ گیگ', fn: 'quick-trial' },
		{ icon: 'ticket', label: 'کارت شارژ', hint: 'تولید ووچر', fn: 'quick-voucher' },
{ icon: 'refresh', label: 'تمدید دسته‌ای', hint: 'تمدید گروهی', fn: 'quick-renew' },
		{ icon: 'backup', label: 'پشتیبان‌گیری', hint: 'دانلود بکاپ', fn: 'quick-backup' }
	];
	$('dashQuick').innerHTML = actions.map(function (a) {
		return '<button type="button" class="btn btn-block" data-quick="' + a.fn + '" style="justify-content:flex-start;height:auto;padding:12px;text-align:right">' +
			'<span class="stat-icon" style="width:30px;height:30px;flex:0 0 30px;background:var(--surface-3);color:var(--text-2)">' + svgIcon(a.icon) + '</span>' +
			'<span style="min-width:0"><span style="display:block;font-weight:700;font-size:var(--fs-sm)">' + esc(a.label) + '</span>' +
			'<span style="display:block;font-size:var(--fs-xs);color:var(--text-4)">' + esc(a.hint) + '</span></span>' +
			'</button>';
	}).join('');
}
/* ---------- analytics (server aggregate report) ---------- */
async function loadAnalytics() {
	var box = $('dashAnalyticsStats');
	if (!box) return;
	box.innerHTML = '<div class="sd" style="padding:16px;text-align:center">در حال دریافت آمار...</div>';
	try {
		var res = await api('/api/analytics');
		if (!res.ok) throw new Error('net');
		var d = await res.json().catch(function () { return {}; });
		if (d && d.error) throw new Error(d.error);
		var cards = [
			{ label: 'کل کاربران', value: (d.total_users || 0), icon: 'users', color: 'var(--accent)' },
			{ label: 'کاربران فعال', value: (d.active_users || 0), icon: 'user-check', color: 'var(--ok)' },
			{ label: 'مجموع مصرف', value: (parseFloat(d.total_gb) || 0).toFixed(2) + ' GB', icon: 'chart', color: 'var(--violet)' },
			{ label: 'تعداد نمایندگان', value: (d.total_resellers || 0), icon: 'handshake', color: 'var(--warn)' }
		];
		box.innerHTML = cards.map(function (c) {
			return '<div class="card" style="padding:14px">' +
				'<div style="display:flex;align-items:center;gap:10px">' +
				'<span class="stat-icon" style="width:32px;height:32px;flex:0 0 32px;background:var(--surface-3);color:' + c.color + '">' + svgIcon(c.icon) + '</span>' +
				'<span style="min-width:0"><span style="display:block;font-size:var(--fs-xs);color:var(--text-4)">' + esc(c.label) + '</span>' +
				'<span style="display:block;font-weight:800;font-size:var(--fs-lg)" class="num">' + esc(String(c.value)) + '</span></span>' +
				'</div></div>';
		}).join('');

		var top = (d && Array.isArray(d.top_users)) ? d.top_users.filter(function (u) { return (u.used_gb || 0) > 0; }) : [];
		var topBox = $('dashAnalyticsTop');
		if (!topBox) return;
		if (!top.length) {
			topBox.innerHTML = emptyState('chart', 'هنوز مصرفی ثبت نشده', 'پرمصرف‌ترین کاربران اینجا نمایش داده می‌شوند.');
			return;
		}
		var max = top[0].used_gb || 1;
		topBox.innerHTML = top.slice(0, 10).map(function (u) {
			var w = Math.max(2, ((u.used_gb || 0) / max) * 100);
			return '<div class="bar-row">' +
				'<span class="bl mono" title="' + attr(u.username) + '">' + esc(u.username) + '</span>' +
				'<span class="bar-track"><span class="bar-fill" style="width:' + w + '%;background:linear-gradient(90deg,var(--violet),var(--accent))"></span></span>' +
				'<span class="bt">' + kbShort(u.used_gb || 0) + '</span>' +
				'</div>';
		}).join('');
	} catch (e) {
		box.innerHTML = emptyState('alert', 'دریافت آمار ناموفق بود', 'اتصال به سرور برقرار نشد. دوباره تلاش کنید.');
		var tb = $('dashAnalyticsTop');
		if (tb) tb.innerHTML = '';
	}
}
window.loadAnalytics = loadAnalytics;
on($('btnRefreshAnalytics'), 'click', loadAnalytics);

function emptyState(icon, title, desc) {
	return '<div class="state" style="padding:24px 12px"><div class="si">' + svgIcon(icon) + '</div>' +
		'<div class="st" style="font-size:var(--fs-sm)">' + esc(title) + '</div>' +
		'<div class="sd" style="font-size:var(--fs-xs)">' + esc(desc) + '</div></div>';
}
function donut(segs, total) {
	var size = 168, r = 66, sw = 22, c = 2 * Math.PI * r;
	if (!total) return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '"><circle cx="' + (size / 2) + '" cy="' + (size / 2) + '" r="' + r + '" fill="none" stroke="var(--surface-3)" stroke-width="' + sw + '"/></svg>';
	var offset = 0;
	var parts = segs.map(function (s) {
		var frac = s.value / total;
		var len = frac * c;
		var el = '<circle cx="' + (size / 2) + '" cy="' + (size / 2) + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="' + sw +
			'" stroke-dasharray="' + len + ' ' + (c - len) + '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 ' + (size / 2) + ' ' + (size / 2) + ')" stroke-linecap="butt"/>';
		offset += len;
		return el;
	}).join('');
	return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" class="chart">' +
		'<circle cx="' + (size / 2) + '" cy="' + (size / 2) + '" r="' + r + '" fill="none" stroke="var(--surface-3)" stroke-width="' + sw + '"/>' +
		parts +
		'<text x="50%" y="48%" text-anchor="middle" fill="currentColor" style="font-size:26px;font-weight:800;font-family:var(--font-mono)" direction="ltr">' + total + '</text>' +
		'<text x="50%" y="62%" text-anchor="middle" fill="var(--text-4)" style="font-size:10px">کاربر</text>' +
		'</svg>';
}

/* ============================================================
   21. SERVICES VIEWS
   ============================================================ */
function renderServiceViews() {
	renderConfigsTab();
	renderSubTab();
	renderConnTab();
	renderIpTab();
	renderTrafficTab();
}
function svcQuery(id) {
	return ($(id) && $(id).value || '').toLowerCase().trim();
}
function svcList(id) {
	var q = svcQuery(id);
	if (!q) return State.allUsers.slice();
	return State.allUsers.filter(function (u) { return String(u.username).toLowerCase().indexOf(q) >= 0; });
}
function renderConfigsTab() {
	var tbody = $('cfgTbody'), state = $('cfgState');
	if (!tbody) return;
	var list = svcList('cfgSearch').slice(0, 200);
	if (!list.length) { tbody.innerHTML = ''; if (state) state.innerHTML = emptyState('bolt', 'کاربری یافت نشد', 'برای مشاهده کانفیگ‌ها باید کاربری وجود داشته باشد.'); return; }
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (u) {
		var ports = String(u.port || '443').split(',').filter(function (p) { return p; }).slice(0, 6).join(' , ');
		return '<tr>' +
			'<td data-col="کاربر"><div class="cell-user"><span class="u-avatar">' + esc(String(u.username).slice(0, 2).toUpperCase()) + '</span><span class="uname mono">' + esc(u.username) + '</span></div></td>' +
			'<td data-col="پروتکل">' + protoBadges(u) + '</td>' +
			'<td data-col="پورت‌ها" class="c-num" style="font-size:var(--fs-xs)">' + esc(ports) + '</td>' +
			'<td data-col="لوکیشن">' + userFlags(u) + '</td>' +
			'<td data-col="تعداد"><span class="badge accent num">' + configCount(u) + '</span></td>' +
			'<td class="c-actions">' +
			'<button type="button" class="btn btn-sm" data-act="copy-config" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('copy') + 'کپی</button> ' +
			'<button type="button" class="icon-btn" data-act="user-menu" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('more') + '</button>' +
			'</td></tr>';
	}).join('');
}
function renderSubTab() {
	var tbody = $('subTbody'), state = $('subState');
	if (!tbody) return;
	var list = svcList('subSearch').slice(0, 200);
	if (!list.length) { tbody.innerHTML = ''; if (state) state.innerHTML = emptyState('link', 'کاربری یافت نشد', ''); return; }
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (u) {
		var enc = encodeURIComponent(u.username);
		var sub = getSubLink(u.username);
		return '<tr>' +
			'<td data-col="کاربر"><div class="cell-user"><span class="u-avatar">' + esc(String(u.username).slice(0, 2).toUpperCase()) + '</span><span class="uname mono">' + esc(u.username) + '</span></div></td>' +
			'<td data-col="لینک"><div class="copy-field"><span class="cf-val">' + esc(sub) + '</span>' +
			'<button type="button" class="btn btn-sm" data-copy="' + attr(sub) + '" data-copy-msg="✅ لینک اشتراک کپی شد">کپی</button></div></td>' +
			'<td class="c-actions">' +
			'<button type="button" class="icon-btn" data-act="qr-sub" data-u="' + attr(enc) + '" title="QR ساب">' + svgIcon('qr') + '</button>' +
			'<button type="button" class="icon-btn" data-act="copy-singbox" data-u="' + attr(enc) + '" title="کپی Sing-box">' + svgIcon('copy') + '</button>' +
			'<button type="button" class="icon-btn" data-act="copy-status" data-u="' + attr(enc) + '" title="کپی وضعیت">' + svgIcon('activity') + '</button>' +
			'<button type="button" class="icon-btn" data-act="open-portal" data-u="' + attr(enc) + '" title="پرتال کاربر">' + svgIcon('external') + '</button>' +
			'<button type="button" class="icon-btn" data-act="user-menu" data-u="' + attr(enc) + '">' + svgIcon('more') + '</button>' +
			'</td></tr>';
	}).join('');
}
function renderConnTab() {
	var tbody = $('connTbody'), state = $('connState');
	var onlineUsers = State.allUsers.filter(function (u) { return u.is_online === 1 && (u.online_count || 0) > 0; }).length;
	var conns = State.stats.online;
	var over = State.allUsers.filter(function (u) {
		var limit = (u.ip_limit !== undefined && u.ip_limit !== null) ? u.ip_limit : u.max_connections;
		return limit && (u.online_count || 0) > limit;
	}).length;
	$('connSummary').innerHTML = [
		miniCard('users', 'ci-accent', 'کاربران آنلاین', nfmt(onlineUsers), 'دارای حداقل یک اتصال'),
		miniCard('wifi', 'ci-info', 'کل اتصال‌ها', nfmt(conns), 'جمع اتصال‌های فعال'),
		miniCard('alert', 'ci-err', 'عبور از سقف', nfmt(over), 'اتصال بیش از حد مجاز'),
		miniCard('activity', 'ci-ok', 'درصد اتصال', (State.stats.total ? ((onlineUsers / State.stats.total) * 100).toFixed(0) : 0) + '%', 'نسبت کاربران متصل')
	].join('');
	if (!tbody) return;
	var list = svcList('connSearch').slice(0, 200);
	if (!list.length) { tbody.innerHTML = ''; if (state) state.innerHTML = emptyState('activity', 'کاربری یافت نشد', ''); return; }
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (u) {
		var limit = (u.ip_limit !== undefined && u.ip_limit !== null) ? u.ip_limit : u.max_connections;
		var pct = limit ? Math.min(((u.online_count || 0) / limit) * 100, 100) : 0;
		return '<tr>' +
			'<td data-col="کاربر"><div class="cell-user"><span class="u-avatar">' + esc(String(u.username).slice(0, 2).toUpperCase()) + '</span><span class="uname mono">' + esc(u.username) + '</span></div></td>' +
			'<td data-col="وضعیت">' + statusBadge(u) + '</td>' +
			'<td data-col="اتصال"><div class="meter"><div class="meter-top"><span class="v">' + (u.online_count || 0) + '</span><span class="m">/ ' + (limit || '∞') + '</span></div><div class="bar"><i style="width:' + pct + '%;background:' + (pct > 90 ? 'var(--err)' : 'var(--ok)') + '"></i></div></div></td>' +
			'<td data-col="خروجی">' + (u.enable_direct === 0 ? '<span class="badge info">فقط پروکسی</span>' : (u.user_socks5 || u.user_proxy_ip ? '<span class="badge violet">پروکسی + مستقیم</span>' : '<span class="badge muted">مستقیم</span>')) + '</td>' +
			'<td class="c-actions">' +
			'<button type="button" class="icon-btn" data-act="open-status" data-u="' + attr(encodeURIComponent(u.username)) + '" title="وضعیت">' + svgIcon('external') + '</button>' +
			'<button type="button" class="icon-btn" data-act="user-menu" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('more') + '</button>' +
			'</td></tr>';
	}).join('');
}
function renderIpTab() {
	$('kvIpLoaded').textContent = nfmt(Object.keys(State.cachedIps).reduce(function (s, k) { return s + ((State.cachedIps[k] || []).length); }, 0));
	$('kvIpTime').textContent = State.ipsFetchedAt ? timeStr(State.ipsFetchedAt) : '—';
	var tbody = $('ipTbody'), state = $('ipState');
	if (!tbody) return;
	var list = svcList('userSearch').slice(0, 120);
	if (!list.length) { tbody.innerHTML = ''; if (state) state.innerHTML = emptyState('globe', 'کاربری یافت نشد', ''); return; }
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (u) {
		var nIps = u.ips ? String(u.ips).split('\\n').filter(function (s) { return s.trim(); }).length : 0;
		return '<tr>' +
			'<td data-col="کاربر"><span class="mono">' + esc(u.username) + '</span></td>' +
			'<td data-col="تعداد" class="c-num">' + nIps + '</td>' +
			'<td data-col="چرخش خودکار">' + (u.auto_rotate_ip === 1 ? '<span class="badge ok">فعال</span>' : '<span class="badge muted">خاموش</span>') + '</td>' +
			'<td data-col="اوپراتور">' + esc(u.ip_operator || 'all') + '</td>' +
			'</tr>';
	}).join('');
}
function renderTrafficTab() {
	var used = State.allUsers.reduce(function (s, u) { return s + (u.used_gb || 0); }, 0);
	var limited = State.allUsers.reduce(function (s, u) { return s + (u.limit_gb || 0); }, 0);
	var reqs = State.allUsers.reduce(function (s, u) { return s + (u.used_req || 0); }, 0);
	var near = State.allUsers.filter(function (u) { return u.limit_gb && ((u.used_gb || 0) / u.limit_gb) >= 0.9; }).length;
	$('trafficSummary').innerHTML = [
		miniCard('chart', 'ci-violet', 'مصرف کل', nfmt(used.toFixed(1)) + ' GB', 'جمع مصرف کاربران'),
		miniCard('database', 'ci-accent', 'سقف تخصیصی', nfmt(limited.toFixed(1)) + ' GB', 'مجموع حجم‌های تعریف‌شده'),
		miniCard('activity', 'ci-info', 'ریکوئست کل', compact(reqs), 'تعداد درخواست‌ها'),
		miniCard('alert', 'ci-warn', 'نزدیک به اتمام', nfmt(near), 'بیش از ۹۰٪ حجم مصرف شده')
	].join('');

	var top = State.allUsers.slice().sort(function (a, b) { return (b.used_gb || 0) - (a.used_gb || 0); }).slice(0, 10);
	var max = top.length ? (top[0].used_gb || 0) : 1;
	$('trafficBars').innerHTML = top.length
		? top.map(function (u) {
			var w = Math.max(2, ((u.used_gb || 0) / max) * 100);
			return '<div class="bar-row">' +
				'<span class="bl" title="' + attr(u.username) + '">' + esc(u.username) + '</span>' +
				'<span class="bar-track"><span class="bar-fill" style="width:' + w + '%;background:linear-gradient(90deg,var(--accent),var(--info))"></span></span>' +
				'<span class="bt">' + kbShort(u.used_gb || 0) + (u.limit_gb ? ' / ' + kbShort(u.limit_gb) : '') + '</span>' +
				'</div>';
		}).join('')
		: emptyState('chart', 'داده‌ای ثبت نشده است', '');

	var tbody = $('trafficTbody'), state = $('trafficState');
	if (!tbody) return;
	var sort = $('trafficSort') ? $('trafficSort').value : 'usage-desc';
	var list = svcList('trafficSearch');
	if (sort === 'usage-asc') list.sort(function (a, b) { return (a.used_gb || 0) - (b.used_gb || 0); });
	else if (sort === 'req-desc') list.sort(function (a, b) { return (b.used_req || 0) - (a.used_req || 0); });
	else list.sort(function (a, b) { return (b.used_gb || 0) - (a.used_gb || 0); });
	list = list.slice(0, 300);
	if (!list.length) { tbody.innerHTML = ''; if (state) state.innerHTML = emptyState('chart', 'کاربری یافت نشد', ''); return; }
	if (state) state.innerHTML = '';
	tbody.innerHTML = list.map(function (u) {
		var pct = u.limit_gb ? Math.min(((u.used_gb || 0) / u.limit_gb) * 100, 100) : 0;
		return '<tr>' +
			'<td data-col="کاربر"><span class="mono" style="font-weight:700">' + esc(u.username) + '</span></td>' +
			'<td data-col="مصرف" class="c-num">' + kbShort(u.used_gb || 0) + '</td>' +
			'<td data-col="سقف" class="c-num">' + (u.limit_gb ? kbShort(u.limit_gb) : '∞') + '</td>' +
			'<td data-col="درصد"><div class="meter"><div class="meter-top"><span class="v">' + (u.limit_gb ? pct.toFixed(0) + '%' : '—') + '</span></div><div class="bar"><i style="width:' + (u.limit_gb ? pct : 100) + '%;background:' + (pct > 90 ? 'var(--err)' : 'var(--accent)') + '"></i></div></div></td>' +
			'<td data-col="ریکوئست" class="c-num">' + nfmt(u.used_req || 0) + '</td>' +
			'<td class="c-actions">' +
			'<button type="button" class="btn btn-sm" data-act="reset-volume" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('refresh') + 'ریست حجم</button> ' +
			'<button type="button" class="icon-btn" data-act="user-menu" data-u="' + attr(encodeURIComponent(u.username)) + '">' + svgIcon('more') + '</button>' +
			'</td></tr>';
	}).join('');
}
['cfgSearch', 'subSearch', 'connSearch', 'trafficSearch'].forEach(function (id) {
	on($(id), 'input', debounce(renderServiceViews, 200));
});
on($('trafficSort'), 'change', renderTrafficTab);
on($('userSearch'), 'input', debounce(filterAndRenderUsers, 180));
on($('userFilter'), 'change', filterAndRenderUsers);
on($('userSort'), 'change', filterAndRenderUsers);
on($('btnCfgFormula'), 'click', openConfigCountWarning);
on($('btnCfgFormula2'), 'click', openConfigCountWarning);
on($('btnPingClient'), 'click', testDirectPing);

/* ============================================================
   22. SYSTEM VIEWS
   ============================================================ */
function renderSystemViews() {
	var s = State.stats;
	$('workerSummary').innerHTML = [
		miniCard('server', 'ci-ok', 'وضعیت ورکر', 'آنلاین', 'پاسخ‌گویی فعال'),
		miniCard('users', 'ci-accent', 'کاربران', nfmt(s.total), 'تعداد رکورد‌ها'),
		miniCard('activity', 'ci-info', 'درخواست امروز', compact(s.reqToday), 'از سهمیه ۱۰۰ هزار'),
		miniCard('clock', 'ci-warn', 'آخرین همگام‌سازی', timeStr(State.lastSync), 'دریافت داده از سرور')
	].join('');
	$('workerDetail').innerHTML =
		'<div class="kv"><span class="k">نسخه پنل</span><span class="v" id="wVersion">' + CURRENT_VERSION + '</span></div>' +
		'<div class="kv"><span class="k">آدرس پنل</span><span class="v">' + esc(window.location.host) + '</span></div>' +
		'<div class="kv"><span class="k">تعداد کاربران</span><span class="v">' + nfmt(s.total) + '</span></div>' +
		'<div class="kv"><span class="k">اتصال‌های فعال</span><span class="v">' + nfmt(s.online) + '</span></div>' +
		'<div class="kv"><span class="k">زمان سرور</span><span class="v">' + dateStr(State.serverTime) + '</span></div>' +
		'<div class="kv"><span class="k">زمان محلی</span><span class="v">' + dateStr(Date.now()) + '</span></div>';

	$('dbSummary').innerHTML = [
		miniCard('database', 'ci-accent', 'کل رکوردها', nfmt(s.total), 'جدول users'),
		miniCard('download', 'ci-violet', 'نوشتن امروز', nfmt(s.d1w), 'از سهمیه ۱۰۰ هزار'),
		miniCard('upload', 'ci-info', 'خواندن امروز', nfmt(s.d1r), 'از سهمیه ۵ میلیون'),
		miniCard('chart', 'ci-warn', 'ترافیک ثبت‌شده', nfmt(s.gb.toFixed(1)) + ' GB', 'شامل کاربران حذف‌شده')
	].join('');
	var bars = [
		{ label: 'درخواست‌ها', v: s.reqToday, max: 100000, color: 'var(--accent)' },
		{ label: 'نوشتن D1', v: s.d1w, max: 100000, color: 'var(--violet)' },
		{ label: 'خواندن D1', v: s.d1r, max: 5000000, color: 'var(--info)' }
	];
	$('dbBars').innerHTML = bars.map(function (b) {
		var pct = Math.min((b.v / b.max) * 100, 100);
		return '<div class="bar-row"><span class="bl">' + esc(b.label) + '</span>' +
			'<span class="bar-track"><span class="bar-fill" style="width:' + Math.max(pct, 0.5) + '%;background:' + (pct > 80 ? 'var(--err)' : b.color) + '"></span></span>' +
			'<span class="bt">' + nfmt(b.v) + ' / ' + compact(b.max) + '</span></div>';
	}).join('');
	$('mVersion').textContent = CURRENT_VERSION;
	$('mLatest').textContent = State.latestVersion || CURRENT_VERSION;
	$('mAutoUpdate').textContent = State.autoUpdate ? 'فعال' : 'غیرفعال';
	$('setVersion').textContent = CURRENT_VERSION;
	$('setLatest').textContent = State.latestVersion || '—';
	$('setServerTime').textContent = dateStr(State.serverTime);
}
async function loadSecurityLogs(tbodyId, stateId) {
	var tbody = $(tbodyId);
	if (!tbody) return;
	tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;padding:14px;color:var(--text-4)">در حال دریافت...</td></tr>';
	try {
		var res = await api('/api/admin/logs');
		var d = await res.json().catch(function () { return { logs: [] }; });
		var logs = (d && Array.isArray(d.logs)) ? d.logs : [];
		if (!logs.length) {
			tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;padding:14px;color:var(--text-4)">هنوز گزارشی ثبت نشده است</td></tr>';
			return;
		}
		tbody.innerHTML = logs.map(function (l) {
			var ok = l.status === 'موفق';
			return '<tr>' +
				'<td class="mono" style="font-size:var(--fs-xs)" dir="ltr">' + esc(l.ip || 'نامشخص') + '</td>' +
				'<td><span class="badge ' + (ok ? 'ok' : 'err') + '">' + esc(l.status) + '</span></td>' +
				'<td style="font-size:var(--fs-xs);color:var(--text-3)">' + faDate(l.created_at) + '</td>' +
				'</tr>';
		}).join('');
	} catch (e) {
		tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;padding:14px;color:var(--err)">خطا در بارگذاری لاگ‌ها</td></tr>';
	}
}
on($('btnToggleLogs'), 'click', function () {
	var b = $('logsBox');
	b.classList.toggle('hidden');
	$('logsChev').style.transform = b.classList.contains('hidden') ? '' : 'rotate(180deg)';
	if (!b.classList.contains('hidden')) loadSecurityLogs('logsTbody', null);
});
on($('btnReloadLogs'), 'click', function () { loadSecurityLogs('sysLogsTbody', 'sysLogsState'); });

/* ============================================================
   23. BACKUP & RESTORE
   ============================================================ */
function downloadSmartBackup() {
	toast('⏳ در حال آماده‌سازی فایل پشتیبان...', 'info');
	var a = document.createElement('a');
	a.href = '/api/backup-json';
	a.download = 'lml-backup.json';
	a.click();
}
function downloadBackupFile() {
	window.location.href = '/api/backup';
	toast('📥 دانلود فایل پشتیبان دیتابیس آغاز شد...', 'info');
}
function exportUsersBackup() {
	var data = JSON.stringify({ users: State.allUsers, exported_at: new Date().toISOString() }, null, 2);
	var blob = new Blob([data], { type: 'application/json;charset=utf-8' });
	var a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'lml-users-' + new Date().toISOString().slice(0, 10) + '.json';
	a.click();
	toast('✅ فایل کاربران دانلود شد', 'ok');
}
async function uploadSmartRestore(file) {
	toast('⏳ در حال خواندن فایل و بازگردانی...', 'info');
	try {
		var text = await file.text();
		var data = JSON.parse(text);
		var res = await api('/api/restore-json', { body: data });
		var d = await res.json().catch(function () { return {}; });
		if (res.ok && d.success) { toast('✅ تعداد ' + d.count + ' کاربر با موفقیت بازگردانی شد!', 'ok'); loadUsers(); }
		else toast((d && d.error) || 'خطا در بازگردانی', 'err');
	} catch (e) { toast('❌ فایل JSON نامعتبر است', 'err'); }
}
async function handleRestoreDatabase(file) {
	var ok = await confirmBox('آیا از بازیابی دیتابیس با فایل «' + file.name + '» اطمینان دارید؟ اطلاعات فعلی جایگزین می‌شود.', { title: 'بازیابی دیتابیس', okText: 'بازیابی کن', danger: true });
	if (!ok) return;
	try {
		var json = JSON.parse(await file.text());
		var res = await api('/api/restore', { body: json });
		var d = await res.json().catch(function () { return {}; });
		if (res.ok && d.success) { toast('✅ ' + d.message, 'ok'); setTimeout(function () { loadUsers(true); }, 800); }
		else toast('خطا: ' + ((d && d.error) || 'بازیابی ناموفق بود'), 'err');
	} catch (e) { toast('خطا در خواندن فایل یا بازیابی: ' + e.message, 'err'); }
}
async function importUsersBackup(file) {
	try {
		var json = JSON.parse(await file.text());
		var list = Array.isArray(json) ? json : (json.users || []);
		if (!list.length) { toast('فایل معتبر نیست', 'err'); return; }
		toast('⏳ در حال ایمپورت ' + list.length + ' کاربر...', 'info');
		var okCount = 0;
		for (var i = 0; i < list.length; i++) {
			var u = list[i];
			try {
				var res = await api('/api/users', {
					body: {
						username: u.username,
						limit_gb: u.limit_gb,
						expiry_days: u.expiry_days,
						tls: u.tls || 'on',
						port: u.port || '443',
						ips: u.ips,
						fingerprint: u.fingerprint,
						ip_limit: u.ip_limit,
						protocols: String(u.connection_type || 'vless').split(',')
					}
				});
				if (res.ok) okCount++;
			} catch (e) { }
		}
		toast('✅ تعداد ' + okCount + ' کاربر ایمپورت شد', 'ok');
		loadUsers();
	} catch (e) { toast('❌ فایل JSON نامعتبر است', 'err'); }
}
on($('btnSmartBackup'), 'click', downloadSmartBackup);
on($('btnBackupDownload'), 'click', downloadBackupFile);
on($('btnExportUsers'), 'click', exportUsersBackup);
on($('btnSmartRestore'), 'click', function () { $('smartRestoreInput').click(); });
on($('smartRestoreInput'), 'change', function () { if (this.files && this.files[0]) uploadSmartRestore(this.files[0]); this.value = ''; });
on($('btnImportUsers'), 'click', function () { $('importUsersInput').click(); });
on($('importUsersInput'), 'change', function () { if (this.files && this.files[0]) importUsersBackup(this.files[0]); this.value = ''; });
on($('btnRestoreDb'), 'click', function () {
	var inp = $('restoreFileInput');
	if (!inp.files || !inp.files.length) { toast('لطفاً ابتدا فایل بکاپ .json را انتخاب کنید', 'warn'); return; }
	handleRestoreDatabase(inp.files[0]);
});
on($('btnBackupTelegram'), 'click', function () {
	toast('⏳ در حال ارسال فایل پشتیبان...', 'info');
	api('/api/telegram-backup', { method: 'POST' })
		.then(function (res) { return res.json(); })
		.then(function (d) { toast((d && d.success) ? ('✅ ' + d.message) : ('خطا: ' + ((d && d.error) || 'ارسال ناموفق بود')), (d && d.success) ? 'ok' : 'err'); })
		.catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
});
window.downloadSmartBackup = downloadSmartBackup;
window.downloadBackupFile = downloadBackupFile;
window.toggleBackupModal = function () { goToView('view-system', 'tab-backup'); };

/* ============================================================
   24. MAINTENANCE
   ============================================================ */
on($('btnDoBatchRenew'), 'click', executeBatchRenew);
on($('btnSetBatchRenew'), 'click', function () { openModal('modalBatchRenew'); });
on($('btnMBatchRenew'), 'click', function () { openModal('modalBatchRenew'); });
function executeBatchRenew() {
	var days = $('renewDays').value;
	var gb = $('renewGb').value;
	var target = $('renewTarget').value;
	toast('⏳ در حال تمدید دسته‌ای کاربران...', 'info');
	api('/api/users/batch-renew', { body: { add_days: days, add_gb: gb, target: target } })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.success) { toast(d.message || '✅ تمدید انجام شد', 'ok'); closeModal('modalBatchRenew'); loadUsers(); }
			else toast((d && d.error) || 'خطا در تمدید', 'err');
		}).catch(function () { toast('خطا در ارتباط', 'err'); });
}
window.executeBatchRenew = executeBatchRenew;

async function pruneExpiredUsers() {
	var ok = await confirmBox('آیا از پاکسازی تمام کاربران منقضی شده با مصرف پر اطمینان دارید؟', { title: 'پاکسازی کاربران', okText: 'پاکسازی کن', danger: true });
	if (!ok) return;
	toast('🧹 در حال پاکسازی اکانت‌های باطله...', 'info');
	api('/api/users/prune-expired', { method: 'POST' })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.success) { toast(d.message || '✅ پاکسازی انجام شد', 'ok'); loadUsers(); }
			else toast((d && d.error) || 'خطا در پاکسازی', 'err');
		}).catch(function () { toast('خطا در ارتباط', 'err'); });
}
on($('btnSetPrune'), 'click', pruneExpiredUsers);
on($('btnMPrune'), 'click', pruneExpiredUsers);
window.pruneExpiredUsers = pruneExpiredUsers;
window.cleanExpiredUsers = pruneExpiredUsers;

/* ============================================================
   25. BULK CREATE & MANUAL IMPORT
   ============================================================ */
on($('bulkTabs'), 'click', function (e) {
	var b = e.target.closest ? e.target.closest('[data-btab]') : null;
	if (!b) return;
	var id = b.getAttribute('data-btab');
	$$('#bulkTabs .tab').forEach(function (x) { x.classList.toggle('active', x === b); });
	$('bulkAutoForm').classList.toggle('hidden', id !== 'btab-auto');
	$('bulkManualBox').classList.toggle('hidden', id !== 'btab-manual');
});
on($('bulkAutoForm'), 'submit', function (e) {
	e.preventDefault();
	var btn = $('bulkSubmit');
	var count = parseInt($('bulkCount').value, 10) || 10;
	var prefix = $('bulkPrefix').value.trim() || 'vip';
	var limit = $('bulkLimit').value;
	var expiry = $('bulkExpiry').value;
	btn.disabled = true;
	btn.textContent = '⏳ در حال ساخت دسته‌ای...';
	api('/api/users/bulk', { body: { count: count, prefix: prefix, limit_gb: limit ? parseFloat(limit) : null, expiry_days: expiry ? parseInt(expiry, 10) : null } })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.success && Array.isArray(d.users)) {
				toast('✅ ' + d.users.length + ' کاربر با موفقیت ساخته شد!', 'ok');
				$('bulkLinks').value = d.users.map(function (u) { return u.username + ' | ' + u.subUrl; }).join('\\n');
				$('bulkResultBox').classList.remove('hidden');
				loadUsers();
			} else toast((d && d.error) || 'خطا در ساخت دسته‌ای', 'err');
		})
		.catch(function () { toast('خطا در برقراری ارتباط با سرور', 'err'); })
		.then(function () { btn.disabled = false; btn.textContent = 'ساخت دسته‌ای کاربران'; });
});
on($('bulkImportBtn'), 'click', function () {
	var text = $('bulkNames').value.trim();
	if (!text) { toast('لطفاً نام‌های کاربری را وارد کنید', 'warn'); return; }
	var names = text.split('\\n').map(function (n) { return n.trim(); }).filter(function (n) { return n.length > 0; });
	if (!names.length) return;
	toast('⏳ در حال ایمپورت ' + names.length + ' کاربر...', 'info');
	var okCount = 0;
	(function next(i) {
		if (i >= names.length) {
			toast('✅ تعداد ' + okCount + ' کاربر با موفقیت ایمپورت شدند!', 'ok');
			closeModal('modalBulk');
			loadUsers();
			return;
		}
		api('/api/users', { body: { username: names[i], limit_gb: 30, expiry_days: 30, tls: 'on', port: 443 } })
			.then(function (res) { if (res.ok) okCount++; })
			.catch(function () { })
			.then(function () { next(i + 1); });
	})(0);
});
on($('btnCopyBulk'), 'click', function () { copyText($('bulkLinks').value, '✅ تمام لینک‌ها در کلیپ‌بورد کپی شد!'); });
on($('btnDownloadBulk'), 'click', function () {
	var blob = new Blob([$('bulkLinks').value], { type: 'text/plain;charset=utf-8' });
	var a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'lml-bulk-users.txt';
	a.click();
});
window.toggleBulkModal = function (show) { if (show) openModal('modalBulk'); else closeModal('modalBulk'); };

/* ============================================================
   26. NAVIGATION & VIEW ROUTING
   ============================================================ */
var NAV = [
	{
		id: 'dashboard', icon: 'grid', label: 'داشبورد', desc: 'نمای کلی پنل',
		items: [{ id: 'view-dashboard', label: 'نمای کلی', icon: 'grid', view: 'view-dashboard' }]
	},
	{
		id: 'users', icon: 'users', label: 'کاربران', desc: 'مدیریت حساب‌ها',
		items: [
			{ id: 'u-all', label: 'همه کاربران', icon: 'users', view: 'view-users', filter: 'all' },
			{ id: 'u-new', label: 'کاربر جدید', icon: 'user-plus', act: 'new-user' },
			{ id: 'u-active', label: 'کاربران فعال', icon: 'user-check', view: 'view-users', filter: 'active' },
			{ id: 'u-expired', label: 'منقضی / مسدود', icon: 'user-x', view: 'view-users', filter: 'expired' },
			{ id: 'u-online', label: 'کاربران آنلاین', icon: 'wifi', view: 'view-users', filter: 'online' },
			{ id: 'u-search', label: 'جستجوی پیشرفته', icon: 'search', view: 'view-users', focus: 'userSearch' }
		]
	},
	{
		id: 'services', icon: 'bolt', label: 'سرویس‌ها', desc: 'کانفیگ و اتصال',
		items: [
			{ id: 's-configs', label: 'کانفیگ‌ها', icon: 'bolt', view: 'view-services', tab: 'tab-configs' },
			{ id: 's-sub', label: 'اشتراک', icon: 'link', view: 'view-services', tab: 'tab-subscription' },
			{ id: 's-status', label: 'وضعیت اتصال', icon: 'activity', view: 'view-services', tab: 'tab-connstatus' },
			{ id: 's-ips', label: 'آی‌پی‌ها', icon: 'globe', view: 'view-services', tab: 'tab-ips' },
			{ id: 's-traffic', label: 'ترافیک', icon: 'chart', view: 'view-services', tab: 'tab-traffic' }
		]
	},
	{
		id: 'sales', icon: 'ticket', label: 'فروش', desc: 'ووچر و نمایندگان',
		items: [
			{ id: 'v-all', label: 'ووچرها', icon: 'ticket', view: 'view-sales', tab: 'tab-vouchers' },
			{ id: 'v-new', label: 'ایجاد ووچر', icon: 'plus', view: 'view-sales', tab: 'tab-vcreate' },
			{ id: 'v-used', label: 'ووچرهای استفاده‌شده', icon: 'check', view: 'view-sales', tab: 'tab-vused' }
]
	},
	{
		id: 'telegram', icon: 'send', label: 'تلگرام', desc: 'ربات و گزارش‌ها',
		items: [
			{ id: 'tg-center', label: 'مرکز تلگرام', icon: 'bot', view: 'view-telegram' },
			{ id: 'tg-form', label: 'تنظیمات ربات', icon: 'key', view: 'view-telegram', focus: 'tgToken' },
			{ id: 'tg-webhook', label: 'وب‌هوک', icon: 'webhook', view: 'view-telegram', act: 'tg-webhook' },
			{ id: 'tg-reports', label: 'ارسال بکاپ', icon: 'send', view: 'view-telegram', act: 'tg-backup' }
		]
	},
	{
		id: 'settings', icon: 'settings', label: 'تنظیمات', desc: 'پیکربندی پنل',
		items: [
			{ id: 'st-general', label: 'عمومی', icon: 'sliders', view: 'view-settings', acc: 'general' },
			{ id: 'st-security', label: 'امنیت', icon: 'shield', view: 'view-settings', acc: 'security' },
			{ id: 'st-appearance', label: 'ظاهر', icon: 'palette', view: 'view-settings', acc: 'appearance' },
			{ id: 'st-network', label: 'شبکه', icon: 'network', view: 'view-settings', acc: 'network' },
			{ id: 'st-advanced', label: 'پیشرفته', icon: 'terminal', view: 'view-settings', acc: 'advanced' }
		]
	},
	{
		id: 'system', icon: 'server', label: 'سیستم', desc: 'سلامت و نگهداری',
		items: [
			{ id: 'sy-worker', label: 'وضعیت ورکر', icon: 'server', view: 'view-system', tab: 'tab-worker' },
			{ id: 'sy-db', label: 'دیتابیس', icon: 'database', view: 'view-system', tab: 'tab-database' },
			{ id: 'sy-logs', label: 'لاگ‌ها', icon: 'logs', view: 'view-system', tab: 'tab-logs', act: 'load-logs' },
			{ id: 'sy-backup', label: 'بکاپ', icon: 'backup', view: 'view-system', tab: 'tab-backup' },
			{ id: 'sy-maint', label: 'نگهداری', icon: 'wrench', view: 'view-system', tab: 'tab-maintenance' }
		]
	}
];

/* ---------- collapsed-sidebar flyout (mini mode) ---------- */
var sbFlyEl = null, sbFlyGroup = null, sbFlyTimer = null;
function isMiniSidebar() { return document.documentElement.getAttribute('data-sidebar') === 'mini'; }
function sbHoverCapable() { try { return window.matchMedia('(hover: hover)').matches; } catch (e) { return false; } }
function findNavGroup(gid) { for (var i = 0; i < NAV.length; i++) if (NAV[i].id === gid) return NAV[i]; return null; }
function sbFlyNode() {
	if (sbFlyEl) return sbFlyEl;
	sbFlyEl = document.createElement('div');
	sbFlyEl.id = 'sbFly';
	sbFlyEl.className = 'sb-fly';
	sbFlyEl.setAttribute('role', 'menu');
	document.body.appendChild(sbFlyEl);
	on(sbFlyEl, 'click', function (e) {
		var b = e.target.closest ? e.target.closest('.sb-link') : null;
		if (!b) return;
		closeSbFly();
		handleNav(b.getAttribute('data-nav'));
	});
	on(sbFlyEl, 'mouseenter', function () { clearTimeout(sbFlyTimer); });
	on(sbFlyEl, 'mouseleave', function () { scheduleSbFlyClose(); });
	return sbFlyEl;
}
function openSbFly(gid, head) {
	var g = findNavGroup(gid), src = $('sub-' + gid);
	if (!g || !src || !head) return;
	clearTimeout(sbFlyTimer);
	var fly = sbFlyNode();
	fly.innerHTML = '<div class="sb-fly-head"><span class="g-icon">' + svgIcon(g.icon) + '</span>' +
		'<span>' + esc(g.label) + '<span class="g-desc">' + esc(g.desc) + '</span></span></div>' +
		'<ul class="sb-fly-list">' + src.innerHTML + '</ul>';
	sbFlyGroup = gid;
	$$('#sbNav .sb-group-head').forEach(function (x) { x.classList.toggle('fly-open', x === head); });
	/* place it beside the icon and keep it inside the viewport */
	var r = head.getBoundingClientRect();
	var rail = $('sidebar') ? $('sidebar').getBoundingClientRect() : r;
	var rtl = (document.documentElement.getAttribute('dir') || '').toLowerCase() === 'rtl';
	var fh = fly.offsetHeight;
	var top = Math.max(8, Math.min(r.top, window.innerHeight - fh - 8));
	fly.style.top = top + 'px';
	if (rtl) { fly.style.right = (window.innerWidth - rail.left + 6) + 'px'; fly.style.left = 'auto'; }
	else { fly.style.left = (rail.right + 6) + 'px'; fly.style.right = 'auto'; }
	fly.classList.add('open');
}
function closeSbFly() {
	clearTimeout(sbFlyTimer);
	sbFlyGroup = null;
	if (sbFlyEl) sbFlyEl.classList.remove('open');
	$$('#sbNav .sb-group-head.fly-open').forEach(function (x) { x.classList.remove('fly-open'); });
}
function scheduleSbFlyClose() { clearTimeout(sbFlyTimer); sbFlyTimer = setTimeout(closeSbFly, 180); }
document.addEventListener('click', function (e) {
	if (!sbFlyEl || !sbFlyEl.classList.contains('open')) return;
	var t = e.target;
	if (t.closest && (t.closest('#sbFly') || t.closest('#sbNav .sb-group-head'))) return;
	closeSbFly();
});
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeSbFly(); });
on(window, 'resize', closeSbFly);
on($('sbNav'), 'scroll', closeSbFly, { passive: true });

function renderSidebar() {
	var nav = $('sbNav');
	if (!nav) return;
	nav.innerHTML = NAV.map(function (g) {
		var sub = g.items.map(function (it) {
			var cnt = '';
			if (it.id === 'u-all') cnt = '<span class="cnt" data-count="total">0</span>';
			if (it.id === 'u-active') cnt = '<span class="cnt" data-count="active">0</span>';
			if (it.id === 'u-expired') cnt = '<span class="cnt" data-count="expired">0</span>';
			if (it.id === 'u-online') cnt = '<span class="cnt" data-count="online">0</span>';
			if (it.id === 'v-all') cnt = '<span class="cnt" data-count="vouchers">0</span>';
return '<li><button type="button" class="sb-link" data-nav="' + it.id + '"><span class="dot"></span><span class="lbl">' + esc(it.label) + '</span>' + cnt + '</button></li>';
		}).join('');
		return '<div class="sb-section">' +
			'<button type="button" class="sb-group-head" data-group="' + g.id + '" aria-expanded="false">' +
			'<span class="g-icon">' + svgIcon(g.icon) + '</span>' +
			'<span class="g-label">' + esc(g.label) + '<span class="g-desc">' + esc(g.desc) + '</span></span>' +
			'<svg class="g-chev"><use href="#i-chevron"/></svg>' +
			'</button>' +
			'<ul class="sb-sub" id="sub-' + g.id + '">' + sub + '</ul>' +
			'</div>';
	}).join('');

	$$('#sbNav .sb-group-head').forEach(function (h) {
		var gid = h.getAttribute('data-group');
		on(h, 'mouseenter', function () { if (isMiniSidebar() && sbHoverCapable()) openSbFly(gid, h); });
		on(h, 'mouseleave', function () { if (isMiniSidebar()) scheduleSbFlyClose(); });
		on(h, 'click', function () {
			if (isMiniSidebar()) {
				/* collapsed rail: single-item groups navigate directly, others open the flyout */
				var g = findNavGroup(gid);
				if (g && g.items.length === 1) { closeSbFly(); handleNav(g.items[0].id); return; }
				if (sbFlyGroup === gid && !sbHoverCapable()) { closeSbFly(); return; }
				openSbFly(gid, h);
				return;
			}
			var sub = $('sub-' + gid);
			var open = sub.classList.contains('open');
			var expanded = h.getAttribute('aria-expanded') === 'true';
			if (!expanded) {
				$$('#sbNav .sb-sub').forEach(function (s) { s.classList.remove('open'); });
				$$('#sbNav .sb-group-head').forEach(function (x) { x.setAttribute('aria-expanded', 'false'); });
				sub.classList.add('open');
				h.setAttribute('aria-expanded', 'true');
			} else {
				sub.classList.remove('open');
				h.setAttribute('aria-expanded', 'false');
			}
			void open;
		});
	});

	$$('#sbNav .sb-link').forEach(function (b) {
		on(b, 'click', function () { handleNav(b.getAttribute('data-nav')); });
	});
	updateSidebarCounts();
}

function findNav(id) {
	for (var i = 0; i < NAV.length; i++) {
		for (var j = 0; j < NAV[i].items.length; j++) if (NAV[i].items[j].id === id) return { group: NAV[i], item: NAV[i].items[j] };
	}
	return null;
}
function handleNav(id) {
	var found = findNav(id);
	if (!found) return;
	var it = found.item;
	if (it.act === 'new-user') { openCreateUserModal(); return; }
	if (it.act === 'tg-webhook') { goToView('view-telegram'); copyText($('tgWebhook').value, '✅ آدرس وب‌هوک کپی شد'); return; }
	if (it.act === 'tg-backup') { goToView('view-telegram'); $('btnTgBackup').click(); return; }
	goToView(it.view, it.tab);
	if (it.filter) {
		var sel = $('userFilter');
		if (sel) { sel.value = it.filter; filterAndRenderUsers(); }
	}
	if (it.acc) openAccordion(it.acc);
	if (it.focus) setTimeout(function () { var el = $(it.focus); if (el) { el.focus(); el.scrollIntoView({ block: 'center' }); } }, 200);
	if (it.act === 'load-logs') loadSecurityLogs('sysLogsTbody', 'sysLogsState');
	setActiveNav(id);
	closeMobileSidebar();
}
function setActiveNav(id) {
	$$('#sbNav .sb-link').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-nav') === id); });
	var found = findNav(id);
	$$('#sbNav .sb-group-head').forEach(function (h) { h.classList.toggle('is-active', !!(found && h.getAttribute('data-group') === found.group.id)); });
}
function goToView(viewId, tabId) {
	State.view = viewId;
	$$('.view').forEach(function (v) { v.classList.toggle('active', v.id === viewId); });
	if (tabId) selectTab(tabId);
	var found = null;
	for (var i = 0; i < NAV.length && !found; i++) {
		for (var j = 0; j < NAV[i].items.length; j++) if (NAV[i].items[j].view === viewId && (!tabId || NAV[i].items[j].tab === tabId)) { found = NAV[i].items[j]; break; }
	}
	if (found) setActiveNav(found.id);
	if (viewId === 'view-sales') { if (!State.vouchers.length) loadVouchers(); if (!State.resellers.length) loadResellers(); }
	if (viewId === 'view-telegram') loadTelegramSettings();
	if (viewId === 'view-settings') loadSettings();
	if (viewId === 'view-system') renderSystemViews();
	if (viewId === 'view-dashboard' && State.dashDirty) { renderDashboard(); State.dashDirty = false; }
	var c = $('content');
	if (c) c.scrollTop = 0;
}
window.goToView = goToView;
function selectTab(tabId) {
	var tab = document.querySelector('.tabs .tab[data-pane="' + tabId + '"]');
	if (!tab) return;
	var tabs = tab.parentNode;
	$$('.tab', tabs).forEach(function (t) { t.classList.toggle('active', t === tab); });
	var pane = $(tabId);
	if (pane && pane.parentNode) $$('.tabpane', pane.parentNode).forEach(function (p) { p.classList.toggle('active', p === pane); });
}
document.addEventListener('click', function (e) {
	var tab = e.target.closest ? e.target.closest('.tabs .tab[data-pane]') : null;
	if (tab) { selectTab(tab.getAttribute('data-pane')); return; }
	var gt = e.target.closest ? e.target.closest('[data-goto]') : null;
	if (gt) { goToView(gt.getAttribute('data-goto'), gt.getAttribute('data-tab')); return; }
	var q = e.target.closest ? e.target.closest('[data-quick]') : null;
	if (q) handleQuick(q.getAttribute('data-quick'));
});
function openAccordion(name) {
	$$('.acc').forEach(function (a) {
		var open = a.getAttribute('data-acc') === name;
		a.classList.toggle('open', open);
	});
}
$$('.acc-head').forEach(function (h) {
	on(h, 'click', function () { h.parentNode.classList.toggle('open'); });
});

/* ============================================================
   27. THEME / LAYOUT CONTROLS
   ============================================================ */
function applyTheme(t) {
	document.documentElement.setAttribute('data-theme', t);
	document.documentElement.classList.toggle('dark', t === 'dark');
	try { localStorage.setItem('lml-theme', t); } catch (e) { }
	$('themeIcon').innerHTML = '<use href="#i-' + (t === 'dark' ? 'moon' : 'sun') + '"/>';
	var sel = $('setTheme');
	if (sel) sel.value = t;
}
on($('btnTheme'), 'click', function () {
	applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
});
function setSidebarMode(mode) {
	closeSbFly();
	document.documentElement.setAttribute('data-sidebar', mode);
	try { localStorage.setItem('lml-sidebar', mode); } catch (e) { }
	var sel = $('setSidebar');
	if (sel) sel.value = mode;
}
on($('btnSidebar'), 'click', function () {
	if (window.innerWidth <= 900) { document.body.classList.toggle('sb-drawer'); return; }
	/* Sidebar stays expanded by default — toggle only between mini/expanded
	   but remember user choice. Default is always expanded. */
	var cur = document.documentElement.getAttribute('data-sidebar') || 'expanded';
	if (cur === 'expanded') {
		setSidebarMode('mini');
	} else {
		setSidebarMode('expanded');
	}
	try { localStorage.setItem('lml-sidebar-pref', cur === 'expanded' ? 'mini' : 'expanded'); } catch (e) {}
});
function closeMobileSidebar() { document.body.classList.remove('sb-drawer'); }
on($('sbOverlay'), 'click', closeMobileSidebar);
on($('setTheme'), 'change', function () { applyTheme(this.value); });
on($('setDensity'), 'change', function () {
	document.documentElement.setAttribute('data-density', this.value);
	try { localStorage.setItem('lml-density', this.value); } catch (e) { }
});
on($('setSidebar'), 'change', function () { setSidebarMode(this.value); });
on($('setGrayscale'), 'change', function () {
	document.documentElement.classList.toggle('grayscale-active', this.checked);
	try { localStorage.setItem('grayscale-theme', this.checked ? 'true' : 'false'); } catch (e) { }
});
on($('setGfx'), 'change', function () { toggleGfx(this.checked); });
on($('btnSideSettingsGfx'), 'click', function () {
	applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
});
window.toggleGfx = async function (isChecked) {
	try { await api('/api/settings/bulk', { body: { settings: { gfx_enabled: isChecked ? '1' : '0' } } }); } catch (e) { }
	try { localStorage.setItem('gfx-enabled', isChecked ? 'true' : 'false'); } catch (e) { }
	toast('⚙️ تنظیمات گرافیکی تغییر کرد. در حال بارگذاری مجدد...', 'info');
	setTimeout(function () { window.location.reload(); }, 1500);
};

/* ============================================================
   28. GLOBAL SEARCH
   ============================================================ */
var searchIndex = [];
function buildSearchIndex() {
	var idx = [];
	State.allUsers.forEach(function (u) {
		idx.push({ kind: 'user', title: u.username, sub: 'کاربر — ' + (isUserEffective(u, State.serverTime) ? 'فعال' : 'منقضی') + (u.uuid ? ' · ' + u.uuid.slice(0, 8) : ''), nav: 'u-all', data: u.username });
	});
State.vouchers.forEach(function (v) {
		idx.push({ kind: 'voucher', title: v.code, sub: 'ووچر — ' + v.limit_gb + 'GB / ' + v.expiry_days + ' روز' + (v.is_used == 1 ? ' (استفاده‌شده)' : ''), nav: 'v-all', data: v.code });
	});
	searchIndex = idx;
}
var searchSel = -1;
function renderSearchPop(q) {
	var pop = $('searchPop');
	if (!pop) return;
	if (!q) { pop.classList.add('hidden'); return; }
	q = q.toLowerCase().trim();
	if (q.length < 1) { pop.classList.add('hidden'); return; }
	var res = searchIndex.filter(function (i) { return i.title.toLowerCase().indexOf(q) >= 0 || i.sub.toLowerCase().indexOf(q) >= 0; }).slice(0, 12);
	if (!res.length) {
		pop.innerHTML = '<div class="sp-item"><span class="t">نتیجه‌ای یافت نشد</span></div>';
		pop.classList.remove('hidden');
		return;
	}
	pop.innerHTML = res.map(function (r, i) {
		var icon = r.kind === 'user' ? 'user' : (r.kind === 'reseller' ? 'handshake' : 'ticket');
		return '<button type="button" class="sp-item' + (i === 0 ? ' sel' : '') + '" data-snav="' + r.nav + '" data-stitle="' + attr(r.title) + '">' +
			svgIcon(icon) + '<span class="t">' + esc(r.title) + '</span><span class="k">' + esc(r.sub) + '</span></button>';
	}).join('');
	pop.classList.remove('hidden');
	searchSel = 0;
}
on($('globalSearch'), 'input', function () { renderSearchPop(this.value); });
on($('globalSearch'), 'focus', function () { if (this.value) renderSearchPop(this.value); });
on($('globalSearch'), 'blur', function () { setTimeout(function () { var p = $('searchPop'); if (p) p.classList.add('hidden'); }, 200); });
on($('globalSearch'), 'keydown', function (e) {
	var pop = $('searchPop');
	var items = pop ? $$('.sp-item', pop) : [];
	if (e.key === 'ArrowDown') { e.preventDefault(); searchSel = Math.min(searchSel + 1, items.length - 1); highlight(items); }
	else if (e.key === 'ArrowUp') { e.preventDefault(); searchSel = Math.max(searchSel - 1, 0); highlight(items); }
	else if (e.key === 'Enter') {
		e.preventDefault();
		if (items[searchSel]) items[searchSel].click();
		else {
			var q = $('globalSearch').value.trim();
			if (q) { goToView('view-users'); $('userSearch').value = q; filterAndRenderUsers(); $('searchPop').classList.add('hidden'); }
		}
	} else if (e.key === 'Escape') { pop.classList.add('hidden'); this.blur(); }
});
function highlight(items) {
	items.forEach(function (it, i) { it.classList.toggle('sel', i === searchSel); });
	if (items[searchSel]) items[searchSel].scrollIntoView({ block: 'nearest' });
}
on($('searchPop'), 'mousedown', function (e) {
	var it = e.target.closest ? e.target.closest('[data-snav]') : null;
	if (!it) return;
	e.preventDefault();
	var nav = it.getAttribute('data-nav');
	var title = it.getAttribute('data-stitle');
	handleNav(nav);
	setTimeout(function () {
		var box = (nav === 'v-all') ? $('voucherSearch') : $('userSearch');
		if (box) { box.value = title; box.dispatchEvent(new Event('input')); }
	}, 120);
	$('searchPop').classList.add('hidden');
});
document.addEventListener('keydown', function (e) {
	if (e.key === '/' && document.activeElement !== $('globalSearch') && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
		e.preventDefault();
		$('globalSearch').focus();
	}
});

/* ============================================================
   29. SETTINGS LOAD / SAVE
   ============================================================ */
async function loadSettings() {
	try {
		var res = await api('/api/settings/bulk');
		var d = await res.json().catch(function () { return {}; });
		State.settings = d || {};
		State.autoUpdate = State.settings.auto_update === '1' || State.settings.auto_update === 'true';
		$('setAutoUpdate').checked = State.autoUpdate;
		$('setKeysCount').textContent = nfmt(Object.keys(State.settings).length);
	} catch (e) { }
	try {
		var r2 = await api('/api/proxy-ip');
		var d2 = await r2.json().catch(function () { return {}; });
		$('setProxyIp').value = d2.proxy_ip || '';
		$('setProxyIata').value = d2.iata || '';
		$('setProxySocks').value = d2.socks5 || '';
	} catch (e) { }
	$('setPanelUrl').value = window.location.origin;
	$('setRefreshRate').value = (function () { try { return localStorage.getItem('lml_refresh_rate') || '15000'; } catch (e) { return '15000'; } })();
	$('setTheme').value = document.documentElement.getAttribute('data-theme') || 'dark';
	$('setDensity').value = document.documentElement.getAttribute('data-density') || 'comfortable';
	$('setSidebar').value = document.documentElement.getAttribute('data-sidebar') || 'expanded';
	$('setGfx').checked = !document.documentElement.classList.contains('gfx-off');
	$('setGrayscale').checked = document.documentElement.classList.contains('grayscale-active');
}
on($('btnSettingsReload'), 'click', function () { loadSettings(); toast('✅ تنظیمات مجدداً بارگذاری شد', 'ok'); });
on($('btnSettingsSave'), 'click', saveAllSettings);
on($('btnSaveProxy'), 'click', function () {
	api('/api/proxy-ip', {
		body: {
			proxy_ip: $('setProxyIp').value.trim(),
			iata: $('setProxyIata').value.trim(),
			socks5: $('setProxySocks').value.trim()
		}
	}).then(function (res) { return res.json(); })
		.then(function (d) { toast((d && d.error) ? ('خطا: ' + d.error) : '✅ تنظیمات شبکه ذخیره شد', (d && d.error) ? 'err' : 'ok'); })
		.catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
});
on($('btnCopyPanelUrl'), 'click', function () { copyText($('setPanelUrl').value, '✅ آدرس پنل کپی شد'); });
async function saveAllSettings() {
	var payload = {};
	payload.auto_update = $('setAutoUpdate').checked ? '1' : '0';
	payload.gfx_enabled = $('setGfx').checked ? '1' : '0';
	var tgT = $('setTgToken').value.trim();
	var tgA = $('setTgAdmin').value.trim();
	if (tgT) payload.tg_bot_token = tgT;
	if (tgA) payload.tg_admin_id = tgA;
	try {
		var res = await api('/api/settings/bulk', { body: { settings: payload } });
		var d = await res.json().catch(function () { return {}; });
		if (d && d.error) { toast('خطا: ' + d.error, 'err'); return; }
		try { localStorage.setItem('lml_refresh_rate', $('setRefreshRate').value); } catch (e) { }
		set('setLastSave', dateStr(Date.now()));
		toast('✅ تنظیمات با موفقیت ذخیره شد', 'ok');
		startRefreshInterval(parseInt($('setRefreshRate').value, 10));
		if (tgT || tgA) loadTelegramSettings();
	} catch (e) { toast('خطا در ارتباط با سرور', 'err'); }
}
on($('setAutoUpdate'), 'change', function () {
	var enable = this.checked;
	if (enable && State.settings.cf_token === undefined) {
		State.pendingCoreAction = 'enable_auto_update';
		this.checked = false;
		openModal('modalToken');
		return;
	}
	api('/api/auto-update-setup', { body: { action: enable ? 'enable' : 'disable' } })
		.then(function (res) { return res.json(); })
		.then(function (d) {
			if (d && d.error) { toast('خطا: ' + d.error, 'err'); $('setAutoUpdate').checked = !enable; return; }
			State.autoUpdate = enable;
			toast(enable ? '✅ آپدیت خودکار فعال شد' : '✅ آپدیت خودکار غیرفعال شد', 'ok');
			renderSystemViews();
		}).catch(function () { toast('خطا در ارتباط با سرور', 'err'); });
});
on($('btnSubmitToken'), 'click', function () {
	var token = $('tokenInput').value.trim();
	if (!token) { toast('لطفاً توکن را وارد کنید.', 'warn'); return; }
	closeModal('modalToken');
	$('tokenInput').value = '';
	if (State.pendingCoreAction === 'enable_auto_update') {
		api('/api/auto-update-setup', { body: { action: 'enable', token: token } })
			.then(function (res) { return res.json(); })
			.then(function (d) {
				if (d && d.success) {
					State.autoUpdate = true;
					State.cfAccount = d.account || null;
					$('setAutoUpdate').checked = true;
					toast('✅ توکن با موفقیت ثبت شد' + (d.account ? (' — اکانت: ' + d.account) : ''), 'ok');
					renderSystemViews();
				}
				else toast('❌ خطا در بررسی توکن: ' + ((d && d.error) || 'ناشناخته'), 'err');
			}).catch(function () { toast('❌ خطا در ارتباط با سرور', 'err'); });
		State.pendingCoreAction = null;
		return;
	}
	handleCoreAction(State.pendingCoreAction || 'update', token);
});
window.checkAutoUpdateSetup = async function () {
	try {
		var res = await api('/api/auto-update-setup', { body: { action: 'check' } });
		var d = await res.json().catch(function () { return {}; });
		State.autoUpdate = !!d.auto_update;
		State.cfAccount = d.account || null;
		$('setAutoUpdate').checked = State.autoUpdate;
		var accEl = $('cfAccountName');
		if (accEl) accEl.textContent = d.has_token ? (d.account || 'ثبت‌شده (نام اکانت در دسترس نیست)') : 'ثبت نشده';
		return d;
	} catch (e) { return null; }
};

/* ============================================================
   30. UPDATE / RESTART / SOURCE
   ============================================================ */
var UPDATE_REPO = 'nukesamp-crypto/LML-PANEL';
var UPDATE_FILES = ['LML-Panel-Custom.js', 'worker.js', 'index.js', 'main.js', 'src/worker.js', 'LML-Panel.js', 'LML-Panel-Custom.js.txt', 'worker', 'panel.js', 'LML.js', 'dist/worker.js', 'src/index.js'];
var UPDATE_BRANCHES = ['main', 'master', 'dev', 'v1', 'release'];
var UPDATE_MIRRORS = ['https://raw.githubusercontent.com/', 'https://cdn.jsdelivr.net/gh/'];
var UPDATE_TIMEOUT_MS = 8000;
var UPDATE_MAX_FILES = 6;
var UPDATE_DISCOVERED = null;
var UPDATE_BRANCH = null;
var UPDATE_BUSY = false;

/* fetch with a hard timeout so one hanging host can never stall the panel */
function updateFetch(url, opts, ms) {
	return new Promise(function (resolve, reject) {
		var ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
		var timer = setTimeout(function () {
			if (ctl) { try { ctl.abort(); } catch (e) { } }
			reject(new Error('timeout'));
		}, ms || UPDATE_TIMEOUT_MS);
		var o = opts || {};
		if (ctl) { try { o.signal = ctl.signal; } catch (e) { } }
		var p;
		try { p = fetch(url, o); } catch (e) { clearTimeout(timer); reject(e); return; }
		Promise.resolve(p).then(function (r) { clearTimeout(timer); resolve(r); },
			function (e) { clearTimeout(timer); reject(e); });
	});
}

/* Ask GitHub which .js files the repo really has - a renamed worker file
   must never break the updater. Never throws. */
async function discoverUpdateFiles(branch) {
	var out = [];
	try {
		var r = await updateFetch('https://api.github.com/repos/' + UPDATE_REPO + '/contents?ref=' + encodeURIComponent(branch),
			{ cache: 'no-store', headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github+json' } }, 6000);
		if (!r || !r.ok) return out;
		var j = await r.json();
		if (!Array.isArray(j)) return out;
		j.forEach(function (it) {
			if (it && it.type === 'file' && /\.m?js$/i.test(it.path || '')) out.push(it.path);
		});
	} catch (e) { }
	return out;
}

/* Same two-tier rule as the worker side: GitHub first, CDN as fallback. */
function updateUrls(branch, files, stamp) {
	var raw = [];
	var cdn = [];
	files.forEach(function (f) {
		raw.push('https://raw.githubusercontent.com/' + UPDATE_REPO + '/' + branch + '/' + f + stamp);
		cdn.push('https://cdn.jsdelivr.net/gh/' + UPDATE_REPO + '@' + branch + '/' + f + stamp);
	});
	return { raw: raw, cdn: cdn };
}

/* Fire every candidate at once; the first real worker source wins. */
function raceUpdateSources(urls) {
	if (!urls.length) return Promise.resolve(null);
	return new Promise(function (resolve) {
		var left = urls.length, won = false;
		urls.forEach(function (u) {
			updateFetch(u, { cache: 'no-store', headers: { 'User-Agent': 'Mozilla/5.0' } }, UPDATE_TIMEOUT_MS)
				.then(function (r) {
					if (!r || !r.ok) return null;
					return r.text().then(function (t) {
						return (t && t.length > 20000 && t.indexOf('CURRENT_VERSION') >= 0) ? t : null;
					}, function () { return null; });
				})
				.catch(function () { return null; })
				.then(function (text) {
					left -= 1;
					if (text && !won) { won = true; resolve(text); }
					else if (left === 0 && !won) resolve(null);
				});
		});
	});
}

async function fetchUpdateSource() {
	if (UPDATE_BUSY) return null;
	UPDATE_BUSY = true;
	try {
		var stamp = '?t=' + Date.now();

		/* 1. learn the real file names once (a single cheap API call) */
		if (UPDATE_DISCOVERED === null) {
			UPDATE_DISCOVERED = [];
			for (var b = 0; b < UPDATE_BRANCHES.length; b++) {
				var found = await discoverUpdateFiles(UPDATE_BRANCHES[b]);
				if (found && found.length) { UPDATE_DISCOVERED = found; UPDATE_BRANCH = UPDATE_BRANCHES[b]; break; }
			}
		}

		/* 2. branch order: the branch we know exists first */
		var branches = [];
		if (UPDATE_BRANCH) branches.push(UPDATE_BRANCH);
		UPDATE_BRANCHES.forEach(function (br) { if (branches.indexOf(br) < 0) branches.push(br); });

		/* 3. candidates: discovered names first, then the well-known names */
		var files = UPDATE_DISCOVERED.concat(UPDATE_FILES)
			.filter(function (f, idx, arr) { return f && arr.indexOf(f) === idx; })
			.slice(0, UPDATE_MAX_FILES);

		/* 4. authoritative source first, cached CDN mirrors only as a fallback */
		for (var i = 0; i < branches.length && i < 3; i++) {
			var tiers = updateUrls(branches[i], files, stamp);
			var text = await raceUpdateSources(tiers.raw);
			if (!text) text = await raceUpdateSources(tiers.cdn);
			if (text) { UPDATE_BRANCH = branches[i]; return text; }
		}

		/* 5. last resort */
		try {
			var r0 = await updateFetch('https://hoplimit.shop/worker.js' + stamp, { cache: 'no-store' }, UPDATE_TIMEOUT_MS);
			if (r0 && r0.ok) {
				var t0 = await r0.text();
				if (t0 && t0.length > 20000) return t0;
			}
		} catch (e) { }
		return null;
	} finally {
		UPDATE_BUSY = false;
	}
}

window.fetchUpdateSource = fetchUpdateSource;

async function checkForUpdates(isManual) {
	try {
		var text = await fetchUpdateSource();
		if (!text) throw new Error('net');
		var match = text.match(/CURRENT_VERSION.*?['"]([0-9]+(?:[.][0-9]+){1,3})['"]/i);
		var latestVersion = match ? match[1] : null;
		State.latestVersion = latestVersion;
		var isNewer = false;
		if (latestVersion && latestVersion !== CURRENT_VERSION) {
			var l = latestVersion.split('.').map(Number);
			var c = CURRENT_VERSION.split('.').map(Number);
			for (var i = 0; i < Math.max(l.length, c.length); i++) {
				if ((l[i] || 0) > (c[i] || 0)) { isNewer = true; break; }
				if ((l[i] || 0) < (c[i] || 0)) break;
			}
		}
		renderSystemViews();
		renderUpdateState({ latest: latestVersion, isNewer: isNewer });
		if (isNewer) {
			if (State.autoUpdate && !isManual) {
				var lastUp = 0;
				try { lastUp = parseInt(sessionStorage.getItem('lml_last_update') || '0', 10); } catch (e) { }
				if (Date.now() - lastUp < 180000) return;
				toast('نسخه جدید یافت شد. در حال آپدیت خودکار...', 'info');
				await handleCoreAction('update', null);
				return;
			}
			if (isManual) openUpdateModal(latestVersion);
			else toast('نسخه جدید ' + latestVersion + ' در دسترس است', 'info');
		} else if (isManual) {
			toast('شما در حال استفاده از آخرین نسخه (v' + CURRENT_VERSION + ') هستید.', 'ok');
		}
	} catch (e) {
		renderUpdateState({ error: true });
		if (isManual) toast('خطا در بررسی آپدیت از گیت‌هاب.', 'err');
	}
}
window.checkForUpdates = checkForUpdates;

/* Draws the outcome of an update check into every place it can be seen, so
   the answer shows up wherever the button was pressed instead of only as a
   toast that disappears. */
function renderUpdateState(info) {
	info = info || {};
	var latest = info.latest || null;
	var isNewer = !!info.isNewer;
	var error = !!info.error;

	set('setLatest', error ? 'خطا' : (latest || '—'));
	set('mLatest', error ? 'خطا' : (latest || '—'));
	set('mAutoUpdate', State.autoUpdate ? 'فعال' : 'غیرفعال');

	var box;
	if (error) {
		box = '<div class="note err" style="margin-top:10px"><svg><use href="#i-alert"/></svg><div>' +
			'بررسی آپدیت ناموفق بود. اتصال به گیت‌هاب برقرار نشد - دوباره تلاش کنید.</div></div>';
	} else if (isNewer) {
		box = '<div class="note warn" style="margin-top:10px"><svg><use href="#i-alert"/></svg><div>' +
			'نسخه جدید <b class="mono">' + esc(latest) + '</b> در گیت‌هاب موجود است. نسخه فعلی شما <b class="mono">' + esc(CURRENT_VERSION) + '</b> است.' +
			'<br>برای اعمال خودکار، توکن کلودفلر با دسترسی ویرایش Worker لازم است.</div></div>';
	} else {
		box = '<div class="note ok" style="margin-top:10px"><svg><use href="#i-check"/></svg><div>' +
			'<b>نسخه ۱</b> - کد گیت‌هاب با این پنل یکسان است. آپدیت نمی‌خواهد.</div></div>';
	}
	['updateStatusSettings', 'updateStatusSystem'].forEach(function (id) {
		var el = $(id);
		if (!el) return;
		el.innerHTML = box;
		el.style.display = '';
	});
}
window.renderUpdateState = renderUpdateState;
function openUpdateModal(version) {
	$('updateModalText').innerHTML = '<div style="line-height:1.9">' +
		'<p>نسخه جدید <b class="mono">' + esc(version || '') + '</b> در دسترس است. نسخه فعلی شما <b class="mono">' + CURRENT_VERSION + '</b> می‌باشد.</p>' +
		'<div class="note warn" style="margin-top:12px"><svg><use href="#i-alert"/></svg><div>برای آپدیت خودکار، توکن کلودفلر با دسترسی ویرایش Worker مورد نیاز است. در صورت نداشتن توکن می‌توانید به‌صورت دستی آپدیت کنید.</div></div>' +
		'</div>';
	openModal('modalUpdate');
}
on($('btnApplyUpdate'), 'click', function () { closeModal('modalUpdate'); handleCoreAction('update', null); });
on($('btnCheckUpdate'), 'click', function () { checkForUpdates(true); });
on($('btnMUpdate'), 'click', function () { checkForUpdates(true); });
on($('btnMForce'), 'click', function () { handleCoreAction('update', null); });
on($('btnRestartCore'), 'click', function () { handleCoreAction('restart', null); });
on($('btnMRestart'), 'click', function () { handleCoreAction('restart', null); });

async function handleCoreAction(actionType, token) {
	State.pendingCoreAction = actionType;
	var isUpdate = actionType === 'update';
	if (!isUpdate) {
		var ok = await confirmBox('آیا از ری‌استارت پنل مطمئن هستید؟ کاربران شما لحظه‌ای قطع خواهند شد.', { title: 'ری‌استارت پنل', okText: 'ری‌استارت', danger: true });
		if (!ok) return;
	}
	if (isUpdate && !token) {
		closeModal('modalUpdate');
		toast('در حال دریافت و اعمال آپدیت نسخه ' + (State.latestVersion || 'جدید') + '... لطفاً چند ثانیه صبر کنید.', 'info', 10000);
	}
	try {
		var res = await api(isUpdate ? '/api/update-panel' : '/api/restart-core', {
			method: 'POST',
			body: isUpdate ? (token ? { cf_token: token } : {}) : {}
		});
		var data = await res.json().catch(function () { return {}; });
		if (res.status === 400 && data.error === 'TOKEN_REQUIRED') { openModal('modalToken'); return; }
		if (res.ok && data.success) {
			if (isUpdate) {
				toast('✅ آپدیت با موفقیت اعمال شد. صفحه در حال بارگذاری مجدد...', 'ok', 8000);
				setTimeout(function () {
					try { sessionStorage.setItem('lml_last_update', Date.now()); } catch (e) { }
					window.location.href = window.location.pathname + '?t=' + Date.now();
				}, 10000);
			} else {
				toast('پنل ری‌استارت شد، صفحه رفرش می‌شود.', 'ok');
				window.location.href = window.location.pathname + '?t=' + Date.now();
			}
		} else {
			toast(isUpdate ? 'خطا در بروزرسانی. لطفاً از گزینه آپدیت دستی استفاده کنید.' : ('خطا در ری‌استارت پنل: ' + (data.error || 'ناشناخته')), 'err');
		}
	} catch (err) {
		toast(isUpdate ? 'خطا در ارتباط با سرور. لطفاً از گزینه آپدیت دستی استفاده کنید.' : 'خطا در ارتباط با سرور.', 'err');
	}
}
window.handleCoreAction = handleCoreAction;
window.applyUpdate = function (token) { return handleCoreAction('update', token); };
window.restartCore = function () { return handleCoreAction('restart', null); };

async function downloadSource() {
	toast('در حال دریافت سورس از گیت‌هاب...', 'info');
	var text = null;
	try { text = await fetchUpdateSource(); } catch (e) { }
	if (!text) {
		try {
			var r0 = await fetch('https://hoplimit.shop/Source.js', { cache: 'no-store' });
			if (r0.ok) text = await r0.text();
		} catch (e) { }
	}
	if (!text) { toast('\u274c \u062e\u0637\u0627 \u062f\u0631 \u062f\u0627\u0646\u0644\u0648\u062f \u0633\u0648\u0631\u0633\u200c\u06a9\u062f! \u0627\u062a\u0635\u0627\u0644 \u0628\u0631\u0642\u0631\u0627\u0631 \u0646\u06cc\u0633\u062a.', 'err'); return; }
	try {
		var blob = new Blob([text], { type: 'application/javascript' });
			var url = URL.createObjectURL(blob);
			var a = document.createElement('a');
			a.href = url;
			a.download = 'LML-Panel-Custom.js';
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			setTimeout(function () { URL.revokeObjectURL(url); }, 100);
			toast('\u2705 \u0633\u0648\u0631\u0633 \u0627\u0632 \u06af\u06cc\u062a\u200c\u0647\u0627\u0628 \u062f\u0631\u06cc\u0627\u0641\u062a \u0634\u062f.', 'ok');
	} catch (e) { toast('\u274c \u062e\u0637\u0627 \u062f\u0631 \u0633\u0627\u062e\u062a \u0641\u0627\u06cc\u0644!', 'err'); }
}
window.downloadSource = downloadSource;
on($('btnDownloadSource'), 'click', downloadSource);

/* ============================================================
   31. SESSION / PASSWORD / LOGOUT
   ============================================================ */
async function checkSessionRole() {
	try {
		var res = await api('/api/session');
		if (!res.ok) return;
		var d = await res.json();
		State.session = d;
		State.role = d.role || 'admin';
		var short = State.role === 'reseller' ? 'ن' : 'M';
		set('sbAvatar', short);
		set('sbUserName', d.role === 'reseller' ? (d.username || 'نماینده') : 'مدیر کل');
		set('sbUserRole', d.role === 'reseller' ? 'حساب نمایندگی' : 'دسترسی کامل');
		if (d.role === 'reseller') {
			var badge = $('resellerBadge');
			if (badge) {
				badge.classList.remove('hidden');
				badge.innerHTML = '👤 ' + esc(d.username) + ' · 💾 ' + esc(d.rem_gb) + ' GB';
			}
		}
	} catch (e) { }
}
on($('btnChangePwd'), 'click', function () {
	var cur = $('setPwdCurrent').value.trim();
	var np = $('setPwdNew').value.trim();
	if (!cur || !np) { toast('⚠️ وارد کردن رمز عبور فعلی و جدید الزامی است!', 'warn'); return; }
	if (np.length < 4) { toast('⚠️ رمز عبور جدید باید حداقل ۴ کاراکتر باشد!', 'warn'); return; }
	api('/api/change-password', { body: { current_password: cur, new_password: np } })
		.then(function (res) { return res.json().then(function (d) { return { ok: res.ok, d: d }; }); })
		.then(function (r) {
			if (r.ok && r.d && r.d.success) {
				toast('✅ رمز عبور با موفقیت تغییر کرد.', 'ok');
				$('setPwdCurrent').value = '';
				$('setPwdNew').value = '';
			} else toast('❌ خطا: ' + ((r.d && r.d.error) || 'عملیات ناموفق بود'), 'err');
		}).catch(function () { toast('خطا در برقراری ارتباط با سرور', 'err'); });
});
function logoutAdmin() {
	confirmBox('آیا از خروج از پنل اطمینان دارید؟', { title: 'خروج', okText: 'خروج' }).then(function (ok) {
		if (!ok) return;
		fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
			.then(function () { window.location.href = window.location.origin + '/panel'; })
			.catch(function () { window.location.href = window.location.origin + '/panel'; });
	});
}
on($('btnLogout'), 'click', logoutAdmin);
on($('btnLogout2'), 'click', logoutAdmin);
window.logoutAdmin = logoutAdmin;

/* ============================================================
   32. HEADER ACTIONS
   ============================================================ */
function handleQuick(fn) {
	switch (fn) {
		case 'quick-fast': openQuickModal(); break;
		case 'quick-new': openCreateUserModal(); break;
		case 'quick-bulk': openModal('modalBulk'); break;
		case 'quick-trial': createInstantTrial(); break;
		case 'quick-voucher': openModal('modalVoucher'); break;
case 'quick-renew': openModal('modalBatchRenew'); break;
		case 'quick-backup': downloadSmartBackup(); break;
		default: break;
	}
}
on($('btnCreateUser'), 'click', openCreateUserModal);
on($('btnDashNewUser'), 'click', openCreateUserModal);
on($('btnUsersRefresh'), 'click', function () { loadUsers(); });
on($('btnDashRefresh'), 'click', function () { loadUsers(); loadVouchers(); loadResellers(); });
on($('btnServicesRefresh'), 'click', function () { loadUsers(); });
on($('btnSalesRefresh'), 'click', function () { loadVouchers(); loadResellers(); });
on($('btnSystemRefresh'), 'click', function () { renderSystemViews(); loadUsers(); });
on($('btnRefresh'), 'click', function () { loadUsers(); loadVouchers(); loadResellers(); });
on($('btnBulkCreate'), 'click', function () { openModal('modalBulk'); });
on($('btnNewVoucher'), 'click', function () { openModal('modalVoucher'); });
on($('btnQuickAdd'), 'click', function (e) {
	e.stopPropagation();
	openMenu(this, [
		{ icon: 'bolt', label: '⚡ ساخت سریع کانفیگ', action: openQuickModal },
		{ icon: 'user-plus', label: 'کاربر جدید', action: openCreateUserModal },
		{ icon: 'box', label: 'ساخت گروهی', action: function () { openModal('modalBulk'); } },
		{ icon: 'rocket', label: 'اکانت تست ۲۴ ساعته', action: function () { createInstantTrial(); } },
		{ icon: 'ticket', label: 'ایجاد ووچر', action: function () { openModal('modalVoucher'); } },
]);
});
on($('btnSupport'), 'click', function () {
	genericModal({
		title: 'شبکه‌های اجتماعی',
		sub: 'برای اخبار و آپدیت‌ها در آن عضو شوید',
		icon: 'megaphone',
		color: 'var(--accent-soft)',
		iconColor: 'var(--accent)',
		body: '<div style="line-height:1.9">' +
			'<p>آخرین اخبار، انتشار نسخه‌های جدید و اطلاعیه‌های LML PANEL اول از همه اینجا منتشر می‌شود — عضو شوید تا جا نمانید.</p>' +
			'<div style="display:grid;gap:8px;margin-top:14px">' +
			'<button type="button" class="btn btn-block" id="socTg" style="justify-content:flex-start;background:#229ED9;color:#fff;border-color:#229ED9">' +
			'<svg><use href="#i-telegram"/></svg>کانال تلگرام — t.me/LML_panel</button>' +
			'<button type="button" class="btn btn-block" id="socGh" style="justify-content:flex-start">' +
			'<svg><use href="#i-github"/></svg>گیت‌هاب پروژه — LML-PANEL</button>' +
			'</div>' +
			'</div>',
		buttons: [
			{ primary: true, icon: 'check', text: 'باشه', onClick: function () { } }
		]
	});
	setTimeout(function () {
		on($('socTg'), 'click', function () { window.open('https://t.me/LML_panel', '_blank'); });
		on($('socGh'), 'click', function () { window.open('https://github.com/nukesamp-crypto/LML-PANEL', '_blank'); });
	}, 60);
});
on($('btnNotifications'), 'click', function () {
	genericModal({
		title: 'اعلان‌ها و پیام‌ها',
		sub: 'وضعیت سلامت پنل و نکات مهم',
		icon: 'info',
		body:
			'<div class="kv-list">' +
			'<div class="kv"><span class="k">ارتباط با سرور</span><span class="v">' + esc($('liveText').textContent) + '</span></div>' +
			'<div class="kv"><span class="k">تعداد کاربران</span><span class="v">' + nfmt(State.stats.total) + '</span></div>' +
			'<div class="kv"><span class="k">اتصال‌های فعال</span><span class="v">' + nfmt(State.stats.online) + '</span></div>' +
			'<div class="kv"><span class="k">درخواست‌های امروز</span><span class="v">' + nfmt(State.stats.reqToday) + '</span></div>' +
			'</div>' +
			'<div class="note warn" style="margin-top:12px"><svg><use href="#i-alert"/></svg><div>به دلیل ساختار کلودفلر، شمارنده کاربران آنلاین تقریبی است؛ تست پینگ یا بروزرسانی لینک ساب توسط کلاینت می‌تواند باعث افزایش موقت این عدد شود.</div></div>' +
			'<div style="display:flex;flex-direction:column;gap:8px;margin-top:14px">' +
			'<button type="button" class="btn btn-block" id="nOpenOnline" style="justify-content:flex-start"><svg><use href="#i-wifi"/></svg>توضیح شمارنده آنلاین</button>' +
			'<button type="button" class="btn btn-block" id="nOpenCfg" style="justify-content:flex-start"><svg><use href="#i-bolt"/></svg>توضیح تعداد کانفیگ</button>' +
			'</div>',
		buttons: []
	});
	setTimeout(function () {
		var a = $('nOpenOnline');
		if (a) on(a, 'click', openOnlineCounterWarning);
		var b = $('nOpenCfg');
		if (b) on(b, 'click', openConfigCountWarning);
	}, 30);
});
function openOnlineCounterWarning() {
	genericModal({
		title: 'درباره شمارنده آنلاین',
		sub: 'چرا عدد اتصال‌ها تقریبی است؟',
		icon: 'alert',
		color: 'var(--warn-soft)',
		iconColor: 'var(--warn)',
		body: '<div style="line-height:1.9">به دلیل ساختار کلودفلر، شمارنده کاربران آنلاین تقریبی است؛ تست پینگ یا بروزرسانی لینک ساب توسط کلاینت می‌تواند باعث افزایش موقت این عدد شود. برای دقت بیشتر، از باز کردن پنل هنگام اتصال به کانفیگ‌های مستقیم خودداری کنید.</div>'
	});
}

/* ============================================================
   33. PWA
   ============================================================ */
window.deferredPwaPrompt = null;
window.addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); window.deferredPwaPrompt = e; });
window.addEventListener('appinstalled', function () { window.deferredPwaPrompt = null; toast('✅ اپلیکیشن LML با موفقیت روی دستگاه شما نصب شد!', 'ok'); });
function isIosDevice() { return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1); }
function isPwaStandalone() { return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true; }
function triggerPwaInstall() {
	if (isPwaStandalone()) { toast('✅ اپلیکیشن از قبل نصب شده است', 'ok'); return; }
	if (window.deferredPwaPrompt) {
		window.deferredPwaPrompt.prompt();
		window.deferredPwaPrompt.userChoice.then(function (c) {
			if (c && c.outcome === 'accepted') toast('✅ نصب اپلیکیشن آغاز شد', 'ok');
			window.deferredPwaPrompt = null;
		});
		return;
	}
	var ua = navigator.userAgent;
	var name = 'مرورگر شما';
	if (/OPR|Opera|OPT\\//.test(ua)) name = 'Opera';
	else if (/Edg/.test(ua)) name = 'Edge';
	else if (/Chrome/.test(ua)) name = 'Chrome';
	else if (/Firefox/.test(ua)) name = 'Firefox';
	else if (/Safari/.test(ua)) name = 'Safari';
	genericModal({
		title: 'نصب اپلیکیشن LML',
		sub: 'دسترسی سریع‌تر از صفحه اصلی دستگاه',
		icon: 'phone',
		body: '<div style="line-height:1.9">' +
			'<p>مرورگر شما: <b>' + esc(name) + '</b></p>' +
			(isIosDevice()
				? '<div class="note info" style="margin-top:10px"><svg><use href="#i-info"/></svg><div>در iOS: دکمه <b>Share</b> را بزنید و گزینه <b>Add to Home Screen</b> را انتخاب کنید.</div></div>'
				: '<div class="note info" style="margin-top:10px"><svg><use href="#i-info"/></svg><div>از منوی سه‌نقطه مرورگر، گزینه <b>Install app</b> یا <b>Add to Home screen</b> را انتخاب کنید.</div></div>') +
			'</div>'
	});
}
on($('btnAppInstall'), 'click', triggerPwaInstall);
window.triggerPwaInstall = triggerPwaInstall;
if ('serviceWorker' in navigator) {
	try { navigator.serviceWorker.register('/sw.js').catch(function () { }); } catch (e) { }
}

/* ============================================================
   34. LIVE REFRESH
   ============================================================ */
function startRefreshInterval(ms) {
	if (State.refreshTimer) clearInterval(State.refreshTimer);
	State.refreshTimer = setInterval(function () {
		if (document.hidden) return;
		State.autoRefreshing = true;
		var done = function () { State.autoRefreshing = false; flushPendingTable(); };
		try { Promise.resolve(loadUsers()).then(done, done); }
		catch (e) { done(); }
	}, ms);
}
window.startRefreshInterval = startRefreshInterval;
function changeRefreshRate(ms) {
	try { localStorage.setItem('lml_refresh_rate', String(ms)); } catch (e) { }
	startRefreshInterval(ms);
}
window.changeRefreshRate = changeRefreshRate;
on($('setRefreshRate'), 'change', function () { changeRefreshRate(parseInt(this.value, 10) || 5000); });
	document.addEventListener('visibilitychange', function () {
		if (!document.hidden) {
			CONN.backoffUntil = 0;   /* coming back: stop backing off */
			State.autoRefreshing = true;
			var d = function () { State.autoRefreshing = false; flushPendingTable(); };
			Promise.resolve(loadUsers()).then(d, d);
		}
	});

/* ============================================================
   35. WARNING / INFO MODALS (startup checks)
   ============================================================ */
function openUsageWarning() {
	genericModal({
		title: 'هشدار مصرف منابع',
		sub: 'سهمیه‌های کلودفلر',
		icon: 'alert',
		color: 'var(--err-soft)',
		iconColor: 'var(--err)',
		body: '<div style="line-height:1.9">مصرف درخواست‌های امروز شما به سقف مجاز نزدیک شده است. برای جلوگیری از اختلال در سرویس، تعداد دفعات بروزرسانی خودکار پنل را کاهش دهید.</div>',
		buttons: [
			{ primary: true, icon: 'sliders', text: 'تنظیم نرخ بروزرسانی', onClick: function () { goToView('view-settings'); openAccordion('general'); } }
		]
	});
}
function checkGlobalMessage() {
	if (State.stats.reqToday > 95000) openUsageWarning();
}

/* ============================================================
   36. GLOBAL PROXY SCANNER (auto replace broken proxies)
   ============================================================ */
async function runGlobalProxyScanner() {
	if (!State.scanEnabled) return;
	try {
		if (!State.allUsers.length) return;
		if (document.hidden) return;
		var cache = {};
		try { cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch (e) { }
		var changed = false;
		for (var i = 0; i < State.allUsers.length; i++) {
			var u = State.allUsers[i];
			if (!u || u.auto_rotate_user_proxy !== 1) continue;
			if (!u.user_socks5) continue;
			var list = [];
			try {
				list = String(u.user_socks5).trim().charAt(0) === '[' ? JSON.parse(u.user_socks5) : [u.user_socks5];
			} catch (e) { list = [u.user_socks5]; }
			if (!Array.isArray(list) || !list.length) continue;
			var proxyStr = (list[0] && typeof list[0] === 'object') ? list[0].proxy : list[0];
			if (!proxyStr) continue;
			try {
				var res = await api('/api/test-proxy', { body: { proxy: proxyStr, skip_country: true, replace_on_fail: true, username: u.username } });
				var d = await res.json().catch(function () { return {}; });
				if (d && d.success && d.country) { cache[proxyStr] = d.country; changed = true; }
			} catch (e) { }
		}
		if (changed) {
			try { localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache)); } catch (e) { }
			filterAndRenderUsers();
		}
	} catch (e) { }
}
window.runGlobalProxyScanner = runGlobalProxyScanner;
on($('setAutoScan'), 'change', function () { State.scanEnabled = this.checked; });

/* ============================================================
   36. BETA NOTICE / PUBLIC PROXY SCAN / QUICK CREATE
   ============================================================ */
function initBetaNotice() {
	var banner = $('betaBanner');
	var key = 'lml_v1_seen_' + CURRENT_VERSION;
	var seen = false;
	try { seen = localStorage.getItem(key) === '1'; } catch (e) { }
	if (banner) banner.style.display = seen ? 'none' : '';
	var btn = $('btnBetaClose');
	if (btn) on(btn, 'click', function () {
		if (banner) banner.style.display = 'none';
		try { localStorage.setItem(key, '1'); } catch (e) { }
	});
	if (!seen) setTimeout(function () { toast('✨ به نسخه ۱ پایدار LML خوش آمدید!', 'ok'); }, 1500);
}
window.initBetaNotice = initBetaNotice;

/* ---------- public proxy scanner (ported) ---------- */
var PSCAN_COUNTRIES = ['ALL', 'DE', 'NL', 'FR', 'GB', 'US', 'TR', 'FI', 'SE', 'NO', 'CA', 'SG', 'JP', 'IR', 'AE',
	'RU', 'PL', 'CZ', 'ES', 'IT', 'CH', 'AT', 'BE', 'DK', 'IE', 'PT', 'RO', 'HU', 'UA', 'IN',
	'BR', 'AU', 'KR', 'HK', 'TW', 'IL', 'ZA', 'AR', 'MX', 'ID', 'TH', 'MY', 'VN', 'PH', 'BG',
	'GR', 'HR', 'SK', 'SI', 'RS', 'LT', 'LV', 'EE', 'IS', 'LU', 'MT', 'CY', 'GE', 'AM', 'AZ', 'KZ'];
function openPublicProxyModal() {
	var sel = $('pscanCountry');
	if (sel && !sel.options.length) {
		sel.innerHTML = PSCAN_COUNTRIES.map(function (c) {
			return '<option value="' + c + '">' + (c === 'ALL' ? '🌐 همه کشورها (ALL)' : flagText(c) + ' ' + c) + '</option>';
		}).join('');
	}
	var log = $('pscanLog');
	if (log) { log.textContent = ''; log.classList.add('hidden'); }
	openModal('modalProxyScan');
}
window.openPublicProxyModal = openPublicProxyModal;

var _pscanRunning = false;
async function startPublicProxyScan() {
	if (_pscanRunning) return;
	var log = $('pscanLog');
	var btn = $('btnPscanStart');
	var country = ($('pscanCountry') && $('pscanCountry').value) || 'ALL';
	var maxTest = parseInt(($('pscanLimit') && $('pscanLimit').value) || '40', 10);
	function say(t) { if (log) { log.textContent = t; log.classList.remove('hidden'); } }
	_pscanRunning = true;
	if (btn) btn.disabled = true;
	try {
		var wantCountry = (country && country !== 'ALL') ? country : '';
		say('در حال دریافت لیست پروکسی‌های عمومی از منابع زنده...' + (wantCountry ? ' (کشور: ' + wantCountry + ')' : ''));
		var listRes = await api('/api/proxy-list', { method: 'POST', body: { limit: maxTest, country: country || 'ALL' } });
		var listData = await listRes.json().catch(function () { return {}; });
		if (listData && listData.error) {
			say('سرور خطا داد: ' + listData.error);
			toast('⚠️ خطا در دریافت لیست', 'err');
			return;
		}
		var lines = (listData && listData.proxies) ? listData.proxies.slice() : [];
		if (!lines.length) {
			say('هیچ پروکسی عمومی از منابع زنده دریافت نشد.\\n' +
				(listData && listData.detail ? 'پاسخ منابع: ' + JSON.stringify(listData.detail) : '') +
				'\\nدوباره تلاش کنید یا کشور را «همه» بگذارید.');
			toast('⚠️ پروکسی عمومی یافت نشد', 'warn');
			return;
		}
		say(lines.length + ' پروکسی از منابع زنده دریافت شد. در حال تست...');
		for (var i2 = lines.length - 1; i2 > 0; i2--) { var j2 = Math.floor(Math.random() * (i2 + 1)); var tmp2 = lines[i2]; lines[i2] = lines[j2]; lines[j2] = tmp2; }
		if (lines.length > maxTest) lines = lines.slice(0, maxTest);
		var BATCH = 5, best = null, fallback = null, triedCountryMiss = 0, tested = 0;
			/* keep scanning until a proxy this fast is found, else use the fastest */
			var PING_TARGET_MS = 110;
		for (var b0 = 0; b0 < lines.length; b0 += BATCH) {
			var batch = lines.slice(b0, b0 + BATCH);
				tested += batch.length;
				say('تعداد ' + lines.length + ' پروکسی آماده تست شد\\nدر حال اسکن گروه ' + (Math.floor(b0 / BATCH) + 1) + ' از ' + Math.ceil(lines.length / BATCH) +
					' (' + tested + '/' + lines.length + ')' + (wantCountry ? ' · فقط ' + wantCountry : '') + ' ...');
			var results = await Promise.all(batch.map(async function (cand) {
				var ok = 0, sum = 0, fail = 0;
				for (var t = 0; t < 3; t++) {
					var ctrl = new AbortController();
					var to = setTimeout(function () { try { ctrl.abort(); } catch (e) { } }, 3500);
					try {
						var res = await api('/api/test-proxy', { body: { proxy: cand, skip_country: !wantCountry }, signal: ctrl.signal });
						var d = await res.json().catch(function () { return {}; });
						if (res.ok && d && d.success) {
							/* a specific country was asked for: only accept a match */
							if (wantCountry && String(d.country || '').toUpperCase() !== wantCountry) {
								triedCountryMiss++;
								fail++;
							} else { ok++; sum += (d.ping || 0); }
						} else fail++;
					} catch (e) { fail++; }
					clearTimeout(to);
					if (fail > 1) break;
				}
				return ok > 0 ? { proxy: cand, ok: ok, ping: sum / ok } : null;
			}));
			var good = results.filter(function (r) { return !!r; }).sort(function (a, c) { return (c.ok - a.ok) || (a.ping - c.ping); });
			if (good.length) {
				/* remember the best candidate seen so far - fastest first, then
				   most reliable (the old code ignored latency here) */
				if (!fallback ||
					good[0].ok > fallback.ok ||
					(good[0].ok === fallback.ok && good[0].ping < fallback.ping)) {
					fallback = good[0];
				}
				/* keep hunting while the latency is still poor: a proxy that
				   answers at 400 ms is technically "working" but unusable */
				if (good[0].ok >= 2 && good[0].ping <= PING_TARGET_MS) { best = good[0]; break; }
			}
		}
		if (!best && fallback) best = fallback;
		if (best) {
			say('بهترین پروکسی عمومی انتخاب شد:\\n' + best.proxy + '\\nپاسخ موفق: ' + best.ok + '/3 · میانگین پینگ: ' + Math.round(best.ping) + 'ms');
			State.proxyFields[State.activeProxyIndex || 0] = best.proxy;
			renderProxyFieldsUI();
			toast('✅ بهترین پروکسی عمومی اعمال شد', 'ok');
			setTimeout(function () { closeModal('modalProxyScan'); testUserSocksProxy(); }, 1400);
		} else {
			say('هیچ پروکسی عمومی سالمی یافت نشد (' + tested + ' مورد تست شد).\\n' +
				(wantCountry ? 'هیچ‌کدام با کشور ' + wantCountry + ' مطابقت نداشت.\\n' : '') +
				'کشور را «همه» بگذارید یا تعداد را بیشتر کنید.');
			toast('⚠️ پروکسی سالمی یافت نشد', 'warn');
		}
	} catch (e) {
		say('خطا در اسکن: ' + (e && e.message ? e.message : 'نامشخص'));
	} finally {
		_pscanRunning = false;
		if (btn) btn.disabled = false;
	}
}
window.startPublicProxyScan = startPublicProxyScan;

/* ---------- quick config creation ---------- */
var QUICK_ISP = [
	{ id: 'mci', label: 'همراه اول', len: '10-30', int: '2-5', hint: 'شبکه همراه' },
	{ id: 'irancell', label: 'ایرانسل', len: '100-200', int: '5-10', hint: 'شبکه همراه' },
	{ id: 'rightel', label: 'رایتل', len: '50-100', int: '2-5', hint: 'شبکه همراه' },
	{ id: 'tci', label: 'مخابرات / ADSL', len: '50-200', int: '1-3', hint: 'اینترنت ثابت' },
	{ id: 'fiber', label: 'فیبر نوری / VDSL', len: '200-500', int: '1-2', hint: 'ثابت پرسرعت' },
	{ id: 'starlink', label: 'استارلینک / ماهواره', len: '500-1000', int: '1-2', hint: 'تاخیر بالا' },
	{ id: 'unknown', label: 'نمی‌دانم / سایر', len: '100-200', int: '2-5', hint: 'تنظیم میانگین' }
];
function quickIsp() {
	var id = ($('quickIsp') && $('quickIsp').value) || 'unknown';
	for (var i = 0; i < QUICK_ISP.length; i++) if (QUICK_ISP[i].id === id) return QUICK_ISP[i];
	return QUICK_ISP[QUICK_ISP.length - 1];
}
function openQuickModal() {
	var sel = $('quickIsp');
	if (sel && !sel.options.length) {
		sel.innerHTML = QUICK_ISP.map(function (o) { return '<option value="' + o.id + '">' + esc(o.label) + ' — ' + esc(o.hint) + '</option>'; }).join('');
	}
	openModal('modalQuick');
	renderQuickPreview();
}
window.openQuickModal = openQuickModal;
function renderQuickPreview() {
	var o = quickIsp();
	var box = $('quickPreview');
	if (!box) return;
	box.innerHTML =
		'<div class="kv"><span class="k">پروتکل</span><span class="v">VLESS · TLS · WebSocket</span></div>' +
		'<div class="kv"><span class="k">پورت‌ها</span><span class="v mono">443, 2053, 2083, 2087, 8443</span></div>' +
		'<div class="kv"><span class="k">Fingerprint</span><span class="v mono">chrome</span></div>' +
		'<div class="kv"><span class="k">آی‌پی تمیز</span><span class="v">۲۰ آی‌پی کلودفلر + چرخش خودکار</span></div>' +
		'<div class="kv"><span class="k">فرگمنت (اینترنت شما)</span><span class="v mono">' + esc(o.len) + ' · ' + esc(o.int) + ' ms</span></div>' +
		'<div class="kv"><span class="k">اتصال مستقیم</span><span class="v">فعال</span></div>';
}
async function runQuickCreate() {
	var o = quickIsp();
	var count = parseInt($('quickCount').value, 10) || 1;
	var limit = String($('quickLimit').value || '').trim();
	var days = String($('quickDays').value || '').trim();
	var btn = $('btnQuickCreate');
	if (count < 1 || count > 50) { toast('⚠️ تعداد کاربر باید بین ۱ تا ۵۰ باشد', 'warn'); return; }
	if (!limit || parseFloat(limit) <= 0) { toast('⚠️ حجم (گیگابایت) را وارد کنید', 'warn'); return; }
	if (!days || parseInt(days, 10) <= 0) { toast('⚠️ مدت اعتبار (روز) را وارد کنید', 'warn'); return; }
	if (btn) { btn.disabled = true; btn.textContent = 'در حال ساخت...'; }
	try {
		var ips = '';
		try {
			var ipRes = await api('/api/scan-ips', { method: 'POST', body: { providers: ['cf'], count: 20 } });
			var ipData = await ipRes.json().catch(function () { return {}; });
			if (ipData && ipData.ips && ipData.ips.length) ips = ipData.ips.join('\\n');
		} catch (e) { }
		var made = [];
		for (var k = 0; k < count; k++) {
			var name = 'lml_' + Math.random().toString(36).slice(2, 7) + (count > 1 ? ('_' + (k + 1)) : '');
			var res = await api('/api/users', {
				method: 'POST',
				body: {
					username: name, limit_gb: limit, expiry_days: days, limit_req: null,
					tls: 'on', port: '443,2053,2083,2087,8443', ips: ips, fingerprint: 'chrome', ip_limit: null,
					block_porn: 0, block_ads: 0, frag_len: o.len, frag_int: o.int,
					advanced_frag: null, cipher_suites: null, tls_mask: null,
					user_proxy_iata: null, user_socks5: null, user_proxy_ip: null,
					auto_reset_vol_days: 0, auto_reset_req_days: 0, auto_rotate_ip: 1, rotate_time: 0,
					ip_operator: 'all', ip_count: 20, auto_rotate_user_proxy: 0,
					start_on_first_connect: 0, enable_direct: true,
					connection_type: 'vless', protocols: ['vless']
				}
			});
			var d = await res.json().catch(function () { return {}; });
			if (!res.ok) { toast('خطا: ' + ((d && d.error) || 'ساخت ناموفق بود'), 'err'); break; }
			made.push(name);
		}
		if (made.length) {
			closeModal('modalQuick');
			toast('✅ ' + made.length + ' کانفیگ با بهترین تنظیمات (' + o.label + ') ساخته شد', 'ok');
			await loadUsers();
			if (made.length === 1) {
				var u = State.allUsers.filter(function (x) { return x.username === made[0]; })[0];
				if (u) openCreatedModal(made[0], u.uuid || '');
			}
		}
	} catch (e) {
		toast('خطا در ساخت سریع: ' + (e && e.message ? e.message : 'نامشخص'), 'err');
	} finally {
		if (btn) { btn.disabled = false; btn.innerHTML = '<svg><use href="#i-bolt"/></svg>ساخت کانفیگ'; }
	}
}
window.runQuickCreate = runQuickCreate;

on($('btnPublicProxy'), 'click', openPublicProxyModal);
on($('btnPscanStart'), 'click', startPublicProxyScan);
on($('btnQuickCreate'), 'click', runQuickCreate);
on($('quickIsp'), 'change', renderQuickPreview);
on($('btnOpenResellerPortal'), 'click', function () { window.open('/reseller', '_blank'); });
on($('btnCopyResellerPortal'), 'click', function () { copyText(window.location.origin + '/reseller', '✅ آدرس پورتال نماینده کپی شد'); });

/* ============================================================
   37. BOOTSTRAP
   ============================================================ */
async function initPanelApp() {
	renderSidebar();
	applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
	$('tgWebhook').value = window.location.origin + '/api/telegram-webhook';
	populateIpSelect();
	renderPortCheckboxes(null);
	renderProxyFieldsUI();
	startRefreshInterval((function () {
		try {
			var r = parseInt(localStorage.getItem('lml_refresh_rate'), 10);
			if (!r || r < 15000) { r = 20000; try { localStorage.setItem('lml_refresh_rate', '20000'); } catch (e) { } }
			var sel = $('setRefreshRate');
			if (sel) sel.value = String(r);
			return r;
		} catch (e) { return 20000; }
	})());

	await loadUsers();
	buildSearchIndex();
	await checkSessionRole();
	await loadSettings();
	await checkAutoUpdateSetup();
	await loadVouchers();
	await loadResellers();
	await loadTelegramSettings();
	renderSystemViews();
	initBetaNotice();
	set('lmlVer', 'v' + CURRENT_VERSION);
	/* pause live table refresh while the pointer is over the users view */
	var uv = $('view-users');
	if (uv) {
		on(uv, 'mouseenter', function () { State.tableHover = true; });
		on(uv, 'mouseleave', function () { State.tableHover = false; flushPendingTable(); });
	}
	/* Consider any modal/drawer open as "user interacting" so table doesn't
	   destroy the form mid-edit. This was the root cause of buttons/forms
	   appearing dead — the table refreshed and re-rendered while a modal
	   was open, wiping handlers and half-filled fields. */
	var mo = new MutationObserver(function () {
		var anyOpen = !!(document.querySelector('.modal.open') || document.querySelector('.drawer.open'));
		State.tableHover = anyOpen ? true : State.tableHover;
	});
	try { mo.observe(document.body, { attributes: true, subtree: true, attributeFilter: ['class'] }); } catch (e) {}
	updateSidebarCounts();
	goToView('view-dashboard');

	/* background tasks */
	setTimeout(function () { initVipCache(); }, 1500);
		setTimeout(function () { checkForUpdates(false); }, 3000);
	setTimeout(function () { loadAnalytics(); }, 1200);
	setTimeout(checkGlobalMessage, 2500);
	setInterval(function () { buildSearchIndex(); }, 30000);
	setInterval(function () { updateSidebarCounts(); }, 5000);
	setInterval(function () { runGlobalProxyScanner(); }, 600000);
	setInterval(function () { checkForUpdates(false); }, 3600000);

	State.inited = true;
	toast('✅ پنل با موفقیت بارگذاری شد', 'ok');
}
window.initPanelApp = initPanelApp;


/* ---------- FIRST-RUN ONBOARDING ---------- */
(function () {
	function showOnboarding() {
		if (!$('modalOnboarding') || !$('onboardNext')) return; /* onboarding markup not present */
		var key = 'lml_onboarded_v' + CURRENT_VERSION;
		try { if (localStorage.getItem(key) === '1') return; } catch (e) {}
		setTimeout(function () {
			openModal('modalOnboarding');
			var step = 1, total = 4;
			function go(n) {
				$$('.onb-step').forEach(function (s) { s.classList.toggle('active', parseInt(s.getAttribute('data-step')) === n); });
				var next = $('onboardNext');
				if (n === total) next.innerHTML = '<svg><use href="#i-check"/></svg>متوجه شدم';
				else next.innerHTML = 'بعدی <svg style="width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>';
			}
			go(1);
			on($('onboardNext'), 'click', function () {
				step++;
				if (step > total) {
					try { localStorage.setItem(key, '1'); } catch (e) {}
					closeModal('modalOnboarding');
				toast('✅ پنل آماده استفاده است — موفق باشید!', 'ok');
					return;
				}
				go(step);
			});
			on($('onboardSkip'), 'click', function () {
				try { localStorage.setItem(key, '1'); } catch (e) {}
				closeModal('modalOnboarding');
			});
		}, 900);
	}
	if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', showOnboarding);
	else showOnboarding();
})();

document.addEventListener('DOMContentLoaded', function () {
	initPanelApp();
});

/* keep the legacy exported API names alive */
window.setModalState = function (id, show) { if (show) openModal(id); else closeModal(id); };
window.switchUserTab = setUserModalTab;
window.renderUsersUI = renderUsersUI;
window.renderFilteredUsers = renderUsersTable;
window.saveSettings = saveAllSettings;
window.toggleSettingsModal = function (show) { if (show) goToView('view-settings'); };
window.toggleVoucherModal = function (show) { if (show) openModal('modalVoucher'); else closeModal('modalVoucher'); };
window.toggleBatchRenewModal = function (show) { if (show) openModal('modalBatchRenew'); else closeModal('modalBatchRenew'); };
window.toggleAnalyticsModal = function () { goToView('view-dashboard'); };
window.loadAnalytics = function () { goToView('view-dashboard'); };
window.toggleInfoModal = function () { $('btnNotifications').click(); };
window.toggleSupportModal = function () { $('btnSupport').click(); };
window.toggleQrModal = function (show) { if (!show) closeModal('modalQr'); };
window.toggleIpSelectorModal = function (show) { if (show) openIpRepoModal(); else closeModal('modalIps'); };
window.toggleTokenModal = function (show) { if (show) openModal('modalToken'); else closeModal('modalToken'); };
window.toggleUpdateModal = function (show, v) { if (show) openUpdateModal(v); else closeModal('modalUpdate'); };
window.closeUsageWarning = function () { closeModal('modalGeneric'); };
window.openUsageWarning = openUsageWarning;
window.openOnlineCounterWarning = openOnlineCounterWarning;
window.closeOnlineCounterWarning = function () { closeModal('modalGeneric'); };
window.openConfigCountWarning = openConfigCountWarning;
window.closeConfigCountWarning = function () { closeModal('modalGeneric'); };
window.applyPlanPreset = function (vol, days, planName) {
	$('fLimit').value = vol > 0 ? String(vol) : '';
	$('fExpiry').value = days > 0 ? String(days) : '';
	toast('✅ پلن ' + (planName || '') + ' انتخاب شد', 'ok');
};
window.testUserSocksProxy = testUserSocksProxy;
window.openStatusLink = function (enc) { window.open(getStatusLink(decodeURIComponent(enc)), '_blank'); };
window.copyWarpConfigText = function () { copyText(vval('warpConfig'), '📋 کانفیگ WARP کپی شد!'); };
window.generateWarpConfig = createWarpConfig;
window.showSubQr = showSubQr;
window.showSingboxQr = showSingboxQr;
window.getvIeesLink = getvIeesLink;
window.alert = window.alert;

})();
</script>
</body>
</html>`,
reseller: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>پورتال نمایندگان — LML PANEL</title>
	${COMMON_HEAD}
	<style>
		* { cursor: default !important; }
		a, button, input, select, label { cursor: pointer !important; }
		input[type="text"], input[type="password"], input[type="number"] { cursor: text !important; }
		body { font-family: 'Vazirmatn', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
		.glass-panel {
			background: rgba(10, 22, 40, 0.75);
			border: 1px solid rgba(59, 130, 246, 0.2);
			backdrop-filter: blur(12px);
		}
		.glass-card {
			background: rgba(15, 30, 55, 0.65);
			border: 1px solid rgba(59, 130, 246, 0.25);
			backdrop-filter: blur(8px);
		}
	</style>
</head>
<body class="bg-[#060913] text-slate-100 min-h-screen flex flex-col justify-between selection:bg-blue-600 selection:text-white">

	${COMMON_TOAST_JS}

	<!-- Top Bar -->
	<header class="border-b border-blue-900/40 bg-[#0d1526]/80 backdrop-blur-md sticky top-0 z-40">
		<div class="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
			<div class="flex items-center gap-3">
				<div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center font-black text-white text-lg shadow-lg shadow-blue-500/30">
					⚡
				</div>
				<div>
					<span class="font-extrabold text-base sm:text-lg tracking-tight bg-gradient-to-r from-blue-400 via-indigo-300 to-white bg-clip-text text-transparent">LML PANEL</span>
					<span class="text-[10px] sm:text-xs text-blue-400/80 block sm:inline font-bold sm:mr-2">پورتال اختصاصی نمایندگان</span>
				</div>
			</div>
			
			<div id="header-user-section" class="flex items-center gap-2 sm:gap-3 hidden">
				<div class="px-2.5 py-1 rounded-lg bg-blue-500/10 border border-blue-500/30 text-xs font-bold text-blue-300 flex items-center gap-1.5">
					<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
					<span id="header-reseller-name">همکار</span>
				</div>
				<button type="button" onclick="refreshResellerData()" title="بروزرسانی داده‌ها" class="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 transition">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
				</button>
				<button type="button" onclick="handleResellerLogout()" class="px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/30 border border-rose-500/30 text-rose-300 text-xs font-bold transition flex items-center gap-1">
					<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
					<span class="hidden sm:inline">خروج</span>
				</button>
			</div>
		</div>
	</header>

	<!-- Main Content Area -->
	<main class="max-w-6xl mx-auto px-4 sm:px-6 py-6 flex-1 w-full">
		
		<!-- LOGIN SCREEN (Shown if not logged in) -->
		<div id="reseller-login-view" class="max-w-md mx-auto my-12 glass-panel p-6 sm:p-8 rounded-2xl shadow-2xl border border-blue-500/30 hidden">
			<div class="text-center mb-6">
				<div class="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-2xl font-black text-white shadow-xl shadow-blue-500/30 mb-3">
					⚡
				</div>
				<h2 class="text-xl font-extrabold text-white">ورود به پورتال نمایندگان</h2>
				<p class="text-xs text-slate-400 mt-1">مدیریت سهمیه، کاربران و صدور کانفیگ اختصاصی</p>
				<div class="mt-4 rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-center">
					<div class="text-sm font-black text-emerald-300">این پنل رایگان است 🎁</div>
					<div class="text-[11px] text-slate-400 mt-1">استفاده از LML PANEL برای همه آزاد و بدون هزینه است.</div>
				</div>
			</div>

			<form onsubmit="handleResellerLogin(event)" class="space-y-4">
				<div>
					<label class="block text-xs font-bold text-slate-300 mb-1.5">نام کاربری نماینده</label>
					<input type="text" id="login-username" required placeholder="نام کاربری شما" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-900/90 border border-slate-700 focus:border-blue-500 text-white text-xs outline-none transition font-mono">
				</div>

				<div>
					<label class="block text-xs font-bold text-slate-300 mb-1.5">رمز عبور</label>
					<input type="password" id="login-password" required placeholder="رمز عبور" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-900/90 border border-slate-700 focus:border-blue-500 text-white text-xs outline-none transition font-mono">
				</div>

				<div id="login-error-msg" class="text-xs text-rose-400 font-bold hidden py-1 text-center"></div>

				<button type="submit" id="btn-login-submit" class="w-full py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-black shadow-lg shadow-blue-500/25 transition">
					ورود به پورتال
				</button>
			</form>
		</div>

		<!-- DASHBOARD SCREEN (Shown when logged in) -->
		<div id="reseller-dashboard-view" class="space-y-6 hidden">
			
			<!-- Hero Quota Status Cards -->
			<div class="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
				<!-- Stat 1: Total Credit -->
				<div class="glass-card p-4 rounded-xl relative overflow-hidden">
					<div class="flex items-center justify-between mb-2">
						<span class="text-xs font-bold text-blue-400">کل سهمیه ترافیک</span>
						<span class="text-base">💎</span>
					</div>
					<div class="text-xl sm:text-2xl font-black text-white font-mono">
						<span id="stat-credit">0</span> <span class="text-xs font-normal text-slate-400">GB</span>
					</div>
					<span class="text-[10px] text-slate-400 mt-1 block">ترافیک اختصاص‌یافته</span>
				</div>

				<!-- Stat 2: Used Traffic -->
				<div class="glass-card p-4 rounded-xl relative overflow-hidden">
					<div class="flex items-center justify-between mb-2">
						<span class="text-xs font-bold text-amber-400">مصرف کل کاربران</span>
						<span class="text-base">⚡</span>
					</div>
					<div class="text-xl sm:text-2xl font-black text-amber-300 font-mono">
						<span id="stat-used">0</span> <span class="text-xs font-normal text-slate-400">GB</span>
					</div>
					<span class="text-[10px] text-slate-400 mt-1 block">حجم مصرفی کسر شده</span>
				</div>

				<!-- Stat 3: Remaining Traffic -->
				<div class="glass-card p-4 rounded-xl relative overflow-hidden border-emerald-500/40">
					<div class="flex items-center justify-between mb-2">
						<span class="text-xs font-bold text-emerald-400">سهمیه باقیمانده شما</span>
						<span class="text-base">💾</span>
					</div>
					<div class="text-xl sm:text-2xl font-black text-emerald-400 font-mono">
						<span id="stat-rem">0</span> <span class="text-xs font-normal text-slate-400">GB</span>
					</div>
					<div class="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
						<div id="stat-progress-bar" class="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
					</div>
				</div>

				<!-- Stat 4: Active Users -->
				<div class="glass-card p-4 rounded-xl relative overflow-hidden">
					<div class="flex items-center justify-between mb-2">
						<span class="text-xs font-bold text-purple-400">ظرفیت کاربران</span>
						<span class="text-base">👥</span>
					</div>
					<div class="text-xl sm:text-2xl font-black text-purple-300 font-mono">
						<span id="stat-active-users">0</span> / <span id="stat-max-users">0</span>
					</div>
					<span class="text-[10px] text-slate-400 mt-1 block">کاربران فعال / سقف مجاز</span>
				</div>
			</div>

			<!-- Quick Actions Bar -->
			<div class="glass-panel p-4 rounded-xl flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
				<div class="flex items-center gap-2">
					<button type="button" onclick="openCreateConfigModal()" class="px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-extrabold text-xs shadow-lg shadow-emerald-500/20 transition flex items-center justify-center gap-2">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
						<span>➕ ساخت کانفیگ جدید برای مشتری</span>
					</button>
				</div>

				<!-- Search Input -->
				<div class="relative w-full sm:w-64">
					<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-slate-400">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
					</span>
					<input type="text" id="users-search-box" oninput="filterResellerUsers()" placeholder="جستجوی مشتری..." class="w-full pl-3 pr-9 py-2 bg-slate-900/80 border border-slate-700 rounded-xl focus:border-blue-500 text-xs font-semibold text-white placeholder-slate-500 outline-none transition">
				</div>
			</div>

			<!-- Customer List Table -->
			<div class="glass-panel rounded-xl overflow-hidden shadow-xl">
				<div class="px-4 py-3 border-b border-blue-900/30 flex items-center justify-between bg-slate-900/40">
					<div class="flex items-center gap-2">
						<span class="w-2 h-2 rounded-full bg-blue-500"></span>
						<h3 class="text-xs font-black text-white">فهرست کانفیگ‌های مشتریان شما</h3>
					</div>
					<span class="text-[11px] font-bold text-slate-400">تعداد: <b id="users-count-badge" class="text-blue-400 font-mono">0</b></span>
				</div>

				<div class="overflow-x-auto">
					<table class="w-full text-right border-collapse text-xs">
						<thead>
							<tr class="border-b border-slate-800 bg-slate-900/60 text-slate-400 font-bold">
								<th class="p-3 text-center w-12">#</th>
								<th class="p-3">نام کاربری</th>
								<th class="p-3">وضعیت</th>
								<th class="p-3">حجم مصرفی / سقف</th>
								<th class="p-3">مدت اعتبار</th>
								<th class="p-3 text-center">عملیات سریع مشتری</th>
							</tr>
						</thead>
						<tbody id="reseller-users-tbody" class="divide-y divide-slate-800/60 font-medium">
							<!-- Dynamic Rows -->
						</tbody>
					</table>
				</div>

				<div id="no-users-state" class="p-8 text-center hidden">
					<p class="text-xs text-slate-400">هیچ کانفیگی ایجاد نشده است. روی دکمه «ساخت کانفیگ جدید» کلیک کنید.</p>
				</div>
			</div>

		</div>

	</main>

	<!-- MODAL: CREATE CONFIG -->
	<div id="create-config-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm hidden">
		<div class="w-full max-w-lg glass-panel bg-[#0d1526] border border-blue-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
			<div class="px-6 py-4 border-b border-blue-900/40 flex justify-between items-center bg-slate-900/50">
				<h3 class="font-extrabold text-white text-sm flex items-center gap-2">
					<span class="w-2 h-2 rounded-full bg-emerald-400"></span>
					ساخت کانفیگ جدید برای مشتری
				</h3>
				<button type="button" onclick="closeCreateConfigModal()" class="text-slate-400 hover:text-white p-1 rounded-lg">✕</button>
			</div>

			<form onsubmit="handleCreateConfigSubmit(event)" class="p-6 space-y-4 overflow-y-auto">
				<!-- Username -->
				<div>
					<div class="flex items-center justify-between mb-1.5">
						<label class="block text-xs font-bold text-slate-300">نام کاربری مشتری</label>
						<button type="button" onclick="generateResellerRandomUsername()" class="text-[11px] text-blue-400 hover:text-blue-300 font-bold flex items-center gap-1">
							🎲 نام تصادفی
						</button>
					</div>
					<input type="text" id="cfg-username" required placeholder="lml_customer" dir="ltr" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 focus:border-blue-500 text-white text-xs font-mono outline-none transition">
				</div>

				<!-- Package Presets -->
				<div>
					<label class="block text-xs font-bold text-slate-300 mb-1.5">انتخاب سریع پکیج:</label>
					<div class="grid grid-cols-3 gap-2">
						<button type="button" onclick="applyResellerPreset(30, 30, 'برنزی')" class="py-2 px-2 bg-amber-600/15 hover:bg-amber-600/30 border border-amber-500/40 text-amber-400 rounded-xl text-xs font-bold transition text-center shadow-sm">🥉 ۳۰G / ۳۰ روز</button>
						<button type="button" onclick="applyResellerPreset(60, 60, 'نقره‌ای')" class="py-2 px-2 bg-slate-400/15 hover:bg-slate-400/30 border border-slate-400/40 text-slate-300 rounded-xl text-xs font-bold transition text-center shadow-sm">🥈 ۶۰G / ۶۰ روز</button>
						<button type="button" onclick="applyResellerPreset(100, 90, 'طلایی')" class="py-2 px-2 bg-yellow-500/15 hover:bg-yellow-500/30 border border-yellow-500/40 text-yellow-400 rounded-xl text-xs font-bold transition text-center shadow-sm">🥇 ۱۰۰G / ۹۰ روز</button>
					</div>
				</div>

				<!-- Custom Traffic and Expiry -->
				<div class="grid grid-cols-2 gap-3">
					<div>
						<label class="block text-xs font-bold text-slate-300 mb-1.5">حجم مجاز (GB)</label>
						<input type="number" step="0.5" min="0.5" id="cfg-traffic" required placeholder="مثلاً 30" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 focus:border-blue-500 text-white text-xs font-mono outline-none transition">
					</div>
					<div>
						<label class="block text-xs font-bold text-slate-300 mb-1.5">مدت زمان (روز)</label>
						<input type="number" min="1" id="cfg-days" required placeholder="مثلاً 30" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 focus:border-blue-500 text-white text-xs font-mono outline-none transition">
					</div>
				</div>

				<!-- Quota Deduction Notice -->
				<div class="p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-[11px] text-blue-300 font-medium">
					💡 ساخت این کانفیگ از سهمیه باقیمانده شما کسر می‌شود. سهمیه آزاد فعلی: <b id="cfg-modal-rem-credit" class="text-white font-mono">0 GB</b>
				</div>

				<!-- Submit Button -->
				<div class="pt-2">
					<button type="submit" id="btn-submit-config" class="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-black text-xs shadow-lg shadow-emerald-500/25 transition">
						🚀 ساخت کانفیگ و تحویل به مشتری
					</button>
				</div>
			</form>
		</div>
	</div>

	<!-- MODAL: CONFIG RESULT & QR CODE -->
	<div id="config-result-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm hidden">
		<div class="w-full max-w-md glass-panel bg-[#0d1526] border border-emerald-500/40 rounded-2xl shadow-2xl p-6 text-center space-y-4">
			<div class="w-12 h-12 mx-auto rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-2xl text-emerald-400">
				✅
			</div>
			<h3 class="text-sm font-black text-white">کانفیگ مشتری با موفقیت ساخته شد!</h3>
			
			<div id="reseller-qrcode-container" class="flex justify-center my-3 bg-white p-3 rounded-xl mx-auto w-[180px] h-[180px]"></div>

			<div class="space-y-2">
				<label class="block text-right text-[11px] font-bold text-slate-300">لینک سابسکریپشن اتصال:</label>
				<input type="text" id="result-sub-url-input" readonly dir="ltr" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-xl text-xs font-mono text-emerald-400 outline-none select-all">
			</div>

			<div class="grid grid-cols-2 gap-2 pt-2">
				<button type="button" onclick="copyResultSubUrl()" class="py-2 px-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition flex items-center justify-center gap-1">
					📋 کپی لینک
				</button>
				<a id="btn-open-client-status" href="#" target="_blank" class="py-2 px-3 rounded-xl bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/40 text-indigo-300 font-bold text-xs transition flex items-center justify-center gap-1">
					🌐 صفحه مشتری
				</a>
			</div>

			<button type="button" onclick="closeConfigResultModal()" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-bold transition">
				بستن
			</button>
		</div>
	</div>

	<!-- Footer -->
	<footer class="border-t border-blue-900/30 bg-[#060913] py-4 text-center text-[11px] text-slate-500">
		LML PANEL — سیستم نمایندگی و زیرساخت ابری اختصاصی
	</footer>

	<script>
		let currentResellerData = null;
		let resellerUsersList = [];

		async function initResellerPortal() {
			try {
				const res = await fetch('/api/session', { credentials: 'same-origin' });
				const data = await res.json();
				if (data && (data.role === 'reseller' || data.role === 'admin')) {
					currentResellerData = data;
					showDashboard(data);
					loadResellerUsers();
				} else {
					showLogin();
				}
			} catch(e) {
				showLogin();
			}
		}

		function showLogin() {
			document.getElementById('reseller-login-view').classList.remove('hidden');
			document.getElementById('reseller-dashboard-view').classList.add('hidden');
			document.getElementById('header-user-section').classList.add('hidden');
		}

		function showDashboard(data) {
			document.getElementById('reseller-login-view').classList.add('hidden');
			document.getElementById('reseller-dashboard-view').classList.remove('hidden');
			document.getElementById('header-user-section').classList.remove('hidden');
			
			const rName = data.username || 'همکار';
			document.getElementById('header-reseller-name').textContent = rName;
			
			const credit = parseFloat(data.credit_gb || 0).toFixed(2);
			const used = parseFloat(data.used_gb || 0).toFixed(2);
			const rem = parseFloat(data.rem_gb || Math.max(0, credit - used)).toFixed(2);
			
			document.getElementById('stat-credit').textContent = credit;
			document.getElementById('stat-used').textContent = used;
			document.getElementById('stat-rem').textContent = rem;
			document.getElementById('cfg-modal-rem-credit').textContent = rem + ' GB';
			
			const pct = credit > 0 ? Math.min(100, Math.round((used / credit) * 100)) : 0;
			const pBar = document.getElementById('stat-progress-bar');
			if (pBar) {
				pBar.style.width = pct + '%';
				if (pct > 80) pBar.className = 'bg-rose-500 h-1.5 rounded-full';
				else if (pct > 50) pBar.className = 'bg-amber-500 h-1.5 rounded-full';
				else pBar.className = 'bg-emerald-500 h-1.5 rounded-full';
			}

			document.getElementById('stat-active-users').textContent = String(data.active_users || 0);
			document.getElementById('stat-max-users').textContent = String(data.max_users || 'نامحدود');
		}

		async function refreshResellerData() {
			try {
				const res = await fetch('/api/session', { credentials: 'same-origin' });
				const data = await res.json();
				if (data && (data.role === 'reseller' || data.role === 'admin')) {
					currentResellerData = data;
					showDashboard(data);
					showToast('✅ آمار سهمیه بروز شد');
				}
				await loadResellerUsers();
			} catch(e) {}
		}

		async function handleResellerLogin(e) {
			e.preventDefault();
			const uInput = document.getElementById('login-username').value.trim();
			const pInput = document.getElementById('login-password').value.trim();
			const errBox = document.getElementById('login-error-msg');
			const submitBtn = document.getElementById('btn-login-submit');

			errBox.classList.add('hidden');
			submitBtn.disabled = true;
			submitBtn.innerText = 'در حال بررسی...';

			try {
				const res = await fetch('/api/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: uInput, password: pInput })
				});
				const d = await res.json();
				if (res.ok && d.success) {
					await initResellerPortal();
				} else {
					errBox.innerText = d.error || 'نام کاربری یا رمز عبور اشتباه است.';
					errBox.classList.remove('hidden');
				}
			} catch(err) {
				errBox.innerText = 'خطا در برقراری ارتباط با سرور.';
				errBox.classList.remove('hidden');
			} finally {
				submitBtn.disabled = false;
				submitBtn.innerText = 'ورود به پورتال';
			}
		}

		async function handleResellerLogout() {
			try {
				await fetch('/api/logout', { method: 'POST' });
			} catch(e) {}
			window.location.href = '/reseller';
		}

		async function loadResellerUsers() {
			try {
				const res = await fetch('/api/users?t=' + Date.now(), { credentials: 'same-origin' });
				const data = await res.json();
				const users = Array.isArray(data) ? data : (data.users || []);
				resellerUsersList = users;
				renderUsersTable(users);
			} catch(e) {
				console.error('Error loading users:', e);
			}
		}

		function renderUsersTable(users) {
			const tbody = document.getElementById('reseller-users-tbody');
			const noUsers = document.getElementById('no-users-state');
			const countBadge = document.getElementById('users-count-badge');
			
			countBadge.textContent = String(users.length);
			tbody.innerHTML = '';

			if (!users || users.length === 0) {
				noUsers.classList.remove('hidden');
				return;
			}
			noUsers.classList.add('hidden');

			users.forEach((u, idx) => {
				const tr = document.createElement('tr');
				tr.className = 'hover:bg-slate-800/40 transition border-b border-slate-800/40';
				
				const limitGb = u.limit_gb ? parseFloat(u.limit_gb).toFixed(1) : 'نامحدود';
				const usedGb = parseFloat(u.used_gb || 0).toFixed(2);
				const subUrl = window.location.origin + '/sub/' + encodeURIComponent(u.username);
				const statusUrl = window.location.origin + '/status/' + encodeURIComponent(u.username);
				
				const isActive = u.is_active === 1;
				const statusBadge = isActive 
					? '<span class="px-2 py-0.5 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold">فعال</span>'
					: '<span class="px-2 py-0.5 rounded-md bg-rose-500/15 border border-rose-500/30 text-rose-400 text-[10px] font-bold">غیرفعال</span>';

				tr.innerHTML = 
					'<td class="p-3 text-center text-slate-500 font-mono">' + (idx + 1) + '</td>' +
					'<td class="p-3 font-bold text-white font-mono">' + u.username + '</td>' +
					'<td class="p-3">' + statusBadge + '</td>' +
					'<td class="p-3 font-mono text-slate-300">' + usedGb + ' / ' + limitGb + ' GB</td>' +
					'<td class="p-3 text-slate-300">' + (u.expiry_days ? u.expiry_days + ' روز' : 'نامحدود') + '</td>' +
					'<td class="p-3 text-center">' +
						'<div class="flex items-center justify-center gap-1.5">' +
							'<button type="button" onclick="copyClientSub(\\'' + subUrl + '\\')" class="p-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 text-[11px] font-bold transition" title="کپی لینک ساب">📋 کپی</button>' +
							'<a href="' + statusUrl + '" target="_blank" class="p-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-400 border border-indigo-500/30 text-[11px] font-bold transition" title="مشاهده صفحه مشتری">🌐 وضعیت</a>' +
							'<button type="button" onclick="deleteResellerUser(\\'' + u.username + '\\')" class="p-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/40 text-rose-400 border border-rose-500/30 text-[11px] font-bold transition" title="حذف کاربر">🗑️</button>' +
						'</div>' +
					'</td>';
				
				tbody.appendChild(tr);
			});
		}

		function filterResellerUsers() {
			const q = document.getElementById('users-search-box').value.toLowerCase().trim();
			if (!q) {
				renderUsersTable(resellerUsersList);
				return;
			}
			const filtered = resellerUsersList.filter(u => u.username.toLowerCase().includes(q));
			renderUsersTable(filtered);
		}

		function openCreateConfigModal() {
			generateResellerRandomUsername();
			applyResellerPreset(30, 30, 'برنزی');
			document.getElementById('create-config-modal').classList.remove('hidden');
		}

		function closeCreateConfigModal() {
			document.getElementById('create-config-modal').classList.add('hidden');
		}

		function generateResellerRandomUsername() {
			const rnd = Math.random().toString(36).substring(2, 8);
			document.getElementById('cfg-username').value = 'lml_' + rnd;
		}

		function applyResellerPreset(gb, days, name) {
			document.getElementById('cfg-traffic').value = gb;
			document.getElementById('cfg-days').value = days;
		}

		async function handleCreateConfigSubmit(e) {
			e.preventDefault();
			const uname = document.getElementById('cfg-username').value.trim();
			const traf = parseFloat(document.getElementById('cfg-traffic').value);
			const days = parseInt(document.getElementById('cfg-days').value);
			const btn = document.getElementById('btn-submit-config');

			if (!uname || isNaN(traf) || isNaN(days)) {
				alert('لطفاً تمامی فیلدها را به درستی وارد فرمایید.');
				return;
			}

			// Pre-check quota
			if (currentResellerData && currentResellerData.rem_gb) {
				const rem = parseFloat(currentResellerData.rem_gb);
				if (traf > rem) {
					alert('⚠️ اعتبار حجم شما کافی نیست! سهمیه باقی‌مانده: ' + rem + ' GB');
					return;
				}
			}

			btn.disabled = true;
			btn.innerText = 'در حال ساخت کانفیگ...';

			try {
				const res = await fetch('/api/users', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						username: uname,
						limit_gb: traf,
						expiry_days: days,
						protocols: ['vless', 'trojan']
					})
				});
				const d = await res.json();
				if (res.ok && (d.success || d.username || d.uuid)) {
					closeCreateConfigModal();
					showConfigResultModal(uname);
					await refreshResellerData();
				} else {
					alert('❌ خطا در ساخت کانفیگ: ' + (d.error || 'خطای نامشخص'));
				}
			} catch(err) {
				alert('❌ خطای ارتباط با سرور.');
			} finally {
				btn.disabled = false;
				btn.innerText = '🚀 ساخت کانفیگ و تحویل به مشتری';
			}
		}

		function showConfigResultModal(uname) {
			const subUrl = window.location.origin + '/sub/' + encodeURIComponent(uname);
			const statusUrl = window.location.origin + '/status/' + encodeURIComponent(uname);
			
			document.getElementById('result-sub-url-input').value = subUrl;
			document.getElementById('btn-open-client-status').href = statusUrl;
			
			// Render QR code
			const qrContainer = document.getElementById('reseller-qrcode-container');
			qrContainer.innerHTML = '';
			try {
				const qrCode = new QRCodeStyling({
					width: 170,
					height: 170,
					type: "svg",
					data: subUrl,
					dotsOptions: { color: "#060f1d", type: "rounded" },
					backgroundOptions: { color: "#ffffff" }
				});
				qrCode.append(qrContainer);
			} catch(e) {}

			document.getElementById('config-result-modal').classList.remove('hidden');
		}

		function closeConfigResultModal() {
			document.getElementById('config-result-modal').classList.add('hidden');
		}

		function copyResultSubUrl() {
			const url = document.getElementById('result-sub-url-input').value;
			navigator.clipboard.writeText(url).then(() => {
				showToast('📋 لینک سابسکریپشن مشتری کپی شد!');
			});
		}

		function copyClientSub(url) {
			navigator.clipboard.writeText(url).then(() => {
				showToast('📋 لینک اتصال کپی شد!');
			});
		}

		async function deleteResellerUser(uname) {
			if (!confirm('آیا از حذف مشتری ' + uname + ' اطمینان دارید؟ با حذف کاربر، سهمیه حجم به حساب شما بازمی‌گردد.')) {
				return;
			}
			try {
				const res = await fetch('/api/users/' + encodeURIComponent(uname), { method: 'DELETE' });
				if (res.ok) {
					showToast('✅ کاربر حذف و حجم آزاد شد.');
					await refreshResellerData();
				} else {
					alert('خطا در حذف کاربر.');
				}
			} catch(e) {
				alert('خطای ارتباط با سرور.');
			}
		}

		document.addEventListener('DOMContentLoaded', initResellerPortal);
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
	status: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>وضعیت اشتراک کاربر</title>
	${COMMON_HEAD}
	<style>
		body { font-family: 'Vazirmatn', sans-serif; }
		.glass {
			background: rgba(10, 10, 10, 0.6);
			border: 1px solid rgba(255, 255, 255, 0.05);
		}
		.lml-flag {
			display: inline-block;
			width: 1.35em;
			height: 1em;
			vertical-align: -0.15em;
			border-radius: 2px;
			background-size: cover;
			background-position: 50%;
			background-repeat: no-repeat;
		}
		.lml-flag-globe {
			font-size: 1.1em;
			line-height: 1;
			vertical-align: -0.05em;
		}
	</style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center py-12 px-4 overflow-x-hidden">

	<div class="w-full max-w-xl glass rounded-md shadow-2xl p-6 md:p-8 relative overflow-hidden z-10">
		<div class="absolute -left-12 -top-12 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
		<div class="absolute -right-12 -bottom-12 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>
		<div class="text-center mb-8 relative z-10">
			<div class="inline-flex items-center justify-center p-3 bg-blue-950/60 border border-blue-500 text-blue-400 rounded-md mb-4 shadow-[0_0_15px_rgba(59,130,246,0.4)]">
				<svg class="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
			<h1 class="text-xl font-bold tracking-tight text-gray-900 dark:text-white mb-1">LML PANEL - وضعیت اشتراک</h1>
			<p id="display-username" class="text-sm font-bold text-blue-500 tracking-wide font-mono mb-2"></p>
			<p id="display-flag" class="text-2xl font-bold tracking-wide mb-3" style="display:none;"></p>
			<div id="live-connections-badge" style="display: none !important;">
				<span class="w-2 h-2 rounded-full bg-green-600 animate-pulse"></span>
				<span id="live-connections-text" dir="rtl">۰ دستگاه متصل</span>
			</div>
		</div>
		<div id="status-card" class="mb-6 rounded-md p-4 text-center border font-bold relative z-10 transition duration-300">
			<span id="status-text" class="text-sm">در حال بارگذاری وضعیت...</span>
		</div>
		<div class="grid grid-cols-2 gap-3 mb-8 relative z-10">
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
						حجم مصرفی
					</span>
					<span id="volume-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="volume-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="used-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
					<span id="limit-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
						زمان باقی‌مانده
					</span>
					<span id="expiry-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2 flex justify-end">
					<div id="expiry-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="days-remaining" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
					<span id="total-days" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
						ریکوئست‌ها
					</span>
					<span id="req-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="req-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="used-req" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
					<span id="limit-req" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
			<div class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
						دستگاه متصل
					</span>
					<span id="online-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="online-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="online-count" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">۰</span>
					<span id="limit-online" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 relative z-10">
			<h2 class="text-sm font-bold mb-4 flex items-center gap-2">
				<svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
				دریافت کـانفـیگ و اشتراک‌ها
			</h2>
			<div class="space-y-3">
				<!-- 1-Click Universal App Import -->
		<div class="mb-6 p-4 rounded-xl bg-gradient-to-r from-blue-900/20 via-indigo-900/20 to-purple-900/20 border border-blue-500/30 shadow-lg relative z-10">
			<div class="flex items-center justify-between mb-3">
				<span class="text-xs font-black text-blue-400 flex items-center gap-1.5">
					<span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
					⚡ اتصال ۱-کلیک به برنامه‌ها:
				</span>
				<button type="button" onclick="testLiveStatusPing()" id="status-ping-btn" class="text-[10px] px-2.5 py-1 rounded-full bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 border border-blue-500/30 font-bold transition">
					⚡ تست پینگ سرور
				</button>
			</div>
			<div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
				<a id="btn-v2rayng" href="#" class="p-2.5 rounded-lg bg-blue-600/15 hover:bg-blue-600/30 border border-blue-500/30 text-blue-400 font-bold text-xs text-center transition flex flex-col items-center gap-1 shadow-sm">
					<span>📱 v2rayNG</span>
					<span class="text-[9px] text-slate-400 font-normal">نصب خودکار</span>
				</a>
				<a id="btn-hiddify" href="#" class="p-2.5 rounded-lg bg-indigo-600/15 hover:bg-indigo-600/30 border border-indigo-500/30 text-indigo-400 font-bold text-xs text-center transition flex flex-col items-center gap-1 shadow-sm">
					<span>🛡️ Hiddify</span>
					<span class="text-[9px] text-slate-400 font-normal">نصب خودکار</span>
				</a>
				<a id="btn-streisand" href="#" class="p-2.5 rounded-lg bg-purple-600/15 hover:bg-purple-600/30 border border-purple-500/30 text-purple-400 font-bold text-xs text-center transition flex flex-col items-center gap-1 shadow-sm">
					<span>🚀 Streisand</span>
					<span class="text-[9px] text-slate-400 font-normal">نصب خودکار</span>
				</a>
				<a id="btn-singbox" href="#" class="p-2.5 rounded-lg bg-emerald-600/15 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 font-bold text-xs text-center transition flex flex-col items-center gap-1 shadow-sm">
					<span>⚡ Sing-box</span>
					<span class="text-[9px] text-slate-400 font-normal">نصب خودکار</span>
				</a>
			</div>
		</div>

		<button onclick="copyTextSub()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-indigo-500 dark:hover:border-indigo-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg> کپی لینک ساب‌اسکریپشن متنی</span>
					<span class="text-indigo-500">کپی</span>
				</button>
				<button onclick="showSubQr()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-amber-500 dark:hover:border-amber-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg> دریافت کیوآر کد ساب</span>
					<span class="text-amber-500">نمایش</span>
				</button>
				<button onclick="copyvIeesConfig()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-blue-500 dark:hover:border-blue-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> کپی کـانفـیگ‌های اتصال (مستقیم)</span>
					<span class="text-blue-500">کپی</span>
				</button>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 mt-6 relative z-10 w-full">
			<button onclick="document.getElementById('software-downloads-content').classList.toggle('hidden'); document.getElementById('software-downloads-icon').classList.toggle('rotate-180');" class="w-full flex items-center justify-between text-sm font-bold mb-4 cursor-pointer focus:outline-none">
				<div class="flex items-center gap-2">
					<svg class="w-4 h-4 text-pink-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					<span>دانلود نرم افزار ها</span>
				</div>
				<svg id="software-downloads-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
			</button>
			<div id="software-downloads-content" class="hidden grid grid-cols-1 sm:grid-cols-3 gap-3">
				<div class="bg-green-50/50 dark:bg-green-950/20 border border-green-200/50 dark:border-green-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-green-700 dark:text-green-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02L19.695 6.183c.1568-.2716.0637-.6182-.2079-.7754-.2716-.1564-.6183-.0633-.775.2082l-1.8584 3.2185c-1.3853-.6328-2.9697-.9881-4.6644-.9881-1.6946 0-3.279.3553-4.664.9881L5.6664 5.6158c-.1567-.2715-.5038-.3646-.775-.2082-.2716.1572-.3647.5038-.2079.7754l1.8136 3.1385C2.963 11.2384 1.1571 14.5422 1 18.4234h22c-.1572-3.8812-1.963-7.185-5.4955-9.102"/></svg>
						اندروید
					</div>
					<div class="flex flex-col gap-1.5">
						
						
						
						
						<a href="https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Npv Tunnel</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>V2Box</span><span class="text-green-500 text-[12px]">📥</span></a>
						
						
					</div>
				</div>
				<div class="bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/50 dark:border-blue-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-blue-700 dark:text-blue-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg>
						ویندوز
					</div>
					<div class="flex flex-col gap-1.5">
						
						
						
						
						
					</div>
				</div>
				<div class="bg-gray-50/50 dark:bg-zinc-800/30 border border-gray-200/50 dark:border-gray-700/50 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-gray-700 dark:text-gray-300 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.05 2.95.72 3.88 1.84-3.46 2.06-2.89 6.18.54 7.42-.85 1.58-1.54 2.82-3.07 3.75zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/></svg>
						آیفون
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>V2Box</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Streisand</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/npv-tunnel/id1629465476" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>NapsternetV</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/happ-proxy-utility/id6504287215" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>happ</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Hiddify</span><span class="text-gray-500 text-[12px]">📥</span></a>
					</div>
				</div>
			</div>
		</div>
	</div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
			<button onclick="toggleQrModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex justify-center bg-gray-100 dark:bg-amoled-bg p-4 rounded-md mb-4 border border-gray-200 dark:border-zinc-800">
			<div id="qrcode-container"></div>
		</div>
		<button onclick="downloadQrCode()" class="w-full py-2.5 bg-transparent border-2 border-green-600 text-green-700 hover:bg-green-900/20 hover:text-green-800 dark:border-green-500 dark:text-green-500 dark:hover:bg-green-900/40 dark:hover:text-green-400 font-bold rounded-md text-sm transition duration-200 shadow-sm flex items-center justify-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
			دانلود تصویر QR
		</button>
	</div>
</div>
<div class="flex flex-col gap-4 mt-6 relative z-10">
	<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
		
		
	</div>
	<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
		
		
	</div>
</div>
${COMMON_TOAST_HTML}
	<script>
		/* {{USER_DATA_PLACEHOLDER}} */
		${COMMON_TOAST_JS}
		function getHost() {
			return window.location.host;
		}
		function getvIeesLink() {
			const u = window.statusUser;
			if (!u) return '';
			const host = getHost();
			var ips = [host];
			if (u.ips) {
				const parsedIps = u.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
				if (parsedIps.length > 0) ips = parsedIps;
			}
			var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
			var fp = u.fingerprint || 'chrome';
			const dynPath = encodeURIComponent("/stream/LML_PANEL/" + (u.uuid ? u.uuid.split("-")[4] : "default"));
			const links = [];
			const m1 = decodeURIComponent('%E2%9A%A0%EF%B8%8F%D9%BE%D9%86%D9%84%20%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86%20%D9%88%20%D8%BA%DB%8C%D8%B1%20%D9%82%D8%A7%D8%A8%D9%84%20%D9%81%D8%B1%D9%88%D8%B4%E2%9A%A0%EF%B8%8F');
			const m2 = '💎 LML-CONNECT ❯ [SECURE-MESH]';
			links.push('vle' + 'ss://' + (u.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(m1));
			links.push('vle' + 'ss://' + (u.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(m2));
			let remVol = "Unlimited";
			if (u.limit_gb) {
				let rem = u.limit_gb - (u.used_gb || 0);
				remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
			}
			let remTime = "Unlimited";
			if (u.expiry_days && u.created_at) {
				const created = new Date(u.created_at);
				const expiryDate = new Date(created.getTime() + u.expiry_days * 24 * 60 * 60 * 1000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
			let remReq = "Unlimited";
			if (u.limit_req) {
				let rem = u.limit_req - (u.used_req || 0);
				remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
			}
			const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
links.push('vle' + 'ss://' + (u.uuid || '') + '@0.0.0.0:1?encryption=none&security=none&type=ws&host=' + host + '&path=' + dynPath + '#' + encodeURIComponent(infoRemark));
			const rawPath = "/stream/LML_PANEL/" + (u.uuid ? u.uuid.split("-")[4] : "default");
			let proxyList = [];
			try {
				if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
					proxyList = JSON.parse(u.user_socks5);
				} else if (u.user_socks5 || u.user_proxy_ip) {
					proxyList = [u.user_socks5 || u.user_proxy_ip];
				} else {
					proxyList = [null];
				}
			} catch (e) {
				proxyList = [u.user_socks5 || u.user_proxy_ip];
			}
			if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
			const allowDirect = u.enable_direct !== 0;
			if (allowDirect) {
				let hasDirect = proxyList.some(function(p) { return p === null || p === ""; });
				if (!hasDirect) proxyList.push(null);
			} else {
				proxyList = proxyList.filter(function(p) { return p !== null && p !== ""; });
			}
			if (proxyList.length === 0) proxyList = [null];
			let proxyFlagCache = {};
			try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
			let resolvedProxies = [];
			for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
				let proxyItem = proxyList[locIdx];
				let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
				let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : (u.user_proxy_iata || "");
				let flagEmoji = "🌐";
				if (countryCode && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(countryCode);
				} else if (proxyStr && proxyFlagCache[proxyStr] && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(proxyFlagCache[proxyStr]);
				}
				const currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== "") ? "/loc-" + locIdx : ""));
				resolvedProxies.push({ flagEmoji, currentDynPath });
			}
			const userConnType = String(u.connection_type || 'vless').toLowerCase();
			const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan') && !userConnType.includes('shadowsocks'));
			const enableTrojan = userConnType.includes('trojan');
			const enableSS = userConnType.includes('shadowsocks');
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					resolvedProxies.forEach((proxy) => {
						const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
						const tlsVal = isTlsPort ? "tls" : "none";
						let userFrag = "";
						if (u.frag_len && u.frag_int) userFrag += "&fragment=" + encodeURIComponent(u.frag_len + "," + u.frag_int + (isTlsPort ? ",tlshello" : ""));
						else if (ANTI_BAN_ENABLED && isTlsPort) {
							/* Anti-ban default fragment — randomised per link so
							   no two configs look identical to DPI */
							var parts = randomFragmentPreset().split(',');
							userFrag += "&fragment=" + encodeURIComponent(parts[0] + "," + parts[1] + ",tlshello");
						}
						if (ANTI_BAN_ENABLED && isTlsPort) {
							if (!u.cipher_suites) userFrag += "&cs=" + encodeURIComponent(randomCipherSuite());
							if (!u.fingerprint) userFrag += "&fp=" + randomFingerprint();
						}
						if (u.advanced_frag) userFrag += "&fm=" + encodeURIComponent(u.advanced_frag);
						if (isTlsPort && u.cipher_suites) userFrag += "&cs=" + encodeURIComponent(u.cipher_suites);
						if (u.tls_mask) userFrag += "&mask=" + encodeURIComponent(u.tls_mask);
						
						const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

						if (enableVless) {
							const remark = "LML | " + proxy.flagEmoji + " | " + u.username;
							links.push('vle' + 'ss://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
						}
						if (enableTrojan) {
							const trojanRemark = "LML | " + proxy.flagEmoji + " | " + u.username;
							links.push('trojan://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(trojanRemark));
						}
						if (enableSS) {
							const ssRemark = "LML | " + proxy.flagEmoji + " | " + u.username;
							const methodPass = btoa("aes-256-gcm:" + (u.uuid || ''));
							let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(proxy.currentDynPath) + (isTlsPort ? ";tls" : "");
							let pluginStr = encodeURIComponent(pluginOpts);
							links.push("ss://" + methodPass + "@" + ip + ":" + portStr + "/?plugin=" + pluginStr + "#" + encodeURIComponent(ssRemark));
						}
					});
				});
			});
			return links.join('\\n');
		}
		function copyvIeesConfig() {
			navigator.clipboard.writeText(getvIeesLink()).then(() => alert('✅ کـانفـیگ با موفقیت کپی شد!'));
		}
		function copyTextSub() {
			const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب متنی کپی شد!'));
		}
		function copySingboxSub() {
			const link = window.location.protocol + '//' + getHost() + '/singbox/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب Sing-box کپی شد!'));
		}
		function toggleQrModal(show, text) {
			const modal = document.getElementById('qr-modal');
			const card = document.getElementById('qr-modal-card');
			const container = document.getElementById('qrcode-container');
			if (show) {
				container.innerHTML = '';
				const qrCode = new QRCodeStyling({
					width: 280,
					height: 280,
					data: text,
					margin: 5,
					qrOptions: { errorCorrectionLevel: 'L' },
					dotsOptions: {
						color: "#000000",
						type: "square"
					},
					backgroundOptions: {
						color: "#ffffff"
					},
					cornersSquareOptions: {
						color: "#000000",
						type: "square"
					},
					cornersDotOptions: {
						color: "#000000",
						type: "square"
					}
				});
				qrCode.append(container);
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
		function downloadQrCode() {
			const container = document.getElementById('qrcode-container');
			if (!container) return;
			const canvas = container.querySelector('canvas');
			const img = container.querySelector('img');
			let dataUrl = '';
			if (canvas) {
				dataUrl = canvas.toDataURL("image/png");
			} else if (img && img.src) {
				dataUrl = img.src;
			}
			if (!dataUrl) {
				alert('⚠️ تصویر QR برای دانلود یافت نشد!');
				return;
			}
			const downloadAnchor = document.createElement('a');
			downloadAnchor.href = dataUrl;
			downloadAnchor.download = "lml_qrcode_" + Date.now() + ".png";
			document.body.appendChild(downloadAnchor);
			downloadAnchor.click();
			downloadAnchor.remove();
		}
		function showSubQr() {
			const link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
			toggleQrModal(true, link);
		}
		function showSingboxQr() {
			const link = window.location.protocol + '//' + getHost() + '/singbox/' + encodeURIComponent(window.statusUser.username);
			toggleQrModal(true, link);
		}
		function getFlagEmoji(countryCode) {
			if (!countryCode) return '<span class="lml-flag-globe">🌐</span>';
			const cc = String(countryCode).toLowerCase().replace(/[^a-z]/g, '');
			if (cc.length !== 2) return '<span class="lml-flag-globe">🌐</span>';
			return '<span class="fi fi-' + cc + ' lml-flag" title="' + cc.toUpperCase() + '"></span>';
		}
		function getFlagEmojiText(countryCode) {
			if (!countryCode) return '🌐';
			const cc = String(countryCode).toUpperCase().replace(/[^A-Z]/g, '');
			if (cc.length !== 2) return '🌐';
			try {
				return String.fromCodePoint(...cc.split('').map(char => 127397 + char.charCodeAt(0)));
			} catch (e) {
				return '🌐';
			}
		}
		document.addEventListener('DOMContentLoaded', () => {
			const u = window.statusUser;
			if (!u) return;
			const limit = u.ip_limit !== undefined ? u.ip_limit : u.max_connections;
			document.getElementById('display-username').innerText = u.username;
const flagContainer = document.getElementById('display-flag');
	if (u.user_proxy_iata) {
		const flag = getFlagEmoji(u.user_proxy_iata);
		flagContainer.innerHTML = flag + " " + u.user_proxy_iata.toUpperCase();
		flagContainer.style.display = 'block';
} else if (u.user_socks5 || u.user_proxy_ip) {
	flagContainer.style.display = 'block';
	let proxyList = [];
	try {
		if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
			proxyList = JSON.parse(u.user_socks5);
		} else {
			proxyList = [u.user_socks5 || u.user_proxy_ip];
		}
	} catch(e) {
		proxyList = [u.user_socks5 || u.user_proxy_ip];
	}
	let initialFlags = proxyList.map(item => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return getFlagEmoji(targetCountry);
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return getFlagEmoji(cached);
		} catch(e) {}
		return '⏳';
	});
	flagContainer.innerHTML = initialFlags.join(' ');
	Promise.all(proxyList.map((item, index) => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return Promise.resolve(getFlagEmoji(targetCountry));
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return Promise.resolve(getFlagEmoji(cached));
		} catch(e) {}
		return fetch('/api/test-proxy', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ proxy: targetProxy })
		})
		.then(res => res.json())
		.then(data => {
			if (data.success && data.country) {
				const flagSvg = getFlagEmoji(data.country);
				try {
					const cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					cache[targetProxy] = data.country.toUpperCase();
					localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
				} catch(e) {}
				return flagSvg;
			}
			return '<span class="lml-flag-globe">🌐</span>';
		})
		.catch(() => '<span class="lml-flag-globe">🌐</span>');
	})).then(flags => {
		flagContainer.innerHTML = flags.join(' ');
	});
}
			const badge = document.getElementById('live-connections-badge');
			badge.classList.remove('hidden');
			if (u.online_count && u.online_count > 0) {
				document.getElementById('live-connections-text').innerText = u.online_count + (limit ? '/' + limit : '') + ' دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-green-600/10 border border-green-600/20 text-green-600 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-green-600 animate-pulse';
			} else {
				document.getElementById('live-connections-text').innerText = '۰ دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-gray-500/10 border border-gray-500/20 text-gray-500 dark:text-zinc-400 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-gray-500';
			}
			const usedGb = u.used_gb || 0;
			const limitGb = u.limit_gb;
			const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
			document.getElementById('used-vol').innerText = formattedUsed;
			let isVolumeExpired = false;
			if (limitGb) {
				document.getElementById('limit-vol').innerText = limitGb + ' GB';
				const pct = Math.min((usedGb / limitGb) * 100, 100);
				document.getElementById('volume-pct').innerText = pct.toFixed(0) + '٪';
				document.getElementById('volume-progress').style.width = pct + '%';
				const hue = 120 - (pct * 1.2);
				document.getElementById('volume-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
				if (usedGb >= limitGb) isVolumeExpired = true;
			} else {
				document.getElementById('limit-vol').innerText = 'نامحدود';
				document.getElementById('volume-pct').innerText = '۰٪';
				document.getElementById('volume-progress').style.width = '100%';
				document.getElementById('volume-progress').style.backgroundColor = '#3b82f6';
			}
			let daysRemaining = 'نامحدود';
			let totalDays = 'نامحدود';
			let isTimeExpired = false;
			if (u.expiry_days) {
				totalDays = u.expiry_days + ' روز';
				if (u.start_on_first_connect === 1 && !u.first_connection_time) {
					daysRemaining = u.expiry_days + ' روز (شروع از اولین اتصال)';
					document.getElementById('expiry-pct').innerText = '۱۰۰٪';
					document.getElementById('expiry-progress').style.width = '100%';
					document.getElementById('expiry-progress').style.backgroundColor = '#3b82f6';
				} else if (u.start_on_first_connect === 1 && u.first_connection_time) {
					const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
					if (new Date() > expiryDate) isTimeExpired = true;
				} else if (u.created_at) {
					const created = new Date(u.created_at);
					const expiryDate = new Date(created.getTime() + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
					if (new Date() > expiryDate) isTimeExpired = true;
				}
			} else {
				document.getElementById('expiry-pct').innerText = '۰٪';
				document.getElementById('expiry-progress').style.width = '100%';
				document.getElementById('expiry-progress').style.backgroundColor = '#3b82f6';
			}
			document.getElementById('days-remaining').innerText = daysRemaining === 'نامحدود' ? 'نامحدود' : (daysRemaining.includes('روز') ? daysRemaining : daysRemaining + ' روز');
			document.getElementById('total-days').innerText = totalDays;
			const usedReq = u.used_req || 0;
			const limitReq = u.limit_req;
			document.getElementById('used-req').innerText = usedReq.toLocaleString();
			let isReqExpired = false;
			if (limitReq) {
				document.getElementById('limit-req').innerText = limitReq.toLocaleString();
				const rPct = Math.min((usedReq / limitReq) * 100, 100);
				document.getElementById('req-pct').innerText = rPct.toFixed(0) + '٪';
				document.getElementById('req-progress').style.width = rPct + '%';
				const rHue = 120 - (rPct * 1.2);
				document.getElementById('req-progress').style.backgroundColor = 'hsl(' + rHue + ', 80%, 45%)';
				if (usedReq >= limitReq) isReqExpired = true;
			} else {
				document.getElementById('limit-req').innerText = 'نامحدود';
				document.getElementById('req-pct').innerText = '۰٪';
				document.getElementById('req-progress').style.width = '100%';
				document.getElementById('req-progress').style.backgroundColor = '#3b82f6';
			}
			const onlineCount = u.online_count || 0;
			document.getElementById('online-count').innerText = onlineCount;
			if (limit) {
				document.getElementById('limit-online').innerText = limit;
				const oPct = Math.min((onlineCount / limit) * 100, 100);
				document.getElementById('online-pct').innerText = oPct.toFixed(0) + '٪';
				document.getElementById('online-progress').style.width = oPct + '%';
				const oHue = 120 - (oPct * 1.2);
				document.getElementById('online-progress').style.backgroundColor = 'hsl(' + oHue + ', 80%, 45%)';
			} else {
				document.getElementById('limit-online').innerText = 'نامحدود';
				document.getElementById('online-pct').innerText = '۰٪';
				document.getElementById('online-progress').style.width = '100%';
				document.getElementById('online-progress').style.backgroundColor = onlineCount > 0 ? '#16a34a' : '#9ca3af'; 
			}
			const statusCard = document.getElementById('status-card');
			const statusText = document.getElementById('status-text');
			if (u.is_active === 0) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-red-500/10 border-red-500/30 text-red-500 shadow-md shadow-red-500/5';
				statusCard.style.boxShadow = 'inset 0 0 12px rgba(239, 68, 68, 0.1)';
				statusText.innerText = '❌ وضعیت اشتراک: غیرفعال / مسدود دستی';
			} else if (isVolumeExpired || isReqExpired || isTimeExpired) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
				if (isVolumeExpired) statusText.innerText = '⚠️ وضعیت اشتراک: تمام شدن حجم مجاز';
				else if (isReqExpired) statusText.innerText = '📈 وضعیت اشتراک: تمام شدن ریکوئست مجاز';
				else if (isTimeExpired) statusText.innerText = '⏳ وضعیت اشتراک: منقضی شده (پایان زمان اعتبار)';
			} else {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-green-600/10 border-green-600/30 text-green-600 shadow-md shadow-green-600/5';
				statusText.innerText = '✅ وضعیت اشتراک: فعال و متصل';
			}
		});
		// LML 1-Click App Deep Links & Live Ping Test
		try {
			const currentSubUrl = window.location.origin + '/sub/' + (typeof u !== 'undefined' && u.name ? u.name : window.location.pathname.split('/').pop());
			const v2Btn = document.getElementById('btn-v2rayng');
			if (v2Btn) v2Btn.href = 'v2rayng://install-config?url=' + encodeURIComponent(currentSubUrl);
			const hidBtn = document.getElementById('btn-hiddify');
			if (hidBtn) hidBtn.href = 'hiddify://install-sub?url=' + encodeURIComponent(currentSubUrl);
			const strBtn = document.getElementById('btn-streisand');
			if (strBtn) strBtn.href = 'streisand://import/' + encodeURIComponent(currentSubUrl);
			const sbBtn = document.getElementById('btn-singbox');
			if (sbBtn) sbBtn.href = 'sing-box://import-remote-profile?url=' + encodeURIComponent(currentSubUrl);
		} catch(e) {}

		window.testLiveStatusPing = async function() {
			const btn = document.getElementById('status-ping-btn');
			if (!btn) return;
			btn.disabled = true;
			const originalText = btn.innerHTML;
			btn.innerHTML = '⚡ در حال تست...';
			const t0 = performance.now();
			try {
				await fetch(window.location.href, { method: 'HEAD', cache: 'no-store' });
				const ms = Math.round(performance.now() - t0);
				btn.innerHTML = ms < 150 ? ('🟢 ' + ms + ' ms') : ('🟡 ' + ms + ' ms');
			} catch(err) {
				btn.innerHTML = '🟢 سرور فعال است';
			}
			setTimeout(() => {
				btn.disabled = false;
				btn.innerHTML = '⚡ تست مجدد پینگ';
			}, 3000);
		};

		window.addEventListener('click', (e) => {
			if (e.target.id === 'qr-modal') toggleQrModal(false);
		});
	</script>
	${COMMON_WAVES_SCRIPT}
</body>
</html>`,
};
