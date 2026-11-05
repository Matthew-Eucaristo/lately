// lately site: an interactive replica of the TUI, plus small page helpers.
// Plain JS, no dependencies, no network. The timeline and the restart verdict
// come from sample.js, which site/build.sh generates by running
// lately --replay demo/sample: generic sample data, never a real Mac.
(() => {
  "use strict";
  document.documentElement.classList.add("js");
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  /* ---------- copy buttons ---------- */
  $$("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    const text = b.dataset.copy;
    try { await navigator.clipboard.writeText(text); }
    catch {
      const t = Object.assign(document.createElement("textarea"), { value: text });
      document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
    }
    b.classList.add("done");
    clearTimeout(b._t); b._t = setTimeout(() => b.classList.remove("done"), 1600);
  }));

  /* ---------- install tabs (ARIA tabs pattern) ---------- */
  const tabs = $$('[role="tab"]');
  const pick = (t) => {
    tabs.forEach((x) => {
      const on = x === t;
      x.setAttribute("aria-selected", on); x.tabIndex = on ? 0 : -1;
      $("#" + x.getAttribute("aria-controls")).hidden = !on;
    });
    t.focus();
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => pick(t));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) { e.preventDefault(); pick(tabs[(i + d + tabs.length) % tabs.length]); }
    });
  });

  /* ---------- reveal on scroll ---------- */
  if (!reduceMotion && "IntersectionObserver" in window) {
    const io = new IntersectionObserver((es) => es.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    }), { rootMargin: "0px 0px -8% 0px" });
    $$(".sec h2, .sec .intro, .q, .limits article, .evidence article, .checks li, .callouts li, .anatomy .window, .funnel, .recording, .platforms div, .usage, .codes").forEach((el, i) => {
      el.classList.add("reveal"); el.style.transitionDelay = (i % 4) * 60 + "ms"; io.observe(el);
    });
  }

  /* ---------- recording: video, GIF fallback ---------- */
  const video = $("#demo-video"), play = $("#play");
  if (video) {
    const toGif = () => {
      const img = Object.assign(new Image(1200, 600), { src: "demo.gif", alt: video.getAttribute("aria-label"), loading: "lazy" });
      video.replaceWith(img); play.hidden = true;
    };
    const srcs = $$("source", video);
    srcs[srcs.length - 1].addEventListener("error", toGif);
    const start = (manual) => { play.hidden = true; if (manual === true) video.controls = true; video.play().catch(() => { play.hidden = false; }); };
    play.addEventListener("click", () => start(true));
    video.addEventListener("click", () => { if (!video.controls) { if (video.paused) video.play(); else video.pause(); } });
    const saveData = navigator.connection && navigator.connection.saveData;
    if (!reduceMotion && !saveData && "IntersectionObserver" in window) {
      const vio = new IntersectionObserver((es) => es.forEach((e) => {
        if (e.isIntersecting) start(); else if (!video.paused) video.pause();
      }), { threshold: 0.5 });
      vio.observe(video);
    }
  }

  /* ---------- the noise column: what Console shows ---------- */
  const noise = $("#noise");
  if (noise) {
    const procs = ["runningboardd", "kernel", "WindowServer", "mDNSResponder", "locationd", "cloudd", "bluetoothd", "trustd", "symptomsd", "powerd", "corespotlightd", "launchservicesd", "tccd", "syspolicyd", "nsurlsessiond", "contextstored"];
    const msgs = ["Acquiring assertion for target", "Invalidating assertion", "[0x7f9a] activating connection", "Received request for", "no change in state", "updating policy", "sending notification", "query completed", "<private>", "handled event", "client registered", "resolved endpoint", "evaluating trust", "timer fired", "state transition"];
    let line = 0;
    const mk = () => {
      const p = procs[(line * 7 + 3) % procs.length], m = msgs[(line * 11 + 5) % msgs.length];
      const ts = String(10 + (line % 50)).padStart(2, "0");
      line++;
      return `17:16:${ts}.${String((line * 137) % 1000).padStart(3, "0")}  ${p}[${100 + (line * 37) % 900}]  ${m} ${line % 3 ? "<private>" : ""}`;
    };
    noise.textContent = Array.from({ length: 14 }, mk).join("\n");
    if (!reduceMotion) {
      setInterval(() => {
        if (document.hidden) return;
        const ls = noise.textContent.split("\n"); ls.shift(); ls.push(mk()); noise.textContent = ls.join("\n");
      }, 140);
    }
  }

  /* =====================================================================
     The TUI replica
     ===================================================================== */
  const term = $("#term");
  const DATA = window.LATELY_SAMPLE;
  if (!term) return;
  if (!DATA) { term.innerHTML = '<img src="demo.gif" alt="lately replaying sample data" style="width:100%;height:auto">'; return; }
  const keysEl = $("#term-keys"), hint = $("#try-hint");

  /* ---------- time: sample times move to the visitor's clock ---------- */
  const T = DATA.timeline;
  const until0 = Date.parse(T.window.until), since0 = Date.parse(T.window.since);
  const shift = Date.now() - until0;
  const pad2 = (n) => String(n).padStart(2, "0");
  const hms = (ms) => { const d = new Date(ms); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; };
  const hm = (ms) => hms(ms).slice(0, 5);
  const day = (ms) => new Date(ms).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  // Card text carries the build machine's UTC clock (TZ=UTC); rewrite it too.
  const u = new Date(until0);
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const retime = (s) => String(s).replace(/\b(?:([A-Z][a-z]{2}) (\d{1,2}) )?(\d\d):(\d\d):(\d\d)\b/g, (all, mon, dd, h, m, sec) => {
    const dated = mon && MON.includes(mon);
    let t = Date.UTC(u.getUTCFullYear(), dated ? MON.indexOf(mon) : u.getUTCMonth(), dated ? +dd : u.getUTCDate(), +h, +m, +sec);
    if (!dated && t > until0 + 3600e3) t -= 86400e3;
    t += shift;
    if (!dated) return hms(t);
    const days = Math.round((new Date().setHours(0, 0, 0, 0) - new Date(t).setHours(0, 0, 0, 0)) / 86400e3);
    return (days === 0 ? "" : days === 1 ? "yesterday " : day(t) + " ") + hms(t);
  });

  /* ---------- findings ---------- */
  const LV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const GL = ["· INFO", "○ LOW ", "● MED ", "▲ HIGH", "✖ CRIT"];
  const LC = ["info", "low", "med", "high", "crit"];
  const who = (f) => {
    const s = f.subject || {};
    if (s.signer === "apple") return "Apple";
    if (s.signer === "devid" && s.team_id) return "Developer ID " + s.team_id;
    if (s.team_id) return "team " + s.team_id;
    if ((s.bundle_id || "").startsWith("com.apple.")) return "Apple (by name)";
    return "";
  };
  const isApple = (f) => /^Apple/.test(who(f));
  const mkFinding = (f) => ({
    ...f, lv: LV[f.level] ?? 0, t: Date.parse(f.ts) + shift, tl: Date.parse(f.last || f.ts) + shift,
    who: who(f), known: false, fresh: false,
  });
  let rows = T.findings.map(mkFinding);

  // Live rows for follow mode: from demo/sample/live.ndjson, as lately shows them.
  const helper = rows.find((r) => /Launch daemon added/.test(r.title)) || {};
  const live = [
    { at: 2400, bump: /crashed ×/ },
    { at: 5200, add: {
      level: "high", category: "PERSIST", rule: "persist.launch_agent", title: "Launch agent added: com.foovpn.updater", first_seen: true, approximate: false,
      subject: { name: "com.foovpn.updater", bundle_id: "com.foovpn.updater", team_id: "ABCDE12345", signer: "devid", path: "/Library/Application Support/FooVPN/updater" },
      fields: { label: "com.foovpn.updater" }, mitre: ["T1543.001"],
      card: {
        what: ["A helper will now start every time you log in: /Library/Application Support/FooVPN/updater"],
        who: ["com.foovpn.updater · Developer ID ABCDE12345", "Developer ID Application: Foo VPN Inc (ABCDE12345)"],
        why: (helper.card && helper.card.why) || ["Written during the Foo VPN install"],
        matters: ["Launch agents are the commonest way software, and malware, keeps running on a Mac.", "MITRE ATT&CK T1543.001"],
        do: ["Expected? press a to mark it known. Not expected? System Settings › General › Login Items, or launchctl bootout gui/$(id -u)/com.foovpn.updater"],
        raw: ["~/Library/LaunchAgents/com.foovpn.updater.plist"],
        source: ["replay:persist · rule persist.launch_agent v1 · confidence ✓ · first seen +1"],
      } } },
  ];

  /* ---------- state ---------- */
  const LADDER = ["5m", "15m", "30m", "1h", "2h", "3h", "6h", "12h", "1d", "2d", "3d", "7d"];
  const SPAN = { "5m": 5, "15m": 15, "30m": 30, "1h": 60, "2h": 120, "3h": 180, "6h": 360, "12h": 720, "1d": 1440, "2d": 2880, "3d": 4320, "7d": 10080 };
  const st = { anc: null, view: "list", cur: 0, floor: 2, all: false, win: 1, ladder: false, follow: false, fsince: 0, stack: [], rcur: 0, status: "", toast: "" };
  let cols = 120, lines = 30, timers = [];

  const until = () => (st.follow ? Date.now() : until0 + shift);
  const since = () => until0 + shift - SPAN[LADDER[st.win]] * 60e3;
  const hiddenWhy = (f) => (f.lv < st.floor ? "below floor" : f.known ? "known" : isApple(f) && f.lv < 2 ? "Apple" : "");
  const shown = (f) => f.t >= since() - 1 && (hiddenWhy(f) === "" || (hiddenWhy(f) !== "below floor" && st.all));
  const visible = () => rows.filter(shown).sort((a, b) => b.tl - a.tl);

  /* ---------- text helpers ---------- */
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const trunc = (s, n) => (n <= 0 ? "" : s.length > n ? s.slice(0, Math.max(0, n - 1)) + "…" : s);
  const pad = (s, n) => { s = trunc(String(s), n); return s + " ".repeat(Math.max(0, n - s.length)); };
  const padL = (s, n) => { s = trunc(String(s), n); return " ".repeat(Math.max(0, n - s.length)) + s; };
  const sp = (c, s) => `<span class="${c}">${esc(s)}</span>`;
  const ln = (html = " ") => `<span class="ln">${html}</span>`;
  const rule = (label = "") => ln(sp("f", label ? "── " + label + " " + "─".repeat(Math.max(0, cols - label.length - 4)) : "─".repeat(cols)));
  const lvs = (f, w = 6) => sp("lv " + LC[f.lv] + (f.lv === 4 ? " b" : ""), pad(GL[f.lv], w));

  const measure = () => {
    const probe = document.createElement("span");
    probe.textContent = "0".repeat(100);
    probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
    term.append(probe);
    const cw = probe.getBoundingClientRect().width / 100;
    probe.remove();
    const cs = getComputedStyle(term);
    const lh = parseFloat(cs.lineHeight) || 18;
    cols = Math.max(36, Math.floor((term.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)) / cw));
    lines = Math.max(20, Math.round((term.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom)) / lh));
  };

  /* ---------- header and activity strip ---------- */
  const header = (title) => {
    if (title) return ln(`<span class="brandb"> lately </span> ${sp("b", title)}`) + ln();
    const vis = visible();
    const c = [0, 0, 0, 0, 0];
    let hidden = 0;
    rows.forEach((f) => { if (f.t < since() - 1) return; if (shown(f)) c[f.lv] += f.count; else hidden += f.count; });
    hidden += c[0];
    const win = st.follow
      ? sp("b", "since " + hm(since())) + " " + sp("grn", "● live") + sp("f", " " + Math.round((Date.now() - st.fsince) / 1000) + "s")
      : sp("b", "last " + LADDER[st.win]) + sp("f", ` (${hm(since())}–${hm(until())})`);
    let h = `<span class="brandb"> lately </span> ${sp("lv med", "● sample data")}  ${sp("f", "·")}  ${win}  ${sp("f", "·")}  ` +
      `${sp("lv crit b", "✖ " + c[4])} ${sp("lv high", "▲ " + c[3])} ${sp("lv med", "● " + c[2])} ${sp("lv low", "○ " + c[1])}  ${sp("f", "·  " + hidden + " hidden")}`;
    let out = ln(h);
    if (st.status) out += ln(sp("lv high", trunc(st.status, cols)));
    if (st.ladder) {
      out += ln("window " + LADDER.map((w, i) => (i === st.win ? `<span class="pillk">${w}</span>` : w)).join(" ") + "  " + sp("f", "t older · T newer · B since boot"));
    }
    // activity strip: one mark per shown finding across the window
    const w = Math.max(10, cols - 14);
    const cells = Array(w).fill(null);
    const s0 = since(), span = until() - s0;
    vis.forEach((f, i) => {
      const x = Math.min(w - 1, Math.max(0, Math.floor(((f.t - s0) / span) * w)));
      const cur = st.view === "list" && i === st.cur;
      if (!cells[x] || cur || f.lv > cells[x].lv) cells[x] = { lv: f.lv, cur, fresh: f.fresh };
    });
    const col = (c) => (c.cur || c.fresh ? "#3fd6a3" : c.lv >= 3 ? "#ef6f8e" : c.lv === 2 ? "#d8e06a" : "#6fd0e0");
    const strip = cells.map((c) => (c ? `<span class="mk" style="background:${col(c)}"></span>` : "·")).join("");
    out += ln(sp("f", hm(s0) + " ") + `<span class="f">${strip}</span>` + sp(st.follow ? "grn" : "f", st.follow ? " now ●" : " " + hm(until())));
    return out;
  };

  /* ---------- timeline view ---------- */
  const timeline = () => {
    const vis = visible();
    st.cur = Math.max(0, Math.min(st.cur, vis.length - 1));
    const whoW = cols >= 110 ? 24 : cols >= 90 ? 16 : 0;
    const flagW = cols >= 70 ? 16 : 0;
    const whatW = Math.max(12, cols - 2 - 10 - 8 - 10 - whoW - flagW - 2);
    let out = header();
    out += ln(sp("f", "  " + pad("TIME", 10) + pad("LEVEL", 8) + pad("WHAT", 10 + whatW) + (whoW ? pad("WHO", whoW) : "") + (flagW ? "floor ≥" + ["INFO", "LOW", "MED", "HIGH", "CRIT"][st.floor].replace("CRIT", "CRIT") : "")));
    if (!vis.length) out += ln(sp("f", "  Nothing at or above the floor in this window. s lowers the floor, t reaches further back."));
    vis.forEach((f, i) => {
      const on = i === st.cur;
      const time = f.fresh ? sp("grn", pad(hms(f.tl), 10)) : sp("b", pad(hms(f.tl), 10));
      let flags = [];
      if (f.first_seen && !f.known) flags.push(sp("new", "NEW"));
      if (f.known) flags.push(sp("f", "known"));
      if (f.approximate) flags.push(sp("f", "≈approx"));
      const hid = hiddenWhy(f);
      if (hid) flags.push(sp("f", "(" + hid + ")"));
      const row = (on ? '<span class="cur g">▌</span>' : " ") + " " + time + lvs(f) + "  " + sp("", pad(f.category, 10)) +
        sp(on || f.lv >= 2 ? "b" : "", pad(f.title, whatW)) + (whoW ? sp("f", pad(f.who, whoW)) : "") + (flagW ? flags.join(" ") : "");
      out += `<span class="row ln${on ? " sel" : ""}" data-row="${i}">${row}</span>`;
    });
    // detail pane
    const f = vis[st.cur];
    let pane = "";
    if (f) {
      const c = f.card || {};
      const why = (c.why || []).filter((s) => !/does not say/.test(s));
      const rel = related(f);
      pane += rule();
      pane += ln(` ${lvs(f)}  ${sp("b", trunc(f.title, cols - 40))}  ${sp("f", hms(f.tl) + " · rule " + f.rule)}`);
      const pl = [" " + esc(trunc(retime((c.what || [""])[0]), cols - 2))];
      if (why.length) pl.push(" " + sp("f", "why: ") + esc(trunc(retime(why[0]), cols - 8)));
      pl.push(" " + sp("f", "do:  ") + esc(trunc(retime((c.do || [""])[0]), cols - 8)));
      pl.push(rel.length ? " " + sp("grn", "related: " + summary(rel)) + sp("f", "  ⏎ card to follow them") : " " + sp("f", "⏎ full card: who, why it matters, activity, raw evidence and source"));
      while (pl.length < 4) pl.push(" ");
      pane += pl.map((l) => ln(l)).join("");
    }
    pane += rule();
    pane += ln(sp("f", trunc(" ⓘ Sample data, not this Mac · ? lists what lately cannot see", cols)));
    pane += ln(sp("f", trunc(` ↑↓ move  ⏎ card  t/T older/newer  f ${st.follow ? "pause" : "follow"}  s floor  S hidden  a known  A ancestry  R restart  e export  ? help`, cols)));
    return { body: out, foot: pane };
  };

  /* ---------- related findings (a small model of internal/relate) ---------- */
  const related = (f) => {
    const out = [];
    const team = f.subject && f.subject.team_id;
    const vendor = (s) => (s || "").split(".").slice(0, 2).join(".");
    rows.forEach((g) => {
      if (g === f) return;
      let why = "";
      if (g.category === "INSTALL" && team && vendor(g.subject.bundle_id) === vendor(f.subject.bundle_id) && Math.abs(g.t - f.t) < 600e3) why = "install";
      else if (team && g.subject && g.subject.team_id === team) why = "same developer";
      else if (f.subject && g.subject && f.subject.bundle_id && g.subject.bundle_id === f.subject.bundle_id) why = "same app";
      else if (Math.abs(g.t - f.t) <= 120e3 && shown(g)) why = "around then";
      if (why) out.push({ g, why, d: g.t - f.t });
    });
    return out.sort((a, b) => Math.abs(a.d) - Math.abs(b.d)).slice(0, 6);
  };
  const summary = (rel) => {
    const n = {};
    rel.forEach((r) => (n[r.why] = (n[r.why] || 0) + 1));
    return Object.entries(n).map(([k, v]) => v + " " + k).join(" · ");
  };
  const delta = (ms) => {
    const s = Math.round(ms / 1000), a = Math.abs(s), sign = s < 0 ? "-" : "+";
    return a < 60 ? sign + a + "s" : sign + Math.floor(a / 60) + "m" + pad2(a % 60) + "s";
  };

  /* ---------- card view ---------- */
  const card = () => {
    const f = st.stack[st.stack.length - 1];
    const c = f.card || {};
    const W = cols - 9;
    const wrap = (s) => {
      const words = retime(s).split(" "), out = [];
      let cur = "";
      words.forEach((w) => { if ((cur + " " + w).trim().length > W) { out.push(cur); cur = w; } else cur = (cur + " " + w).trim(); });
      if (cur) out.push(cur);
      return out;
    };
    const sec = (name, arr) => {
      let o = "";
      (arr || []).flatMap(wrap).forEach((l, i) => { o += ln((i ? " ".repeat(9) : sp("h", pad(name, 9))) + esc(l)); });
      return o;
    };
    const head = `${GL[f.lv].trim()} · ${f.category} · ${f.title}`;
    const date = day(f.tl) + " " + hms(f.tl);
    let out = ln(sp("lv " + LC[f.lv] + " b", trunc(head, cols - date.length - 4)) + " " + sp("f", "─".repeat(Math.max(1, cols - head.length - date.length - 3))) + " " + sp("lv " + LC[f.lv], date));
    const whoL = (c.who || []).concat(f.first_seen && !(c.who || []).some((w) => /first seen/.test(w)) ? ["first seen on this Mac"] : []);
    out += sec("WHAT", c.what) + sec("WHO", whoL) + sec("WHY", c.why) + sec("MATTERS", c.matters) + sec("DO", c.do) + sec("RAW", c.raw) + sec("SOURCE", c.source);
    // activity
    out += rule("ACTIVITY");
    const w = Math.max(10, cols - 24), s0 = since(), span = until() - s0;
    const x = Math.min(w - 1, Math.max(0, Math.floor(((f.t - s0) / span) * w)));
    out += ln(" ".repeat(9) + sp("f", hm(s0) + " " + "·".repeat(x)) + sp("grn", "█") + sp("f", "·".repeat(w - x - 1) + " " + hm(until())));
    out += ln(" ".repeat(9 + 6 + x) + sp("grn", "▲") + sp("f", ` this · ${f.count} event(s) of ${f.subject.name || f.subject.bundle_id || f.title} in the window`));
    const rel = related(f);
    st.rcur = Math.min(st.rcur, Math.max(0, rel.length - 1));
    if (rel.length) {
      out += rule("RELATED · " + summary(rel) + " · ↑↓ select ⏎ open");
      rel.forEach((r, i) => {
        const on = i === st.rcur, g = r.g;
        const hid = hiddenWhy(g) === "below floor" ? sp("f", " (hidden: below floor)") : "";
        out += `<span class="row ln${on ? " sel" : ""}" data-rel="${i}">${on ? '<span class="g">▌</span>' : " "}${padL(delta(r.d), 8)}  ${pad(r.why, 15)} ${lvs(g)}  ${pad(g.category, 9)}${sp("b", trunc(g.title, cols - 50))}${hid}</span>`;
      });
    }
    return { body: out, foot: rule() + ln(sp("f", trunc(" ↑↓ related · ⏎ open · a known · A ancestry · esc back", cols))) };
  };

  /* ---------- ancestry (from the replayed eslogger capture) ---------- */
  const ancestry = () => {
    const f = st.stack.length ? st.stack[st.stack.length - 1] : st.anc;
    let out = header("Process ancestry");
    const chain = f && f.fields && f.fields.chain;
    if (!chain) {
      out += ln(`No capture covers ${esc(f ? f.subject.name || f.title : "this row")}.`);
      out += ln(sp("f", "Without sudo lately capture, A uses today's process table, which only explains processes that are still running."));
      return { body: out, foot: ln(sp("f", " esc back")) };
    }
    const nodes = chain.split(" → ").map((s) => { const m = s.match(/^(.*)\((\d+)\)$/); return { name: m ? m[1] : s, pid: m ? m[2] : "" }; });
    const lived = parseFloat(f.fields.lived) * 1000 || 0;
    out += ln(`Ancestry · ${esc(f.subject.name)} (pid ${f.subject.pid}) · lived ${esc((f.fields.lived || "").replace("s", " s"))} · ${hms(f.t)} → ${hms(f.t + lived)}`);
    const extra = { "com.foovpn.helper": ["/Library/PrivilegedHelperTools/com.foovpn.helper --check-update", "Dev ID ABCDE12345"], osascript: [`osascript -e do shell script "zsh -c '${(f.fields.args || "").replace(/^zsh -c /, "")}…`, "Apple"], launchd: ["", "Apple"] };
    nodes.forEach((n, i) => {
      const last = i === nodes.length - 1;
      const e = last ? [f.fields.args || "", "Apple"] : extra[n.name] || ["", ""];
      const lead = i === 0 ? "" : "   ".repeat(i - 1) + "└─ ";
      const txt = `${n.name} (${n.pid})`;
      out += ln(esc(lead) + sp(last ? "b" : "", txt) + "  " + sp("", trunc(e[0], Math.max(0, cols - lead.length - txt.length - 22))) + "   " + sp("f", e[1]) + (last ? "   " + sp("grn", "◀") : ""));
    });
    out += ln(`Source: replayed capture since ${hms(f.t - 20e3)} · events before it are unknown`);
    return { body: out, foot: ln(sp("f", " esc back")) };
  };

  /* ---------- why did my Mac restart? (from lately why-restart --json) ---------- */
  const restart = () => {
    const R = DATA.restart || {}, v = R.verdict || {};
    let out = header("Why did my Mac restart?");
    const lc = LC[LV[R.level] ?? 2];
    out += ln(sp("b", "VERDICT") + "  " + sp("lv " + lc, "● " + (v.title || "")));
    const words = (v.explanation || "").split(" ");
    let cur = "";
    words.forEach((w) => { if ((cur + " " + w).length > cols - 2) { out += ln(esc(cur.trim())); cur = w; } else cur += " " + w; });
    if (cur.trim()) out += ln(esc(cur.trim()));
    out += ln(sp("f", "─".repeat(Math.min(cols, 70))));
    (v.checks || []).forEach((c) => {
      out += ln("  " + (c.found ? sp("g", "✓") : sp("f", "·")) + " " + pad(c.name, 11) + " " + esc(trunc(retime(c.text), cols - 40)) + (c.note ? sp("f", "   → " + c.note) : ""));
    });
    out += ln(sp("f", "─".repeat(Math.min(cols, 70))));
    out += ln("  " + esc(trunc("No shutdown cause code: Apple silicon Macs do not log one, so this verdict is inferred from the evidence above.", cols - 2)));
    out += ln("  Confidence: ≈ inferred.");
    return { body: out, foot: ln(sp("f", " esc back")) };
  };

  /* ---------- export (redacted Markdown, the e key) ---------- */
  const exportMd = () => {
    let out = header("Export · redacted Markdown");
    out += ln(sp("b", "# lately · last " + LADDER[st.win])) + ln();
    out += ln(sp("f", "| Time | Level | Category | What | Who | Flags |"));
    out += ln(sp("f", "| --- | --- | --- | --- | --- | --- |"));
    visible().forEach((f) => { out += ln(esc(trunc(`| ${hms(f.tl)} | ${GL[f.lv].trim()} | ${f.category} | ${f.title} | ${f.who} | ${f.approximate ? "≈approx" : ""} |`, cols))); });
    out += ln() + ln(sp("b", "## Limitations"));
    (T.limitations || []).forEach((l) => { out += ln(esc(trunc("- " + l, cols))); });
    out += ln() + ln(sp("f", trunc("_Redacted by lately: home, user and host names, serial, UUIDs, IPs and URL paths are placeholders._", cols)));
    return { body: out, foot: ln(sp("f", " w saves it in the current folder · y copies it · esc back")) };
  };

  const help = () => {
    let out = header("What lately cannot see, levels and keys");
    [
      ...(T.limitations || []).map((l) => sp("h", "ⓘ ") + esc(l)),
      sp("h", "ⓘ ") + "On a real Mac: how far back the unified log reaches, how many fields macOS redacted as &lt;private&gt;,",
      "  that short-lived commands need sudo lately capture, that restart causes are inferred, and that network history needs a firewall extension.",
      "",
      `${sp("lv crit b", "✖ CRIT")} act now · ${sp("lv high", "▲ HIGH")} investigate one occurrence · ${sp("lv med", "● MED")} look if unexpected · ${sp("lv low", "○ LOW")} context · ${sp("lv info", "· INFO")} hidden by default`,
      "Apple-signed rows below MED and rows marked known are hidden; S shows them.",
      "",
      "↑↓/jk move · ⏎ card · s cycle floor · S show hidden · t/T older/newer · f follow · a known · A ancestry · R restart · e export",
    ].forEach((l) => { out += ln(l || " "); });
    return { body: out, foot: ln(sp("f", " any key closes help")) };
  };

  /* ---------- render ---------- */
  const render = () => {
    measure();
    const v = ({ list: timeline, card, ancestry, restart, export: exportMd, help })[st.view]();
    term.innerHTML = `<div class="screen">${v.body}</div><div class="tfoot">${v.foot}</div>`;
    renderKeys();
  };

  const KEYSETS = {
    list: [["⏎", "card", true], ["A", "ancestry"], ["f", "follow"], ["R", "restart"], ["s", "floor"], ["S", "hidden"], ["t", "older"], ["T", "newer"], ["a", "known"], ["e", "export"], ["?", "help"]],
    card: [["⏎", "open related", true], ["A", "ancestry"], ["a", "known"], ["esc", "back"]],
    ancestry: [["esc", "back", true]], restart: [["esc", "back", true]], export: [["esc", "back", true]], help: [["esc", "close", true]],
  };
  const renderKeys = () => {
    let set = KEYSETS[st.view];
    if (st.view === "list" && st.follow) set = set.map((k) => (k[0] === "f" ? ["f", "pause", true] : [k[0], k[1], false]));
    const arrows = st.view === "list" || st.view === "card" ? [["↑", ""], ["↓", ""]] : [];
    keysEl.innerHTML = arrows.concat(set).map(([k, l, p]) => `<button type="button" data-key="${esc(k)}" class="${p ? "primary" : ""}"><b>${esc(k)}</b>${esc(l)}</button>`).join("");
  };

  /* ---------- follow ---------- */
  const stopFollow = () => { timers.forEach(clearTimeout); timers = []; st.follow = false; };
  const startFollow = () => {
    st.follow = true; st.fsince = Date.now(); st.status = "";
    const tick = () => { if (st.follow) { if (st.view === "list") render(); timers.push(setTimeout(tick, 1000)); } };
    timers.push(setTimeout(tick, 1000));
    live.forEach((L) => timers.push(setTimeout(() => {
      if (!st.follow) return;
      const now = Date.now();
      let f;
      if (L.bump) {
        f = rows.find((r) => L.bump.test(r.title));
        if (!f) return;
        f.count += 1; f.title = f.title.replace(/×\d+/, "×" + f.count); f.tl = now; f.fresh = true;
      } else {
        f = mkFinding({ ...L.add, ts: new Date(now - shift).toISOString(), count: 1 });
        f.fresh = true; rows.push(f);
      }
      if (f.lv >= 3) st.status = `${f.lv === 4 ? "✖ new CRIT" : "▲ new HIGH"} at ${hms(now)}: ${f.title}`;
      st.cur = 0;
      if (st.view === "list") render();
    }, reduceMotion ? 300 : L.at)));
  };

  /* ---------- keys ---------- */
  const key = (k) => {
    if (hint) hint.classList.add("gone");
    const vis = visible();
    if (st.view === "help") { st.view = "list"; return render(); }
    if (["ancestry", "restart", "export"].includes(st.view)) {
      if (["esc", "q", "left", "enter"].includes(k)) { st.view = st.stack.length ? "card" : "list"; return render(); }
      if (st.view === "export" && (k === "y" || k === "w")) { st.view = "list"; st.toast = ""; return render(); }
      return false;
    }
    if (st.view === "card") {
      const rel = related(st.stack[st.stack.length - 1]);
      if (k === "up") st.rcur = Math.max(0, st.rcur - 1);
      else if (k === "down") st.rcur = Math.min(rel.length - 1, st.rcur + 1);
      else if (k === "enter" && rel[st.rcur]) { st.stack.push(rel[st.rcur].g); st.rcur = 0; }
      else if (k === "esc" || k === "left" || k === "q") { st.stack.pop(); st.rcur = 0; if (!st.stack.length) st.view = "list"; }
      else if (k === "A") st.view = "ancestry";
      else if (k === "a") { st.stack[st.stack.length - 1].known = true; st.stack = []; st.view = "list"; }
      else if (k === "R") st.view = "restart";
      else return false;
      return render();
    }
    // timeline
    switch (k) {
      case "up": st.cur = Math.max(0, st.cur - 1); break;
      case "down": st.cur = Math.min(vis.length - 1, st.cur + 1); break;
      case "g": st.cur = 0; break;
      case "G": st.cur = vis.length - 1; break;
      case "n": { const i = vis.findIndex((f, j) => j > st.cur && f.lv >= 2); if (i >= 0) st.cur = i; break; }
      case "N": { for (let j = st.cur - 1; j >= 0; j--) if (vis[j].lv >= 2) { st.cur = j; break; } break; }
      case "enter": case "right": if (vis[st.cur]) { st.stack = [vis[st.cur]]; st.rcur = 0; st.view = "card"; } break;
      case "s": st.floor = (st.floor + 1) % 5; st.cur = 0; break;
      case "S": st.all = !st.all; st.cur = 0; break;
      case "t": if (st.follow) break; st.win = Math.min(LADDER.length - 1, st.win + 1); st.ladder = true; break;
      case "T": if (st.follow) break; st.win = Math.max(0, st.win - 1); st.ladder = true; break;
      case "B": st.win = LADDER.length - 1; st.ladder = true; break;
      case "f": if (st.follow) stopFollow(); else startFollow(); break;
      case "a": if (vis[st.cur]) vis[st.cur].known = true; break;
      case "A": if (vis[st.cur]) { st.stack = []; st.anc = vis[st.cur]; st.view = "ancestry"; } break;
      case "R": st.view = "restart"; break;
      case "e": st.view = "export"; break;
      case "?": st.view = "help"; break;
      case "r": rows = T.findings.map(mkFinding); stopFollow(); Object.assign(st, { cur: 0, floor: 2, all: false, win: 1, ladder: false, status: "" }); break;
      case "esc": case "q": if (st.follow) stopFollow(); else return false; break;
      default: return false;
    }
    render();
    return true;
  };
  const KEYMAP = { ArrowUp: "up", k: "up", ArrowDown: "down", j: "down", ArrowLeft: "left", ArrowRight: "right", Enter: "enter", Escape: "esc", Backspace: "esc" };
  term.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const k = KEYMAP[e.key] || (e.key.length === 1 ? e.key : null);
    if (!k) return;
    if (key(k) !== false) e.preventDefault();
  });
  keysEl.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-key]");
    if (!b) return;
    const map = { "↑": "up", "↓": "down", "⏎": "enter" };
    key(map[b.dataset.key] || b.dataset.key);
  });
  term.addEventListener("click", (e) => {
    term.focus({ preventScroll: true });
    const r = e.target.closest("[data-row],[data-rel]");
    if (!r) { if (["help", "restart", "ancestry", "export"].includes(st.view)) key("esc"); return; }
    if (r.dataset.row != null) { const i = +r.dataset.row; if (i === st.cur) key("enter"); else { st.cur = i; render(); } }
    else { const i = +r.dataset.rel; if (i === st.rcur) key("enter"); else { st.rcur = i; render(); } }
  });

  let rt;
  addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(render, 80); });

  render();
})();
