// Glace Mauve — logique de l'application.
// Toute autorisation réelle est appliquée par la base (RLS + 2FA aal2) ; l'interface ne fait que refléter.
"use strict";
(() => {
  if (window.top !== window.self) { document.documentElement.textContent = ""; return; } // anti-clickjacking

  const CFG = window.GM_CONFIG || {};
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const GATES = ["s-auth", "s-reset", "s-enroll", "s-challenge", "s-codes", "s-pending", "s-profile"];
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* stockage indisponible */ } },
  };

  if (!window.supabase || !CFG.url || !CFG.key) {
    document.body.insertAdjacentHTML("beforeend", '<p class="panel gate">Configuration manquante : impossible de joindre le serveur.</p>');
    return;
  }
  const sb = window.supabase.createClient(CFG.url, CFG.key, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: "pkce" },
  });

  const S = {
    uid: null, admin: false, recovering: false, pendingCodes: null, enrollFactor: null,
    profiles: [], board: [], games: [], members: [], view: "classement",
    editing: null, form: { goals: 0, assists: 0, plus_minus: 0 }, channel: null, reloadTimer: 0, duel: [null, null],
  };

  // ------------------------------------------------------------ utilitaires
  function show(id) {
    for (const g of GATES) $(g).hidden = g !== id;
    $("app").hidden = id !== "app";
    $("btnLogout").hidden = id === "s-auth";
  }
  function msg(el, text, kind) { const m = $(el); m.textContent = text || ""; m.className = "msg" + (kind ? " " + kind : ""); }
  function toast(text, kind) {
    const t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : ""); t.textContent = text;
    $("toasts").append(t); setTimeout(() => t.remove(), 4200);
  }
  function errText(e) {
    if (!e) return "";
    const m = String(e.message || "");
    if (e.code === "42501" || /row-level security|permission denied/i.test(m)) return "Action refusée par le serveur : tu n'as pas le droit de faire ça.";
    if (e.code === "23514") return "Valeur hors des limites permises.";
    if (e.code === "23505") return "Cet élément existe déjà.";
    if (e.code === "54000" || e.code === "22023") return m;
    if (/Invalid login credentials/i.test(m)) return "Courriel ou mot de passe incorrect.";
    if (/Email not confirmed/i.test(m)) return "Confirme d'abord ton courriel avec le lien reçu à l'inscription.";
    if (/rate limit|too many/i.test(m)) return "Trop de tentatives. Patiente quelques minutes.";
    if (/Invalid TOTP|invalid.*code/i.test(m)) return "Code invalide ou expiré. Réessaie avec le code actuel.";
    if (/Password should|weak/i.test(m)) return "Mot de passe trop faible : 10 caractères minimum, évite les mots courants.";
    if (/fetch|network/i.test(m)) return "Connexion au serveur impossible. Vérifie ton réseau.";
    return "Erreur : " + m.slice(0, 140);
  }
  const todayISO = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
  const fmtDate = (iso) => { const [y, m, d] = iso.split("-").map(Number); return new Date(y, m - 1, d).toLocaleDateString("fr-CA", { day: "numeric", month: "short", year: "numeric" }); };
  const fmtPm = (v) => (v > 0 ? "+" + v : v < 0 ? "−" + Math.abs(v) : "0");
  const pmClass = (v) => (v > 0 ? "pm-pos" : v < 0 ? "pm-neg" : "");
  const nameOf = (id) => (S.profiles.find((p) => p.id === id) || {}).display_name || "Joueur";
  const busy = async (btn, fn) => { btn.disabled = true; try { return await fn(); } finally { btn.disabled = false; } };

  // ------------------------------------------------------------ routage d'accès
  async function route() {
    const { data: { session } } = await sb.auth.getSession();
    if (!session) { S.uid = null; teardown(); return show("s-auth"); }
    S.uid = session.user.id;
    const who = await sb.rpc("whoami");
    if (who.error) { show("s-auth"); return msg("aMsg", errText(who.error), "err"); }
    if (!who.data.member) { $("pEmail").textContent = session.user.email || ""; return show("s-pending"); }
    S.admin = !!who.data.admin;

    const { data: aal, error } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error) return toast(errText(error), "err");
    if (aal.currentLevel !== "aal2") return aal.nextLevel === "aal2" ? showChallenge() : showEnroll();
    if (S.pendingCodes) return showCodes(S.pendingCodes);
    if (S.recovering) return show("s-reset");

    const prof = await sb.from("profiles").select("id").eq("id", S.uid).maybeSingle();
    if (prof.error) return toast(errText(prof.error), "err");
    if (!prof.data) { $("pfTitle").textContent = "Crée ton profil de joueur"; $("pfCancel").hidden = true; return show("s-profile"); }
    enterApp();
  }

  // ------------------------------------------------------------ connexion
  let authMode = "login";
  document.querySelectorAll("[data-auth]").forEach((b) => b.addEventListener("click", () => {
    authMode = b.dataset.auth;
    document.querySelectorAll("[data-auth]").forEach((x) => x.classList.toggle("active", x === b));
    $("aSubmit").textContent = authMode === "login" ? "Se connecter" : "Créer mon compte";
    $("aPass").autocomplete = authMode === "login" ? "current-password" : "new-password";
    $("aHint").hidden = authMode === "login";
    msg("aMsg", "");
  }));
  const validEmail = (v) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(v);
  const strongEnough = (p) => p.length >= 10 && p.length <= 72 && new Set(p).size >= 5;

  $("authForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const email = $("aEmail").value.trim().toLowerCase(), password = $("aPass").value;
    if (!validEmail(email)) return msg("aMsg", "Courriel invalide.", "err");
    if (authMode === "signup" && !strongEnough(password)) return msg("aMsg", "Mot de passe trop faible : 10 caractères minimum et variés.", "err");
    busy($("aSubmit"), async () => {
      msg("aMsg", "…");
      if (authMode === "login") {
        const { error } = await sb.auth.signInWithPassword({ email, password });
        if (error) return msg("aMsg", errText(error), "err");
        $("aPass").value = ""; msg("aMsg", ""); route();
      } else {
        const { data, error } = await sb.auth.signUp({ email, password, options: { emailRedirectTo: CFG.siteUrl } });
        if (error) return msg("aMsg", errText(error), "err");
        $("aPass").value = "";
        if (data.session) return route();
        msg("aMsg", "Compte créé. Ouvre le lien de confirmation reçu par courriel, puis reviens te connecter ici.", "good");
      }
    });
  });

  $("aForgot").addEventListener("click", async () => {
    const email = $("aEmail").value.trim().toLowerCase();
    if (!validEmail(email)) return msg("aMsg", "Entre d'abord ton courriel ci-dessus.", "err");
    const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: CFG.siteUrl });
    msg("aMsg", error ? errText(error) : "Si ce compte existe, un lien de réinitialisation vient d'être envoyé.", error ? "err" : "good");
  });

  $("resetForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = $("rPass").value;
    if (!strongEnough(password)) return msg("rMsg", "10 caractères minimum et variés.", "err");
    const { error } = await sb.auth.updateUser({ password });
    if (error) return msg("rMsg", errText(error), "err");
    $("rPass").value = ""; S.recovering = false; toast("Mot de passe mis à jour.", "good"); route();
  });

  $("btnLogout").addEventListener("click", async () => { await sb.auth.signOut(); S.pendingCodes = null; route(); });
  $("btnRecheck").addEventListener("click", route);

  // ------------------------------------------------------------ 2FA
  async function showEnroll() {
    show("s-enroll"); msg("eMsg", "Préparation…");
    const list = await sb.auth.mfa.listFactors();
    for (const f of (list.data?.all || []).filter((f) => f.status !== "verified")) await sb.auth.mfa.unenroll({ factorId: f.id });
    const { data, error } = await sb.auth.mfa.enroll({ factorType: "totp", friendlyName: "Glace Mauve " + new Date().toISOString().slice(0, 16) });
    if (error) return msg("eMsg", errText(error), "err");
    S.enrollFactor = data.id;
    const qr = data.totp.qr_code || "";
    $("eQr").src = qr.startsWith("data:") ? qr : "data:image/svg+xml;utf8," + encodeURIComponent(qr);
    $("eSecret").textContent = data.totp.secret;
    msg("eMsg", ""); $("eCode").value = ""; $("eCode").focus();
  }
  $("enrollForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const code = $("eCode").value.replace(/\D/g, "");
    if (code.length !== 6) return msg("eMsg", "Le code compte 6 chiffres.", "err");
    busy(e.submitter || $("enrollForm").querySelector("button"), async () => {
      const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: S.enrollFactor, code });
      if (error) return msg("eMsg", errText(error), "err");
      const codes = await sb.rpc("generate_recovery_codes");
      if (codes.error) return msg("eMsg", errText(codes.error), "err");
      S.pendingCodes = codes.data; route();
    });
  });

  async function showChallenge() {
    show("s-challenge"); msg("cMsg", ""); $("cCode").value = ""; $("cCode").focus();
  }
  $("challengeForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const code = $("cCode").value.replace(/\D/g, "");
    if (code.length !== 6) return msg("cMsg", "Le code compte 6 chiffres.", "err");
    busy($("challengeForm").querySelector("button"), async () => {
      const list = await sb.auth.mfa.listFactors();
      const factor = list.data?.totp?.[0];
      if (!factor) return showEnroll();
      const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: factor.id, code });
      if (error) return msg("cMsg", errText(error), "err");
      route();
    });
  });
  $("recoverForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const code = $("rcCode").value.trim();
    busy($("recoverForm").querySelector("button"), async () => {
      const { data, error } = await sb.rpc("redeem_recovery_code", { p_code: code });
      if (error) return msg("cMsg", errText(error), "err");
      if (!data) return msg("cMsg", "Code de secours invalide ou déjà utilisé.", "err");
      $("rcCode").value = "";
      await sb.auth.refreshSession();
      toast("Code accepté. Configure maintenant une nouvelle appli d'authentification.", "good");
      showEnroll();
    });
  });

  function showCodes(codes) {
    show("s-codes");
    $("codesList").innerHTML = codes.map((c) => `<li>${esc(c)}</li>`).join("");
    $("codesSaved").checked = false; $("btnCodesDone").disabled = true;
  }
  $("codesSaved").addEventListener("change", (e) => { $("btnCodesDone").disabled = !e.target.checked; });
  $("btnCopyCodes").addEventListener("click", async () => {
    const text = (S.pendingCodes || []).join("\n");
    try { await navigator.clipboard.writeText(text); toast("Codes copiés.", "good"); }
    catch { const r = document.createRange(); r.selectNodeContents($("codesList")); getSelection().removeAllRanges(); getSelection().addRange(r); toast("Sélectionnés : copie-les manuellement."); }
  });
  $("btnCodesDone").addEventListener("click", () => { S.pendingCodes = null; $("codesList").textContent = ""; route(); });

  // ------------------------------------------------------------ profil
  $("profileForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const display_name = $("pfName").value.trim();
    const jRaw = $("pfJersey").value.trim();
    const jersey = jRaw === "" ? null : Number(jRaw);
    const position = $("pfPos").value;
    if (!display_name || display_name.length > 24) return msg("pfMsg", "Nom de 1 à 24 caractères.", "err");
    if (jersey !== null && !(Number.isInteger(jersey) && jersey >= 0 && jersey <= 99)) return msg("pfMsg", "Numéro entre 0 et 99.", "err");
    busy($("profileForm").querySelector(".primary"), async () => {
      const exists = S.profiles.some((p) => p.id === S.uid);
      const q = exists
        ? sb.from("profiles").update({ display_name, jersey, position }).eq("id", S.uid).select("id")
        : sb.from("profiles").insert({ display_name, jersey, position }).select("id");
      const { data, error } = await q;
      if (error || !data?.length) return msg("pfMsg", errText(error) || "Enregistrement refusé.", "err");
      msg("pfMsg", ""); toast("Profil enregistré.", "good"); route();
    });
  });
  $("pfCancel").addEventListener("click", () => enterApp());
  $("btnEditProfile").addEventListener("click", () => {
    const me = S.profiles.find((p) => p.id === S.uid) || {};
    $("pfName").value = me.display_name || ""; $("pfJersey").value = me.jersey ?? ""; $("pfPos").value = me.position || "Attaquant";
    $("pfTitle").textContent = "Modifier mon profil"; $("pfCancel").hidden = false; show("s-profile");
  });

  // ------------------------------------------------------------ application
  function enterApp() {
    show("app");
    $("adminBox").hidden = !S.admin;
    setView(location.hash.slice(1) || S.view);
    reload();
    if (!S.channel) subscribe();
  }
  function teardown() { if (S.channel) { sb.removeChannel(S.channel); S.channel = null; } setSync("idle", "Hors ligne"); }

  async function reload() {
    const [b, g, p] = await Promise.all([
      sb.from("leaderboard").select("*"),
      sb.from("games").select("id,player_id,played_on,opponent,goals,assists,plus_minus,points,created_at").order("played_on", { ascending: false }).order("created_at", { ascending: false }).limit(1000),
      sb.from("profiles").select("id,display_name,jersey,position"),
    ]);
    const err = b.error || g.error || p.error;
    if (err) { setSync("warn", "Erreur"); return toast(errText(err), "err"); }
    S.board = b.data.sort((x, y) => y.points - x.points || y.goals - x.goals || y.plus_minus - x.plus_minus || x.display_name.localeCompare(y.display_name, "fr"));
    S.games = g.data; S.profiles = p.data;
    if (S.admin) {
      const m = await sb.from("league_members").select("email,is_admin,created_at").order("created_at");
      if (!m.error) S.members = m.data;
    }
    render();
  }
  function scheduleReload() { clearTimeout(S.reloadTimer); S.reloadTimer = setTimeout(reload, 300); }

  function subscribe() {
    S.channel = sb.channel("ligue")
      .on("postgres_changes", { event: "*", schema: "public", table: "games" }, (ev) => {
        if (ev.eventType === "INSERT" && ev.new && ev.new.player_id !== S.uid) {
          toast(`${nameOf(ev.new.player_id)} a saisi un match : ${ev.new.goals} B, ${ev.new.assists} A`, "good");
        }
        scheduleReload();
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "profiles" }, scheduleReload)
      .subscribe((status) => {
        if (status === "SUBSCRIBED") setSync("live", "Synchronisé");
        else if (status === "CHANNEL_ERROR" || status === "TIMED_OUT") setSync("warn", "Hors ligne");
      });
  }
  function setSync(state, label) { $("sync").dataset.state = state; $("sync").querySelector("b").textContent = label; }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && S.channel) reload(); });

  // ------------------------------------------------------------ rendu
  function render() {
    renderLeader(); renderRanks(); renderDuel(); renderHistory(); renderLeague();
    window.Scene?.setPlayers(S.board.map((r) => ({ id: r.id, name: r.display_name, points: r.points })));
    $("codesLeft").textContent = "…";
    sb.rpc("recovery_codes_left").then(({ data }) => { $("codesLeft").textContent = data ?? "?"; });
  }

  function renderLeader() {
    const top = S.board[0];
    if (!top || !S.games.length) {
      $("leader").innerHTML = `<span class="tag">Saison en attente</span><p class="name">La glace est vierge</p><p class="muted">Saisis ton premier match dans l'onglet Saisir : les tours du classement s'élèveront ici.</p>`;
      return;
    }
    $("leader").innerHTML = `<span class="tag">En tête du classement</span>
      <p class="name">${esc(top.display_name)}</p>
      <div class="line"><b class="xnum">${top.points}</b><span class="muted">points<br>${top.goals} B · ${top.assists} A · <span class="${pmClass(top.plus_minus)}">${fmtPm(top.plus_minus)}</span></span></div>`;
  }

  function renderRanks() {
    if (!S.board.length) { $("rankList").innerHTML = `<li class="empty">Aucun joueur pour l'instant.</li>`; return; }
    $("rankList").innerHTML = S.board.map((r, i) => {
      const ppg = r.games_played ? (r.points / r.games_played).toFixed(2).replace(".", ",") : "0";
      return `<li class="rank${r.id === S.uid ? " me" : ""}">
        <span class="coin">${i + 1}</span>
        <div class="who"><b>${esc(r.display_name)}${r.jersey != null ? ` <span>#${r.jersey}</span>` : ""}</b>
          <div class="line-stats"><span>${r.games_played} MJ</span><span>${r.goals} B</span><span>${r.assists} A</span><span class="${pmClass(r.plus_minus)}">${fmtPm(r.plus_minus)}</span><span>${ppg} PTS/MJ</span></div></div>
        <div class="pts">${r.points}<small>PTS</small></div></li>`;
    }).join("");
  }

  function renderDuel() {
    const ids = S.board.map((r) => r.id);
    const opts = S.board.map((r) => `<option value="${esc(r.id)}">${esc(r.display_name)}</option>`).join("");
    $("dA").innerHTML = opts; $("dB").innerHTML = opts;
    if (!ids.includes(S.duel[0])) S.duel[0] = ids[0] || null;
    if (!ids.includes(S.duel[1]) || S.duel[1] === S.duel[0]) S.duel[1] = ids.find((x) => x !== S.duel[0]) || null;
    if (S.duel[0]) $("dA").value = S.duel[0];
    if (S.duel[1]) $("dB").value = S.duel[1];
    const a = S.board.find((r) => r.id === S.duel[0]), b = S.board.find((r) => r.id === S.duel[1]);
    if (!a || !b) { $("duel").innerHTML = `<p class="empty">Il faut deux joueurs pour un duel. Invite un ami dans l'onglet Ligue.</p>`; return; }
    const ppg = (r) => (r.games_played ? r.points / r.games_played : 0);
    const metrics = [["Points", a.points, b.points], ["Buts", a.goals, b.goals], ["Passes", a.assists, b.assists], ["Différentiel +/−", a.plus_minus, b.plus_minus], ["Points par match", ppg(a), ppg(b)]];
    $("duel").innerHTML = metrics.map(([label, va, vb], i) => {
      const span = Math.max(Math.abs(va), Math.abs(vb), 1);
      const f = (v) => (i === 4 ? v.toFixed(2).replace(".", ",") : i === 3 ? fmtPm(v) : v);
      return `<div class="d-row"><span class="d-label">${label}</span><b>${f(va)}</b>
        <div class="d-bars"><div class="d-bar l"><i data-w="${(Math.abs(va) / span) * 100}"${va < 0 ? ' class="neg"' : ""}></i></div><div class="d-bar r"><i data-w="${(Math.abs(vb) / span) * 100}"${vb < 0 ? ' class="neg"' : ""}></i></div></div>
        <b>${f(vb)}</b></div>`;
    }).join("");
    requestAnimationFrame(() => $("duel").querySelectorAll("i[data-w]").forEach((el) => el.style.setProperty("--w", el.dataset.w + "%")));
  }
  $("dA").addEventListener("change", (e) => { S.duel[0] = e.target.value; renderDuel(); });
  $("dB").addEventListener("change", (e) => { S.duel[1] = e.target.value; renderDuel(); });

  function renderHistory() {
    const sel = $("hPlayer"), cur = sel.value || "all";
    sel.innerHTML = `<option value="all">Tous les joueurs</option>` + S.profiles.map((p) => `<option value="${esc(p.id)}">${esc(p.display_name)}</option>`).join("");
    sel.value = [...sel.options].some((o) => o.value === cur) ? cur : "all";
    const list = S.games.filter((g) => sel.value === "all" || g.player_id === sel.value);
    if (!list.length) { $("hList").innerHTML = `<li class="empty">Aucun match enregistré.</li>`; return; }
    $("hList").innerHTML = list.map((g) => {
      const mine = g.player_id === S.uid;
      return `<li class="game" data-id="${esc(g.id)}">
        <div class="g-top">${esc(nameOf(g.player_id))}${g.opponent ? ` <span class="muted">contre ${esc(g.opponent)}</span>` : ""}</div>
        <div class="g-pts">${g.points}<span class="muted small"> PTS</span></div>
        <div class="g-sub">${fmtDate(g.played_on)} · ${g.goals} B · ${g.assists} A · <span class="${pmClass(g.plus_minus)}">${fmtPm(g.plus_minus)}</span></div>
        ${mine ? `<div class="g-act"><button type="button" class="btn small" data-act="edit">Modifier</button><button type="button" class="btn small ghost" data-act="del">Supprimer</button></div>` : ""}
      </li>`;
    }).join("");
  }
  $("hPlayer").addEventListener("change", renderHistory);
  $("hList").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]"); if (!btn) return;
    const id = btn.closest(".game").dataset.id, g = S.games.find((x) => x.id === id); if (!g) return;
    if (btn.dataset.act === "edit") return startEdit(g);
    if (btn.dataset.armed !== "1") { btn.dataset.armed = "1"; btn.textContent = "Confirmer ?"; btn.classList.add("danger"); setTimeout(() => { btn.dataset.armed = ""; btn.textContent = "Supprimer"; btn.classList.remove("danger"); }, 3500); return; }
    const { data, error } = await sb.from("games").delete().eq("id", id).select("id");
    if (error || !data?.length) return toast(errText(error) || "Suppression refusée par le serveur.", "err");
    toast("Match supprimé.", "good"); reload();
  });

  function renderLeague() {
    $("pGrid").innerHTML = S.profiles.map((p) => `<div class="jersey${p.id === S.uid ? " me" : ""}"><div class="num">${p.jersey ?? "—"}</div><b>${esc(p.display_name)}</b><span>${esc(p.position)}${p.id === S.uid ? " · moi" : ""}</span></div>`).join("") || `<p class="empty">Aucun joueur.</p>`;
    if (!S.admin) return;
    $("memberList").innerHTML = S.members.map((m) => `<li><span>${esc(m.email)}${m.is_admin ? ' <span class="muted small">(admin)</span>' : ""}</span>${m.is_admin ? "" : `<button type="button" class="btn small ghost" data-email="${esc(m.email)}">Retirer</button>`}</li>`).join("");
  }
  $("inviteForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = $("iEmail").value.trim().toLowerCase();
    if (!validEmail(email)) return msg("iMsg", "Courriel invalide.", "err");
    const { error } = await sb.from("league_members").insert({ email, is_admin: false, invited_by: S.uid });
    if (error) return msg("iMsg", errText(error), "err");
    $("iEmail").value = ""; msg("iMsg", `Invitation enregistrée. Envoie-lui le lien de l'app : il crée son compte avec ${email}.`, "good"); reload();
  });
  $("memberList").addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-email]"); if (!b) return;
    if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Confirmer ?"; return; }
    const { error } = await sb.from("league_members").delete().eq("email", b.dataset.email);
    if (error) return msg("iMsg", errText(error), "err");
    reload();
  });
  $("btnRegen").addEventListener("click", async () => {
    const codes = await sb.rpc("generate_recovery_codes");
    if (codes.error) return toast(errText(codes.error), "err");
    S.pendingCodes = codes.data; showCodes(codes.data);
  });
  $("btnExport").addEventListener("click", () => {
    const cell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
    const rows = [["Date", "Joueur", "Adversaire", "Buts", "Passes", "Points", "Plus-moins"]]
      .concat(S.games.map((g) => [g.played_on, cell(nameOf(g.player_id)), cell(g.opponent), g.goals, g.assists, g.points, g.plus_minus]));
    const blob = new Blob(["﻿" + rows.map((r) => r.join(",")).join("\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "glace-mauve-matchs.csv"; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  // ------------------------------------------------------------ saisie
  function setStep(field, v) {
    const el = document.querySelector(`.stepper[data-field="${field}"]`);
    const min = Number(el.dataset.min), max = Number(el.dataset.max);
    S.form[field] = Math.max(min, Math.min(max, v));
    el.querySelector(".st-val").textContent = field === "plus_minus" ? fmtPm(S.form[field]) : S.form[field];
    $("gPts").textContent = S.form.goals + S.form.assists;
  }
  document.querySelectorAll(".stepper").forEach((el) => el.addEventListener("click", (e) => {
    const b = e.target.closest(".st-btn"); if (!b) return;
    setStep(el.dataset.field, S.form[el.dataset.field] + Number(b.dataset.d));
    if (navigator.vibrate) try { navigator.vibrate(8); } catch { /* ignoré */ }
  }));
  function resetForm() {
    S.editing = null; $("gDate").value = todayISO(); $("gDate").max = todayISO(); $("gOpp").value = "";
    ["goals", "assists", "plus_minus"].forEach((f) => setStep(f, 0));
    $("gfTitle").textContent = "Nouveau match"; $("gSubmit").textContent = "Enregistrer le match"; $("gCancel").hidden = true;
  }
  function startEdit(g) {
    S.editing = g.id; $("gDate").value = g.played_on; $("gOpp").value = g.opponent || "";
    setStep("goals", g.goals); setStep("assists", g.assists); setStep("plus_minus", g.plus_minus);
    $("gfTitle").textContent = "Modifier le match"; $("gSubmit").textContent = "Mettre à jour"; $("gCancel").hidden = false;
    setView("saisir");
  }
  $("gCancel").addEventListener("click", () => { resetForm(); setView("historique"); });
  $("gameForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const played_on = $("gDate").value, opponent = $("gOpp").value.trim() || null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(played_on) || played_on > todayISO() || played_on < "2000-01-01") return msg("gMsg", "Choisis une date valide (pas dans le futur).", "err");
    if (opponent && opponent.length > 40) return msg("gMsg", "Nom d'adversaire trop long (40 max).", "err");
    const body = { played_on, opponent, goals: S.form.goals, assists: S.form.assists, plus_minus: S.form.plus_minus };
    busy($("gSubmit"), async () => {
      const q = S.editing ? sb.from("games").update(body).eq("id", S.editing).select("id") : sb.from("games").insert(body).select("id");
      const { data, error } = await q;
      if (error || !data?.length) return msg("gMsg", errText(error) || "Enregistrement refusé par le serveur.", "err");
      msg("gMsg", ""); toast(S.editing ? "Match mis à jour." : `Match enregistré : ${body.goals + body.assists} PTS`, "good");
      resetForm(); reload(); setView("classement");
    });
  });

  // ------------------------------------------------------------ navigation et effets
  function setView(v) {
    if (!["classement", "saisir", "historique", "ligue"].includes(v)) v = "classement";
    S.view = v;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === v));
    document.querySelectorAll(".view").forEach((s) => { s.hidden = s.id !== "v-" + v; });
    if (location.hash.slice(1) !== v) history.replaceState(null, "", "#" + v);
    window.scrollTo({ top: 0 });
  }
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setView(t.dataset.view)));

  const fxSel = $("fxMode");
  fxSel.value = store.get("gm.fx") || "auto";
  const applyFx = () => window.Scene?.init($("rink3d"), fxSel.value);
  fxSel.addEventListener("change", () => { store.set("gm.fx", fxSel.value); applyFx(); render(); });
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change", () => { applyFx(); render(); });

  if (matchMedia("(hover: hover) and (pointer: fine)").matches) {
    let last = null;
    document.addEventListener("pointermove", (e) => {
      const el = window.Scene?.level() === "full" ? e.target.closest?.(".tilt") : null;
      if (last && last !== el) { last.style.setProperty("--rx", "0deg"); last.style.setProperty("--ry", "0deg"); }
      last = el; if (!el) return;
      const r = el.getBoundingClientRect();
      el.style.setProperty("--ry", (((e.clientX - r.left) / r.width - 0.5) * 6).toFixed(2) + "deg");
      el.style.setProperty("--rx", ((-(e.clientY - r.top) / r.height + 0.5) * 6).toFixed(2) + "deg");
    }, { passive: true });
  }

  // ------------------------------------------------------------ démarrage
  sb.auth.onAuthStateChange((event) => {
    if (event === "PASSWORD_RECOVERY") { S.recovering = true; setTimeout(route, 0); }
    if (event === "SIGNED_OUT") setTimeout(route, 0);
  });
  applyFx();
  resetForm();
  route();
})();
