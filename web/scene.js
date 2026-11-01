// Patinoire 3D : tours de classement, rondelle du meneur, éclats de glace.
// Niveaux : full / low (30 i/s, moins d'objets) / still (une image, mouvement réduit) / off.
"use strict";
window.Scene = (() => {
  let renderer, scene, camera, puck, raf = 0, level = "off", players = [];
  const towers = new Map();
  const shards = [];
  let px = 0, py = 0, lastT = 0, acc = 0, frames = 0, skip = false;

  const hasGL = () => typeof window.THREE !== "undefined";

  function detectLevel(mode) {
    if (mode === "off" || !hasGL()) return "off";
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return "still";
    const weak = (navigator.hardwareConcurrency || 8) <= 4 || (navigator.deviceMemory || 8) <= 3 ||
      (navigator.connection && navigator.connection.saveData);
    return mode === "low" || weak ? "low" : "full";
  }

  function init(canvas, mode) {
    destroy();
    level = detectLevel(mode);
    document.documentElement.classList.toggle("fx-off", level === "off");
    document.documentElement.classList.toggle("fx-low", level === "low" || level === "still");
    if (level === "off") return level;
    const T = window.THREE;
    try {
      renderer = new T.WebGLRenderer({ canvas, antialias: level === "full", alpha: true, powerPreference: level === "full" ? "high-performance" : "low-power" });
    } catch (e) {
      level = "off";
      document.documentElement.classList.add("fx-off");
      return level;
    }
    renderer.setPixelRatio(Math.min(devicePixelRatio || 1, level === "full" ? 1.75 : 1));
    renderer.setSize(innerWidth, innerHeight, false);
    scene = new T.Scene();
    scene.fog = new T.FogExp2(0x0d0718, 0.045);
    camera = new T.PerspectiveCamera(45, innerWidth / innerHeight, 0.1, 100);

    scene.add(new T.AmbientLight(0x6a4bb0, 0.7));
    const sun = new T.DirectionalLight(0xffffff, 0.75); sun.position.set(4, 10, 6); scene.add(sun);
    const pv = new T.PointLight(0x8b5cf6, 2.4, 30); pv.position.set(-5, 4, 3); scene.add(pv);
    const pc = new T.PointLight(0x7fe7ff, 1.6, 30); pc.position.set(5, 3, -2); scene.add(pc);

    const floor = new T.Mesh(new T.PlaneGeometry(60, 60), new T.MeshStandardMaterial({ color: 0x140b28, metalness: 0.6, roughness: 0.35 }));
    floor.rotation.x = -Math.PI / 2; scene.add(floor);
    const grid = new T.GridHelper(60, 60, 0x7fe7ff, 0x3b2370);
    grid.material.transparent = true; grid.material.opacity = 0.22; grid.position.y = 0.005; scene.add(grid);
    const lineMat = new T.MeshBasicMaterial({ color: 0x7fe7ff, transparent: true, opacity: 0.55, side: T.DoubleSide });
    const ring = new T.Mesh(new T.RingGeometry(2.6, 2.7, 72), lineMat); ring.rotation.x = -Math.PI / 2; ring.position.set(0, 0.01, 1.5); scene.add(ring);
    const red = new T.Mesh(new T.PlaneGeometry(0.16, 40), new T.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.7 }));
    red.rotation.x = -Math.PI / 2; red.rotation.z = Math.PI / 2; red.position.set(0, 0.012, 1.5); scene.add(red);

    puck = new T.Group();
    puck.add(new T.Mesh(new T.CylinderGeometry(0.8, 0.8, 0.32, 48), new T.MeshStandardMaterial({ color: 0x120a22, metalness: 0.85, roughness: 0.25, emissive: 0x2a1150 })));
    const rim = new T.Mesh(new T.TorusGeometry(0.82, 0.045, 10, 64), new T.MeshBasicMaterial({ color: 0x7fe7ff }));
    rim.rotation.x = Math.PI / 2; puck.add(rim);
    scene.add(puck);

    const n = level === "full" ? 36 : 12;
    const shardMat = new T.MeshStandardMaterial({ color: 0x7fe7ff, emissive: 0x1b6c80, transparent: true, opacity: 0.55, flatShading: true });
    for (let i = 0; i < n; i++) {
      const m = new T.Mesh(new T.IcosahedronGeometry(0.1 + Math.random() * 0.2, 0), shardMat);
      m.position.set((Math.random() - 0.5) * 22, Math.random() * 8, (Math.random() - 0.5) * 14 - 2);
      m.userData.v = 0.15 + Math.random() * 0.35;
      shards.push(m); scene.add(m);
    }

    addEventListener("resize", onResize);
    addEventListener("pointermove", onPointer, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    setPlayers(players);
    if (level === "still") renderOnce(); else start();
    return level;
  }

  function labelTexture(name, pts) {
    const T = window.THREE;
    const c = document.createElement("canvas"); c.width = 256; c.height = 128;
    const g = c.getContext("2d");
    g.textAlign = "center";
    g.fillStyle = "#f7f4ff"; g.font = "700 30px Outfit, sans-serif";
    g.fillText(name.length > 14 ? name.slice(0, 13) + "…" : name, 128, 44);
    g.fillStyle = "#7fe7ff"; g.font = "900 46px Unbounded, sans-serif";
    g.fillText(pts + " PTS", 128, 104);
    const tex = new T.CanvasTexture(c);
    return tex;
  }

  // list : [{id, name, points}] déjà trié.
  function setPlayers(list) {
    players = list.slice(0, 6);
    if (!scene) return;
    const T = window.THREE;
    const max = Math.max(1, ...players.map(p => p.points));
    const slots = [0, -2.6, 2.6, -5, 5, -7.2];
    const keep = new Set(players.map(p => p.id));
    for (const [id, t] of towers) if (!keep.has(id)) { scene.remove(t.group); t.mat.dispose(); t.label.material.map.dispose(); t.label.material.dispose(); towers.delete(id); }
    players.forEach((p, i) => {
      let t = towers.get(p.id);
      if (!t) {
        const geo = new T.BoxGeometry(1.5, 1, 1.5); geo.translate(0, 0.5, 0);
        const mat = new T.MeshStandardMaterial({ color: 0x5b2fc9, metalness: 0.4, roughness: 0.3, emissive: 0x2a1170 });
        const body = new T.Mesh(geo, mat);
        const edges = new T.LineSegments(new T.EdgesGeometry(geo), new T.LineBasicMaterial({ color: 0x7fe7ff, transparent: true, opacity: 0.8 }));
        const label = new T.Sprite(new T.SpriteMaterial({ transparent: true, depthWrite: false }));
        label.scale.set(2.6, 1.3, 1);
        const group = new T.Group(); group.add(body, edges, label);
        scene.add(group);
        t = { group, body, edges, label, mat, h: 0.3, key: "" };
        towers.set(p.id, t);
      }
      t.target = 0.5 + 4.2 * (p.points / max);
      t.x = slots[i]; t.group.position.set(t.x, 0, -Math.abs(t.x) * 0.3);
      t.mat.color.setHex(i === 0 ? 0x8b5cf6 : 0x5b2fc9);
      t.mat.emissive.setHex(i === 0 ? 0x3d1a9e : 0x22105a);
      const key = p.name + "|" + p.points;
      if (key !== t.key) {
        if (t.label.material.map) t.label.material.map.dispose();
        t.label.material.map = labelTexture(p.name, p.points); t.label.material.needsUpdate = true; t.key = key;
      }
      if (level === "still") t.h = t.target;
    });
    if (level === "still") renderOnce();
  }

  function step(dt, time) {
    for (const t of towers.values()) {
      t.h += (t.target - t.h) * Math.min(1, dt * 3);
      t.body.scale.y = t.edges.scale.y = t.h;
      t.label.position.y = t.h + 0.9;
    }
    const lead = players[0] && towers.get(players[0].id);
    const lx = lead ? lead.x : 0, ly = lead ? lead.h + 2.1 : 2;
    puck.position.set(lx, ly + Math.sin(time * 1.6) * 0.15, lead ? lead.group.position.z : 0);
    puck.rotation.y += dt * 1.2; puck.rotation.z = Math.sin(time * 0.9) * 0.25;
    for (const s of shards) {
      s.position.y += s.userData.v * dt; s.rotation.x += dt * 0.6; s.rotation.y += dt * 0.4;
      if (s.position.y > 9) s.position.y = -0.2;
    }
    const ang = Math.sin(time * 0.07) * 0.35 + px * 0.22;
    camera.position.set(Math.sin(ang) * 12.5, 5.6 + py * 0.6, Math.cos(ang) * 12.5);
    camera.lookAt(0, 2, 0);
  }

  function frame(now) {
    raf = requestAnimationFrame(frame);
    const dt = Math.min(0.1, (now - lastT) / 1000 || 0.016); lastT = now;
    if (level === "low") { skip = !skip; if (skip) return; }
    // Surveillance : si l'appareil peine, on rétrograde automatiquement.
    acc += dt; frames++;
    if (frames === 90) {
      const avg = acc / frames;
      if (level === "full" && avg > 0.034) { level = "low"; renderer.setPixelRatio(1); shards.splice(12).forEach(s => scene.remove(s)); document.documentElement.classList.add("fx-low"); }
      else if (level === "low" && avg > 0.05) { level = "still"; stop(); renderOnce(); return; }
      acc = 0; frames = 0;
    }
    step(dt, now / 1000);
    renderer.render(scene, camera);
  }

  function renderOnce() { if (!renderer) return; step(0, 0); for (const t of towers.values()) { t.h = t.target; t.body.scale.y = t.edges.scale.y = t.h; t.label.position.y = t.h + 0.9; } renderer.render(scene, camera); }
  function start() { if (!raf && renderer && level !== "still") { lastT = performance.now(); raf = requestAnimationFrame(frame); } }
  function stop() { if (raf) cancelAnimationFrame(raf); raf = 0; }
  function onVisibility() { if (document.hidden) stop(); else start(); }
  function onPointer(e) { px = e.clientX / innerWidth - 0.5; py = e.clientY / innerHeight - 0.5; if (level === "still") return; }
  function onResize() {
    if (!renderer) return;
    camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix();
    renderer.setSize(innerWidth, innerHeight, false);
    if (level === "still") renderOnce();
  }

  function destroy() {
    stop();
    removeEventListener("resize", onResize);
    removeEventListener("pointermove", onPointer);
    document.removeEventListener("visibilitychange", onVisibility);
    towers.clear(); shards.length = 0;
    if (renderer) { renderer.dispose(); renderer = null; }
    scene = null;
  }

  return { init, setPlayers, level: () => level };
})();
