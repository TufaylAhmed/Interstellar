(() => {
  const state = {
    projects: [],
    currentId: null,
    project: null,
    dirty: false,
  };

  const $ = (id) => document.getElementById(id);
  const toast = (msg, err = false) => {
    const el = $("toast");
    el.textContent = msg;
    el.classList.toggle("err", !!err);
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), 3200);
  };

  async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("application/json") ? await res.json() : await res.text();
    if (!res.ok) {
      const msg = (data && data.error) || res.statusText;
      throw new Error(msg);
    }
    return data;
  }

  function markDirty(v = true) {
    state.dirty = v;
    $("btn-save").textContent = v ? "Save edits *" : "Save edits";
  }

  async function refreshList() {
    state.projects = await api("/api/workspace/projects");
    const ul = $("project-list");
    ul.innerHTML = "";
    if (!state.projects.length) {
      ul.innerHTML = '<li style="color:var(--muted);font-size:12px;padding:8px 0;">No projects yet</li>';
      return;
    }
    for (const p of state.projects) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      if (p.id === state.currentId) btn.classList.add("active");
      btn.innerHTML = `${escapeHtml(p.name)}<span class="sub">${p.sources || 0} sources · ${p.rules} rules · ${p.addresses} addr</span>`;
      btn.addEventListener("click", () => openProject(p.id));
      li.appendChild(btn);
      ul.appendChild(li);
    }
  }

  async function openProject(id) {
    if (state.dirty && !confirm("Discard unsaved edits?")) return;
    const p = await api(`/api/workspace/projects/${id}`);
    state.currentId = id;
    state.project = p;
    markDirty(false);
    renderWorkspace();
    await refreshList();
  }

  function renderWorkspace() {
    const p = state.project;
    if (!p) {
      $("empty-state").classList.remove("hidden");
      $("workspace").classList.add("hidden");
      return;
    }
    $("empty-state").classList.add("hidden");
    $("workspace").classList.remove("hidden");
    $("project-title").textContent = p.name;
    $("project-meta").textContent = `id ${p.id.slice(0, 8)}… · updated ${new Date(p.updated_at).toLocaleString()} · vendor ${p.summary.vendor}`;
    const s = p.summary;
    $("stats").innerHTML = [
      ["Sources", p.sources.length],
      ["Addresses", s.addresses],
      ["Addr groups", s.address_groups],
      ["Services", s.services],
      ["Rules", s.security_rules],
      ["NAT", s.nat_rules],
    ]
      .map(([k, v]) => `<div class="stat"><b>${v}</b><span>${k}</span></div>`)
      .join("");

    renderSources();
    renderAddresses();
    renderServices();
    renderRules();
    renderNat();
    renderExport();

    $("dl-xml").href = `/api/workspace/projects/${p.id}/export/xml`;
    $("dl-set").href = `/api/workspace/projects/${p.id}/export/set`;
    $("dl-ir").href = `/api/workspace/projects/${p.id}/export/ir`;
  }

  function renderSources() {
    const body = $("sources-body");
    const sources = state.project.sources || [];
    if (!sources.length) {
      body.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">No configs imported yet</td></tr>';
      return;
    }
    body.innerHTML = sources
      .map((s) => {
        const sum = s.summary || {};
        return `<tr>
          <td>${escapeHtml(s.filename)}</td>
          <td>${escapeHtml(s.vendor)}</td>
          <td>${new Date(s.imported_at).toLocaleString()}</td>
          <td>${sum.security_rules ?? "—"}</td>
          <td>${sum.addresses ?? "—"}</td>
        </tr>`;
      })
      .join("");
  }

  function addrValue(a) {
    const v = a.value || {};
    if (v.kind === "ip_netmask") return v.value || "";
    if (v.kind === "ip_range") return `${v.from || ""}-${v.to || ""}`;
    if (v.kind === "fqdn") return v.value || "";
    if (v.kind === "ip_wildcard") return `${v.ip || ""}/${v.mask || ""}`;
    return JSON.stringify(v);
  }

  function setAddrValue(a, kind, raw) {
    if (kind === "ip_netmask") a.value = { kind: "ip_netmask", value: raw };
    else if (kind === "fqdn") a.value = { kind: "fqdn", value: raw };
    else if (kind === "ip_range") {
      const [from, to] = raw.split("-");
      a.value = { kind: "ip_range", from: (from || "").trim(), to: (to || "").trim() };
    } else a.value = { kind: "ip_netmask", value: raw };
  }

  function renderAddresses() {
    const body = $("addresses-body");
    const rows = state.project.document.addresses || [];
    body.innerHTML = rows
      .map((a, i) => {
        const kind = (a.value && a.value.kind) || "ip_netmask";
        return `<tr>
          <td><input data-i="${i}" data-f="name" value="${escapeAttr(a.name || "")}" /></td>
          <td>
            <select data-i="${i}" data-f="kind">
              <option value="ip_netmask" ${kind === "ip_netmask" ? "selected" : ""}>ip-netmask</option>
              <option value="ip_range" ${kind === "ip_range" ? "selected" : ""}>ip-range</option>
              <option value="fqdn" ${kind === "fqdn" ? "selected" : ""}>fqdn</option>
            </select>
          </td>
          <td><input data-i="${i}" data-f="value" value="${escapeAttr(addrValue(a))}" /></td>
          <td><button class="icon-btn" data-del-addr="${i}">✕</button></td>
        </tr>`;
      })
      .join("") || '<tr><td colspan="4" style="color:var(--muted)">No addresses</td></tr>';

    body.querySelectorAll("input, select").forEach((el) => {
      el.addEventListener("change", () => {
        const i = +el.dataset.i;
        const a = state.project.document.addresses[i];
        if (el.dataset.f === "name") a.name = el.value.trim();
        if (el.dataset.f === "kind" || el.dataset.f === "value") {
          const kindEl = body.querySelector(`select[data-i="${i}"][data-f="kind"]`);
          const valEl = body.querySelector(`input[data-i="${i}"][data-f="value"]`);
          setAddrValue(a, kindEl.value, valEl.value.trim());
        }
        markDirty();
      });
    });
    body.querySelectorAll("[data-del-addr]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.project.document.addresses.splice(+btn.dataset.delAddr, 1);
        markDirty();
        renderAddresses();
      });
    });
  }

  function svcValue(s) {
    const v = s.value || {};
    if (v.kind === "tcp" || v.kind === "udp" || v.kind === "tcp_udp") return v.port || "";
    if (v.kind === "protocol") return String(v.protocol ?? "");
    if (v.kind === "any") return "any";
    return "";
  }

  function setSvcValue(s, kind, raw) {
    if (kind === "tcp") s.value = { kind: "tcp", port: raw };
    else if (kind === "udp") s.value = { kind: "udp", port: raw };
    else if (kind === "tcp_udp") s.value = { kind: "tcp_udp", port: raw };
    else s.value = { kind: "any" };
  }

  function renderServices() {
    const body = $("services-body");
    const rows = state.project.document.services || [];
    body.innerHTML = rows
      .map((s, i) => {
        const kind = (s.value && s.value.kind) || "tcp";
        return `<tr>
          <td><input data-i="${i}" data-f="name" value="${escapeAttr(s.name || "")}" /></td>
          <td>
            <select data-i="${i}" data-f="kind">
              <option value="tcp" ${kind === "tcp" ? "selected" : ""}>tcp</option>
              <option value="udp" ${kind === "udp" ? "selected" : ""}>udp</option>
              <option value="tcp_udp" ${kind === "tcp_udp" ? "selected" : ""}>tcp-udp</option>
              <option value="any" ${kind === "any" ? "selected" : ""}>any</option>
            </select>
          </td>
          <td><input data-i="${i}" data-f="value" value="${escapeAttr(svcValue(s))}" /></td>
          <td><button class="icon-btn" data-del-svc="${i}">✕</button></td>
        </tr>`;
      })
      .join("") || '<tr><td colspan="4" style="color:var(--muted)">No services</td></tr>';

    body.querySelectorAll("input, select").forEach((el) => {
      el.addEventListener("change", () => {
        const i = +el.dataset.i;
        const s = state.project.document.services[i];
        if (el.dataset.f === "name") s.name = el.value.trim();
        if (el.dataset.f === "kind" || el.dataset.f === "value") {
          const kindEl = body.querySelector(`select[data-i="${i}"][data-f="kind"]`);
          const valEl = body.querySelector(`input[data-i="${i}"][data-f="value"]`);
          setSvcValue(s, kindEl.value, valEl.value.trim());
        }
        markDirty();
      });
    });
    body.querySelectorAll("[data-del-svc]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.project.document.services.splice(+btn.dataset.delSvc, 1);
        markDirty();
        renderServices();
      });
    });
  }

  function listField(arr) {
    return (arr || []).join(", ");
  }
  function parseList(s) {
    return s
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function renderRules() {
    const body = $("rules-body");
    const rows = state.project.document.security_rules || [];
    body.innerHTML = rows
      .map((r, i) => `<tr>
        <td><input data-i="${i}" data-f="name" value="${escapeAttr(r.name || "")}" /></td>
        <td><input data-i="${i}" data-f="from_zones" value="${escapeAttr(listField(r.from_zones))}" /></td>
        <td><input data-i="${i}" data-f="to_zones" value="${escapeAttr(listField(r.to_zones))}" /></td>
        <td><input data-i="${i}" data-f="source" value="${escapeAttr(listField(r.source))}" /></td>
        <td><input data-i="${i}" data-f="destination" value="${escapeAttr(listField(r.destination))}" /></td>
        <td><input data-i="${i}" data-f="service" value="${escapeAttr(listField(r.service))}" /></td>
        <td>
          <select data-i="${i}" data-f="action">
            ${["allow","deny","drop","reset_client","reset_server","reset_both"].map((a) =>
              `<option value="${a}" ${r.action === a ? "selected" : ""}>${a}</option>`
            ).join("")}
          </select>
        </td>
        <td><input data-i="${i}" data-f="disabled" type="checkbox" ${r.disabled ? "checked" : ""} /></td>
        <td><button class="icon-btn" data-del-rule="${i}">✕</button></td>
      </tr>`)
      .join("") || '<tr><td colspan="9" style="color:var(--muted)">No rules</td></tr>';

    body.querySelectorAll("input, select").forEach((el) => {
      el.addEventListener("change", () => {
        const i = +el.dataset.i;
        const r = state.project.document.security_rules[i];
        const f = el.dataset.f;
        if (f === "disabled") r.disabled = el.checked;
        else if (["from_zones","to_zones","source","destination","service"].includes(f)) r[f] = parseList(el.value);
        else if (f === "action") r.action = el.value;
        else if (f === "name") r.name = el.value.trim();
        markDirty();
      });
    });
    body.querySelectorAll("[data-del-rule]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.project.document.security_rules.splice(+btn.dataset.delRule, 1);
        markDirty();
        renderRules();
      });
    });
  }

  function renderNat() {
    const body = $("nat-body");
    const rows = state.project.document.nat_rules || [];
    body.innerHTML = rows
      .map((n) => `<tr>
        <td>${escapeHtml(n.name)}</td>
        <td>${escapeHtml(n.nat_type)}</td>
        <td>${escapeHtml(listField(n.from_zones))}</td>
        <td>${escapeHtml(listField(n.to_zones))}</td>
        <td>${escapeHtml(listField(n.source))}</td>
        <td>${escapeHtml(listField(n.destination))}</td>
        <td>${escapeHtml(n.translated_source || n.translated_destination || "—")}</td>
      </tr>`)
      .join("") || '<tr><td colspan="7" style="color:var(--muted)">No NAT rules</td></tr>';
  }

  function renderExport() {
    const v = state.project.validation || { issues: [] };
    $("validation-out").textContent =
      (v.issues || []).map((i) => `[${i.severity}] ${i.code}: ${i.message}`).join("\n") || "No issues";
    $("analysis-out").textContent = state.project.report_markdown || JSON.stringify(state.project.analysis, null, 2);
  }

  function switchTab(name) {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    ["sources","addresses","services","rules","nat","export"].forEach((t) => {
      $(`tab-${t}`).classList.toggle("hidden", t !== name);
    });
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  // Events
  $("btn-create").addEventListener("click", async () => {
    const name = $("new-project-name").value.trim();
    if (!name) return toast("Enter a project name", true);
    try {
      const p = await api("/api/workspace/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      $("new-project-name").value = "";
      state.currentId = p.id;
      state.project = p;
      markDirty(false);
      await refreshList();
      renderWorkspace();
      toast(`Created ${p.name}`);
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("btn-import").addEventListener("click", async () => {
    if (!state.currentId) return toast("Open a project first", true);
    const file = $("import-file").files[0];
    if (!file) return toast("Choose a config file", true);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("vendor", $("import-vendor").value);
    fd.append("filename", file.name);
    const zm = $("import-zone-map").value.trim();
    if (zm) fd.append("zone_map", zm);
    if ($("import-dedup").checked) fd.append("dedup", "true");
    try {
      $("btn-import").disabled = true;
      const res = await api(`/api/workspace/projects/${state.currentId}/import`, {
        method: "POST",
        body: fd,
      });
      state.project = res.project;
      markDirty(false);
      await refreshList();
      renderWorkspace();
      toast(`Merged ${res.source.filename}`);
      $("import-file").value = "";
    } catch (e) {
      toast(e.message, true);
    } finally {
      $("btn-import").disabled = false;
    }
  });

  $("btn-save").addEventListener("click", async () => {
    if (!state.project) return;
    try {
      const p = await api(`/api/workspace/projects/${state.currentId}/document`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ document: state.project.document }),
      });
      state.project = p;
      markDirty(false);
      await refreshList();
      renderWorkspace();
      toast("Saved");
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("btn-dedup").addEventListener("click", async () => {
    if (!state.currentId) return;
    if (state.dirty && !confirm("Save edits first? Dedup uses the last saved document. Continue on saved copy?")) return;
    try {
      const p = await api(`/api/workspace/projects/${state.currentId}/dedup`, { method: "POST" });
      state.project = p;
      markDirty(false);
      await refreshList();
      renderWorkspace();
      toast("Dedup complete");
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("btn-delete").addEventListener("click", async () => {
    if (!state.currentId) return;
    if (!confirm("Delete this project permanently?")) return;
    try {
      await api(`/api/workspace/projects/${state.currentId}`, { method: "DELETE" });
      state.currentId = null;
      state.project = null;
      markDirty(false);
      await refreshList();
      renderWorkspace();
      toast("Deleted");
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("btn-add-address").addEventListener("click", () => {
    state.project.document.addresses = state.project.document.addresses || [];
    state.project.document.addresses.push({
      name: `addr_${state.project.document.addresses.length + 1}`,
      value: { kind: "ip_netmask", value: "10.0.0.0/24" },
      tags: [],
    });
    markDirty();
    renderAddresses();
  });

  $("btn-add-service").addEventListener("click", () => {
    state.project.document.services = state.project.document.services || [];
    state.project.document.services.push({
      name: `svc_${state.project.document.services.length + 1}`,
      value: { kind: "tcp", port: "443" },
    });
    markDirty();
    renderServices();
  });

  $("btn-add-rule").addEventListener("click", () => {
    state.project.document.security_rules = state.project.document.security_rules || [];
    state.project.document.security_rules.push({
      name: `rule_${state.project.document.security_rules.length + 1}`,
      from_zones: ["any"],
      to_zones: ["any"],
      source: ["any"],
      destination: ["any"],
      application: ["any"],
      service: ["any"],
      action: "allow",
      disabled: false,
      log_start: false,
      log_end: true,
      tags: [],
      profiles: {},
    });
    markDirty();
    renderRules();
  });

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  refreshList().catch((e) => toast(e.message, true));
})();
