(function(){
    // Theme handling (centralized)
    const THEME_KEY = 'theme';

    function applyTheme(theme){
        const mode = theme === 'dark' ? 'dark' : 'light';
        try{
            document.documentElement.setAttribute('data-theme', mode);
            document.body.setAttribute('data-theme', mode);
        }catch(e){}
        localStorage.setItem(THEME_KEY, mode);
        try{
            const toggles = document.querySelectorAll('#theme-toggle');
            toggles.forEach(t=> t.textContent = mode === 'dark' ? '🌙' : '☀️');
        }catch(e){}
        try{
            const sel = document.getElementById('theme-select');
            if(sel) sel.value = mode === 'dark' ? 'Dark' : 'Light';
        }catch(e){}
    }

    function initThemeControls(){
        const saved = localStorage.getItem(THEME_KEY);
        if(saved) applyTheme(saved); else applyTheme('light');

        try{
            const toggles = document.querySelectorAll('#theme-toggle');
            toggles.forEach(t=>{
                t.addEventListener('click', ()=>{
                    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                    applyTheme(cur === 'dark' ? 'light' : 'dark');
                });
            });
        }catch(e){}

        try{
            const sel = document.getElementById('theme-select');
            if(sel){
                sel.addEventListener('change', ()=>{
                    const next = sel.value === 'Dark' ? 'dark' : 'light';
                    applyTheme(next);
                });
            }
        }catch(e){}

        window.addEventListener('storage', (e)=>{
            if(e.key === THEME_KEY && e.newValue) applyTheme(e.newValue);
        });
    }

    async function getSessionUser(){
    try {
        const res = await fetch("http://localhost:5000/me", {
            credentials: "include"
        });
        return res.ok ? res.json() : null;
    } catch(e){
        return null;
    }
}


    async function logout(){
    try{
        await fetch("http://localhost:5000/logout", {
            method: "POST",
            credentials: "include"
        });
    }catch(e){}
    window.location.href = "index.html";
}


    // Format a date/time value to IST (Asia/Kolkata)
    function formatToIST(dateVal){
        if(!dateVal) return '—';
        try{
            const d = new Date(dateVal);
            if(isNaN(d)) return String(dateVal);
            return d.toLocaleString('en-IN', {
                timeZone: 'Asia/Kolkata',
                year: 'numeric', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }catch(e){
            return String(dateVal);
        }
    }

    function showLoginModal(triggerElement){
        // If a static modal exists in the page, show it instead of creating a new one
        const staticModal = document.getElementById('loginModal') || document.getElementById('login-modal');
        if(staticModal){
            staticModal.style.display = 'flex';
            return;
        }

        const modal = document.createElement('div');
        modal.id = 'login-modal';
        modal.style = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);z-index:9999;';
        modal.innerHTML = `
            <div style="background:#fff;color:#111;border-radius:10px;padding:20px;max-width:380px;width:95%;box-shadow:0 8px 28px rgba(2,6,23,0.5);">
                <h3 style="margin:0 0 8px;font-size:18px">Sign in</h3>
                <p style="margin:0 0 12px;color:#444;font-size:13px">Enter your username and password to continue.</p>
                <div style="display:flex;flex-direction:column;gap:8px">
                    <input id="login-username" placeholder="Username" style="padding:8px;border-radius:6px;border:1px solid #ddd" />
                    <input id="login-password" type="password" placeholder="Password" style="padding:8px;border-radius:6px;border:1px solid #ddd" />
                    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">
                        <button id="login-cancel" style="padding:8px 12px;border-radius:6px;background:#eee;border:0;">Cancel</button>
                        <button id="login-submit" style="padding:8px 12px;border-radius:6px;background:linear-gradient(90deg,#6366f1,#a855f7);color:#fff;border:0;">Sign in</button>
                    </div>
                    <div id="login-error" style="color:#b91c1c;font-size:13px;display:none;margin-top:8px"></div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        modal.querySelector('#login-cancel').addEventListener('click', ()=>{ modal.remove(); });

        modal.querySelector('#login-submit').addEventListener('click', async ()=>{
            const u = modal.querySelector('#login-username').value.trim();
            const p = modal.querySelector('#login-password').value;
            const err = modal.querySelector('#login-error');
            err.style.display = 'none';
            if(!u || !p){ 
                err.textContent = 'Please enter username and password.'; 
                err.style.display = 'block'; 
                return; 
            }
            try{
                const response = await fetch("http://localhost:5000/login",{
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    credentials: "include",
                    body: JSON.stringify({ username: u, password: p })
                });
                const result = await response.json();
                modal.remove();
                if(result.role === "admin"){
                    window.location.href = "admin.html";
                } else {
                    window.location.href = "user.html";
                }

            } catch(e){
                console.log(e);
            }
        });
    }
    
    document.addEventListener('DOMContentLoaded', async ()=>{

    try { initThemeControls(); } catch(e){}

    const path = window.location.pathname;
    const isDashboard =
        path.includes("user.html") ||
        path.includes("admin.html");

    let currentUser = null;

    if (isDashboard) {
        currentUser = await getSessionUser();
        if (!currentUser) {
            console.warn("Not logged in → redirecting to home");
            return window.location.href = "index.html";
        }
        console.log("Dashboard loaded for:", currentUser.username, "role:", currentUser.role);
    }

    const username = currentUser?.username || null;

        // Wire static login modal (if present in HTML) to backend login
        try{
            const staticModal = document.getElementById('loginModal');
            if(staticModal){
                const closeBtn = document.getElementById('closeLogin');
                if(closeBtn) closeBtn.addEventListener('click', ()=>{ staticModal.style.display = 'none'; });

                const form = staticModal.querySelector('form');
                if(form){
                    form.addEventListener('submit', async (ev)=>{
                        ev.preventDefault();
                        const inputs = form.querySelectorAll('input');
                        const username = inputs[0]?.value?.trim();
                        const password = inputs[1]?.value || '';
                        if(!username || !password){
                            alert('Please provide username and password.');
                            return;
                        }
                        try{
                            const response = await fetch('http://localhost:5000/login',{
                                credentials: 'include',
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ username, password })
                            });
                            const result = await response.json();
                            staticModal.style.display = 'none';
                            if(result.role === 'admin') window.location.href = 'admin.html'; 
                            else window.location.href = 'user.html';
                        }catch(err){
                            console.error(err);
                            alert('Login failed.');
                        }
                    });
                }
            }
        }catch(e){ console.log('login modal wiring failed', e); }

        const dash = document.getElementById('dashboard-link');
        if(dash) dash.addEventListener('click', async (e)=>{
            e.preventDefault();
            try{
                const current = await getSessionUser();
                if(current){
                    if(current.role === 'admin') window.location.href = 'admin.html';
                    else window.location.href = 'user.html';
                    return;
                }
            }catch(err){/* ignore and show modal */}
            showLoginModal(dash);
        });

        const goBtn = document.getElementById('go-dashboard');
        if(goBtn) goBtn.addEventListener('click', async ()=>{
            try{
                const current = await getSessionUser();
                if(current){
                    if(current.role === 'admin') window.location.href = 'admin.html';
                    else window.location.href = 'user.html';
                    return;
                }
            }catch(err){/* ignore and show modal */}
            showLoginModal(goBtn);
        });

        const tryNow = document.getElementById('try-now');
        if(tryNow) tryNow.addEventListener('click', ()=> showLoginModal());

        // helper to save history AFTER explanation
        async function saveHistoryAfterExplain(){
            try{
                const current = await getSessionUser();
                const user = current;
                if(!user || !user.username) return;

                const language = document.getElementById("language")?.value || "Auto";
                const action = document.getElementById("code-input")?.value || "";

                if(!action.trim()) return;

                await fetch("http://localhost:5000/add-history",{
                    credentials: "include",
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body:JSON.stringify({
                        username: user.username,
                        role: user.role,
                        action,
                        language
                    })
                });
            }catch(err){
                console.log("Failed to save history", err);
            }
        }

        // USER PAGE: generate explanation (and save history)
        const explainBtn = document.querySelector(".bottom-cta .btn-primary");
        if (explainBtn) {
            explainBtn.addEventListener("click", async () => {
                const codeEl = document.getElementById("code-input");
                const langEl = document.getElementById("language");
                const view = document.getElementById("explanation-view");

                const code = (codeEl?.value || "").trim();
                const language = langEl ? langEl.value : "Auto";

                if (!code) {
                    alert("Please paste some code first.");
                    return;
                }

                if (view) {
                    view.innerHTML = `
                        <div class="placeholder">
                            <div class="placeholder-icon">⏳</div>
                            <div>Generating explanation...</div>
                        </div>
                    `;
                }

                try {
                    const res = await fetch("http://localhost:5000/api/explain", {
                        credentials: "include",
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ code, language })
                    });

                    const data = await res.json();

                    if (!res.ok) {
                        throw new Error(data.message || "Server error");
                    }

                    if (view) {
                        view.innerHTML = `
                            <div style="white-space: pre-wrap; font-size: 13px; line-height: 1.5;">
                                ${data.explanation || "No explanation returned."}
                            </div>
                        `;
                    }

                    // 👉 save history only after successful explanation
                    await saveHistoryAfterExplain();

                } catch (err) {
                    console.error(err);
                    if (view) {
                        view.innerHTML = `
                            <div class="placeholder">
                                <div class="placeholder-icon">⚠️</div>
                                <div>Failed to generate explanation: ${err.message}</div>
                            </div>
                        `;
                    }
                }

                
            });
        }
        try {
  const logoutSelectors = '.logout-link,[data-logout],#logout,a[href="/logout"],a[href="logout"]';
  document.querySelectorAll(logoutSelectors).forEach(el=>{
    el.addEventListener('click', ev=>{
      try{ ev.preventDefault(); }catch(e){}
      logout();
    });
  });

  document.body.addEventListener('click', ev=>{
    const el = ev.target && ev.target.closest && (
      ev.target.closest('.logout-link') ||
      ev.target.closest('[data-logout]') ||
      ev.target.closest('#logout') ||
      ev.target.closest('a[href="/logout"]') ||
      ev.target.closest('a[href="logout"]')
    );
    if(el){
      try{ ev.preventDefault(); }catch(e){}
      logout();
    }
  });
} catch(e){
  console.log('logout wiring failed', e);
}

// ... rest of DOMContentLoaded code ...

        // ❌ REMOVED the old generic .btn-primary listener that was crashing pages
        // document.querySelector(".btn-primary").addEventListener(...)

        // ✅ give session cookie time to attach
        



        // USER HISTORY TABLE
        const tblbody = document.getElementById("user_history");
        if(tblbody){
            try{
                const response = await fetch("http://localhost:5000/user-history",{
                    credentials: "include",
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                });
                const result = await response.json();
                tblbody.innerHTML="";
                result.forEach(data=>{
                    const tr=document.createElement('tr');
                    const userTime = formatToIST(data.time || data.createdAt);
                    tr.innerHTML=`
                    <td>${data.action}</td>
                    <td>${data.language || "—"}</td>
                    <td>${userTime}</td>
                    `;
                    tblbody.append(tr);
                });
            } catch(e){
                console.log("Failed to fetch user history");
            }
        }

        // ADMIN HISTORY TABLE
        const tbody=document.getElementById("admin_user_history");
        if(tbody){
            try{
                const response=await fetch("http://localhost:5000/admin-history",{
                    credentials: "include",
                    method: "GET",
                    headers: {"Content-Type": "application/json"}
                });
                const result=await response.json();
                tbody.innerHTML="";
                result.forEach(user=>{
                    const tr=document.createElement('tr');
                    const adminTime = formatToIST(user.time || user.createdAt);
                    tr.innerHTML=`
                    <td>${user.username}</td>
                    <td>${user.action}</td>
                    <td>${user.language || "—"}</td>
                    <td>${adminTime}</td>
                    `;
                    tbody.append(tr);
                });
                // Update dashboard stats using real data
                try{
                    // Total requests = total history records
                    const totalRequestsEl = document.getElementById('total-requests');
                    if(totalRequestsEl) totalRequestsEl.textContent = String(result.length || 0);

                    // Languages supported = distinct languages in history
                    const langs = new Set();
                    result.forEach(item => {
                        const lang = (item.language || 'Unknown').toString().trim() || 'Unknown';
                        langs.add(lang);
                    });
                    const languagesSupportedEl = document.getElementById('languages-supported');
                    if(languagesSupportedEl) languagesSupportedEl.textContent = String(langs.size);

                    const langTopEl = document.getElementById('lang-top');
                    if(langTopEl) langTopEl.textContent = `Top ${Math.min(5, langs.size)}`;

                    // Active users: fetch from /get-users (server-side user list)
                    try{
                        const resUsers = await fetch('http://localhost:5000/get-users',{ credentials: 'include' });
                        if(resUsers.ok){
                            const users = await resUsers.json();
                            const activeEl = document.getElementById('active-users');
                            if(activeEl) activeEl.textContent = String((users && users.length) || 0);
                        }
                    }catch(e){ console.log('Failed to fetch users for active count', e); }
                }catch(e){ console.log('Failed to update dashboard stats', e); }
                // Compute language statistics and render chart (using real data)
                try{
                    const languageCounts = {};
                    result.forEach(item => {
                        const lang = (item.language || 'Unknown').toString().trim() || 'Unknown';
                        languageCounts[lang] = (languageCounts[lang] || 0) + 1;
                    });

                    const entries = Object.entries(languageCounts).sort((a,b)=>b[1]-a[1]);
                    const top = entries.slice(0, 8);
                    const labels = top.map(e=>e[0]);
                    const data = top.map(e=>e[1]);

                    // Render multiple chart types (excluding bar) to present the same language stats
                    function safeDestroy(key){ try{ if(window[key]){ window[key].destroy(); window[key]=null; } }catch(e){} }

                    const makeColor = i => `hsl(${(i*55)%360} 65% 55%)`;
                    const palette = labels.map((_,i)=> makeColor(i));

                    if(labels.length === 0){
                        // If no data, display a small message in the first canvas area
                        const first = document.getElementById('languageLine');
                        if(first){ const ctx = first.getContext('2d'); ctx.clearRect(0,0,first.width||300, first.height||150); ctx.fillStyle='#666'; ctx.font='14px sans-serif'; ctx.fillText('No language data available',10,30); }
                    } else {
                        // helpers
                        const createGradient = (ctx, color) => {
                            const g = ctx.createLinearGradient(0,0,0,300);
                            g.addColorStop(0, 'rgba(99,102,241,0.45)');
                            g.addColorStop(1, 'rgba(168,85,247,0.06)');
                            return g;
                        };

                        // Build numeric arrays for scatter/bubble
                        const scatterPoints = labels.map((l,i)=>({ x: i + 1, y: data[i] }));
                        const bubblePoints = labels.map((l,i)=>({ x: i + 1, y: data[i], r: Math.max(6, Math.sqrt(data[i]) * 4) }));

                        // LINE (with subtle area)
                        (function(){
                            const el = document.getElementById('languageLine');
                            if(!el) return;
                            const ctx = el.getContext('2d');
                            safeDestroy('languageLineChart');
                            window.languageLineChart = new Chart(ctx, {
                                type: 'line',
                                data: { labels, datasets: [{ label: 'Requests', data, borderColor: palette[0], backgroundColor: 'rgba(0,0,0,0)', tension: 0.35, pointRadius:4 }] },
                                options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{display:false} }, scales:{ x:{ display:true }, y:{ beginAtZero:true } } }
                            });
                        })();

                        // AREA (line with fill/gradient)
                        (function(){
                            const el = document.getElementById('languageArea'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageAreaChart');
                            const grad = ctx.createLinearGradient(0,0,0,300);
                            grad.addColorStop(0, 'rgba(99,102,241,0.45)');
                            grad.addColorStop(1, 'rgba(168,85,247,0.06)');
                            window.languageAreaChart = new Chart(ctx, {
                                type: 'line',
                                data: { labels, datasets: [{ label:'Requests', data, borderColor: 'rgba(99,102,241,0.9)', backgroundColor: grad, tension:0.35, fill:true, pointRadius:3 }] },
                                options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{display:false} }, scales:{ y:{ beginAtZero:true } } }
                            });
                        })();

                        // PIE
                        (function(){
                            const el = document.getElementById('languagePie'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languagePieChart');
                            window.languagePieChart = new Chart(ctx,{ type:'pie', data:{ labels, datasets:[{ data, backgroundColor: palette }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom' } } } });
                        })();

                        // DOUGHNUT
                        (function(){
                            const el = document.getElementById('languageDoughnut'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageDoughnutChart');
                            window.languageDoughnutChart = new Chart(ctx,{ type:'doughnut', data:{ labels, datasets:[{ data, backgroundColor: palette }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom' } }, cutout:'50%' } });
                        })();

                        // RADAR
                        (function(){
                            const el = document.getElementById('languageRadar'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageRadarChart');
                            window.languageRadarChart = new Chart(ctx,{ type:'radar', data:{ labels, datasets:[{ label:'Requests', data, backgroundColor:'rgba(99,102,241,0.18)', borderColor:'rgba(99,102,241,0.9)', pointBackgroundColor:palette }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false } } } });
                        })();

                        // POLAR AREA
                        (function(){
                            const el = document.getElementById('languagePolar'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languagePolarChart');
                            window.languagePolarChart = new Chart(ctx,{ type:'polarArea', data:{ labels, datasets:[{ data, backgroundColor: palette }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right' } } } });
                        })();

                        // SCATTER
                        (function(){
                            const el = document.getElementById('languageScatter'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageScatterChart');
                            window.languageScatterChart = new Chart(ctx,{ type:'scatter', data:{ datasets:[{ label:'Requests', data: scatterPoints, backgroundColor: palette, borderColor: palette, showLine:false, pointRadius:6 }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false } }, scales:{ x:{ title:{ display:true, text:'Index' } }, y:{ beginAtZero:true } } } });
                        })();

                        // BUBBLE
                        (function(){
                            const el = document.getElementById('languageBubble'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageBubbleChart');
                            window.languageBubbleChart = new Chart(ctx,{ type:'bubble', data:{ datasets:[{ label:'Requests', data: bubblePoints, backgroundColor: palette }] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false } }, scales:{ x:{ display:false }, y:{ beginAtZero:true } } } });
                        })();

                        // MIXED (line + scatter)
                        (function(){
                            const el = document.getElementById('languageMixed'); if(!el) return;
                            const ctx = el.getContext('2d'); safeDestroy('languageMixedChart');
                            window.languageMixedChart = new Chart(ctx,{ data:{ labels, datasets:[ { type:'line', label:'Trend', data, borderColor:'rgba(16,185,129,0.9)', tension:0.3, fill:false }, { type:'scatter', label:'Points', data: scatterPoints, backgroundColor: palette, pointRadius:5 } ] }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom' } }, scales:{ y:{ beginAtZero:true } } } });
                        })();
                    }
                }catch(e){ console.log('Failed to render language chart', e); }
            }catch(err){
                console.log("Failed to fetch user history");
            }
        }

        // ADMIN USER DATA TABLE
        const tablebody = document.getElementById("admin_user_data");
        if(!tablebody) return;
        try{
            const res = await fetch("http://localhost:5000/get-users",{ credentials: 'include' });
            const result = await res.json();
            tablebody.innerHTML="";
            result.forEach(user=>{
                const tr = document.createElement("tr");
                tr.innerHTML= `
                    <td>${user.username}</td>
                    <td>${user.email || "—"}</td>
                    <td>${user.requests || 0}</td>
                    <td>${user.role}</td>
                    <td><button class="delete_user" data-username="${user.username}">Delete</button></td>
                `;
                tablebody.appendChild(tr);
            });    
            document.querySelectorAll(".delete_user").forEach(btn=>{
                btn.addEventListener("click",async ()=>{
                    const username=btn.dataset.username;
                    if(!confirm(`Delete user ${username}`)) return;
                    try{
                        const response=await fetch("http://localhost:5000/delete-user",{
                            credentials: "include",
                            method:"POST",
                            headers:{
                                "Content-Type": "application/json"
                            },
                            body:JSON.stringify({username})
                        });
                        const result=await response.json();
                        console.log(result.message);
                        btn.closest("tr").remove();
                    } catch(err){
                        console.log(err);
                    }
                });
            });    
        } catch (e){
            console.log(e); 
        }
    });
})();
