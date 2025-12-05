(function(){
    const API_BASE = window.location.hostname === "127.0.0.1"
        ? "http://127.0.0.1:5000"
        : "http://localhost:5000";
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
            const token = localStorage.getItem("jwt");
            try {
                const res = await fetch(`${API_BASE}/me`, {
                    method: "GET",
                    headers: {
                        "Authorization": token ? `Bearer ${token}` : "",
                        "Content-Type": "application/json"
                    },
                    credentials: "include"   // keep Redis session cookie
                });

                return res.ok ? await res.json() : null;

            } catch(e){
                return null;
            }
        }

        function initProfileMenu(){
        const profileBtn = document.getElementById('profile-btn');
        const profileMenu = document.getElementById('profile-menu');
        if(!profileBtn || !profileMenu) return;

        const wrapper = profileBtn.closest('.profile-wrapper') || profileBtn;
        let isOpen = false;

        const setOpen = (open) => {
            isOpen = open;
            profileMenu.style.display = open ? 'block' : 'none';
        };

        profileBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setOpen(!isOpen);
        });

        document.addEventListener('click', (event) => {
            if(!isOpen) return;
            if(wrapper.contains(event.target)) return;
            setOpen(false);
        });

        document.addEventListener('keydown', (event) => {
            if(event.key === 'Escape' && isOpen){
                setOpen(false);
            }
        });

        window.addEventListener('blur', () => setOpen(false));

    }

    async function logout(){
        try{
            await fetch(`${API_BASE}/logout`, {
                method: "POST",
                credentials: "include"
            });
        }catch(e){}

        localStorage.removeItem("jwt"); // <-- Added

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
            setupAuthModal(staticModal);
            return;
        }
    }

    function setupAuthModal(modalElement){
        if(!modalElement || modalElement.dataset.authWired === 'true') return;
        modalElement.dataset.authWired = 'true';

        const overlay = modalElement.closest('.modal-overlay') || modalElement;
        const closeBtn = modalElement.querySelector('.close-btn');
        const modeButtons = modalElement.querySelectorAll('[data-mode]');
        const loginForm = modalElement.querySelector('#loginForm');
        const signupForm = modalElement.querySelector('#signupForm');
        const helperText = modalElement.querySelector('#authHelperText');
        const messageBox = modalElement.querySelector('#authMessage');

        const showMessage = (text = '', type = 'error') => {
            if(!messageBox) return;
            if(!text){
                messageBox.style.display = 'none';
                messageBox.textContent = '';
                messageBox.className = 'auth-message';
                return;
            }
            messageBox.textContent = text;
            messageBox.style.display = 'block';
            messageBox.className = 'auth-message ' + (type === 'success' ? 'success' : '');
        };

        const switchMode = (mode) => {
            modeButtons.forEach(btn => {
                btn.classList.toggle('active', btn.dataset.mode === mode);
            });
            if(loginForm) loginForm.classList.toggle('active', mode === 'login');
            if(signupForm) signupForm.classList.toggle('active', mode === 'signup');
            if(helperText) helperText.textContent = mode === 'signup' 
                ? 'Already have an account? Switch back to Login.'
                : 'Need an account? Click Sign Up to get started.';
            showMessage('');
        };

        modeButtons.forEach(btn => {
            btn.addEventListener('click', () => switchMode(btn.dataset.mode));
        });

        if(closeBtn){
            closeBtn.addEventListener('click', () => {
                overlay.style.display = 'none';
            });
        }

        if(overlay && overlay !== modalElement){
            overlay.addEventListener('click', (e) => {
                if(e.target === overlay) overlay.style.display = 'none';
            });
        }

        if(loginForm){
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = loginForm.querySelector('#loginUsername')?.value?.trim();
                const password = loginForm.querySelector('#loginPassword')?.value || '';
                
                if(!username || !password){
                    showMessage('Please enter username and password.');
                    return;
                }

                try{
                    const response = await fetch(`${API_BASE}/login`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ username, password })
                    });

                    const result = await response.json();
                    if(!response.ok){
                        throw new Error(result.message || 'Login failed');
                    }

                    //  SAVE JWT TOKEN HERE 
                    localStorage.setItem("jwt", result.token);

                    overlay.style.display = 'none';
                    if(result.role === 'admin'){
                        window.location.href = 'admin.html';
                    } else {
                        window.location.href = 'user.html';
                    }

                } catch(err){
                    showMessage(err.message || 'Login failed. Please try again.');
                }
            });
        }

        if(signupForm){
            signupForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = signupForm.querySelector('#signupEmail')?.value?.trim();
                const username = signupForm.querySelector('#signupUsername')?.value?.trim();
                const password = signupForm.querySelector('#signupPassword')?.value || '';
                const confirm = signupForm.querySelector('#signupConfirm')?.value || '';

                if(!email || !username || !password){
                    showMessage('Please fill in all fields.');
                    return;
                }

                if(password.length < 6){
                    showMessage('Password must be at least 6 characters.');
                    return;
                }

                if(password !== confirm){
                    showMessage('Passwords do not match.');
                    return;
                }

                try{
                    const response = await fetch(`${API_BASE}/register`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ email, username, password })
                    });

                    const result = await response.json();
                    if(!response.ok){
                        throw new Error(result.message || 'Signup failed');
                    }

                    // Clear signup form
                    signupForm.reset();
                    
                    // Pre-fill login form with username
                    const loginUsername = loginForm?.querySelector('#loginUsername');
                    if(loginUsername) loginUsername.value = username;

                    // Show success message and switch to login
                    showMessage('Account created successfully! Please login to continue.', 'success');
                    setTimeout(() => {
                        switchMode('login');
                    }, 1500);
                } catch(err){
                    showMessage(err.message || 'Unable to create account. Please try again.');
                }
            });
        }

        switchMode('login');
    }
    
    document.addEventListener('DOMContentLoaded', async ()=>{

    // Always initialize theme controls (works on all pages)
    try { initThemeControls(); } catch(e){ console.log('Theme init failed:', e); }
    try { initProfileMenu(); } catch(e){ console.log('Profile menu init failed:', e); }

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

        // Wire static login modal (if present in HTML) to auth handlers
        try{
            const staticModal = document.getElementById('loginModal');
            if(staticModal){
                setupAuthModal(staticModal);
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
            // Always show the login modal first so users see the auth UI after logout.
            // If a session is active the modal's auth handlers will redirect after successful check.
            try{
                showLoginModal(goBtn);
            }catch(e){
                // fallback: in case modal isn't available, attempt session check and redirect
                try{
                    const current = await getSessionUser();
                    if(current){
                        if(current.role === 'admin') window.location.href = 'admin.html';
                        else window.location.href = 'user.html';
                        return;
                    }
                }catch(err){}
                showLoginModal(goBtn);
            }
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

                await fetch(`${API_BASE}/add-history`, {
                credentials: "include",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                },
                body: JSON.stringify({
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
                    const res = await fetch(`${API_BASE}/api/explain`, {
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
                        // Render markdown returned by the model into safe HTML
                        const md = data.explanation || "No explanation returned.";
                        let rendered = md;
                        try {
                            if (typeof marked !== 'undefined') {
                                rendered = marked.parse(md);
                            } else {
                                // Fallback: escape HTML and preserve line breaks
                                rendered = md
                                    .replace(/&/g, '&amp;')
                                    .replace(/</g, '&lt;')
                                    .replace(/>/g, '&gt;')
                                    .replace(/\n/g, '<br>');
                            }
                        } catch (e) {
                            console.warn('Markdown parse failed, falling back to plain text', e);
                            rendered = md.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
                        }

                        try {
                            if (typeof DOMPurify !== 'undefined') {
                                rendered = DOMPurify.sanitize(rendered);
                            }
                        } catch (e) {
                            console.warn('DOMPurify sanitize failed', e);
                        }

                        view.innerHTML = `<div class="explanation-markdown" style="font-size:13px;line-height:1.6">${rendered}</div>`;
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
      const logoutSelectors = '.logout-link,[data-logout],#logout,#logout-btn,a[href="/logout"],a[href="logout"]';
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
                const response = await fetch(`${API_BASE}/user-history`, {
                credentials: "include",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                }
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
        const historyShowMoreBtn = document.getElementById("history-show-more");
        const historyShowAllBtn = document.getElementById("history-show-all");
        let adminHistoryData = [];
        let visibleHistoryCount = 10;
        const HISTORY_INCREMENT = 20;

        const renderAdminHistory = () => {
            if(!tbody) return;
            const slice = adminHistoryData.slice(0, visibleHistoryCount);
            tbody.innerHTML="";
            slice.forEach(user=>{
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

            if(historyShowMoreBtn){
                historyShowMoreBtn.style.display = visibleHistoryCount >= adminHistoryData.length ? 'none' : 'inline-flex';
            }
        };

        if(tbody){
            try{
                const response = await fetch(`${API_BASE}/admin-history`, {
                credentials: "include",
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                }
            });
            const result = await response.json();

                adminHistoryData = [...result].sort((a,b)=>{
                    const dateA = new Date(a.time || a.createdAt || 0);
                    const dateB = new Date(b.time || b.createdAt || 0);
                    return dateB - dateA;
                });
                visibleHistoryCount = Math.min(visibleHistoryCount, adminHistoryData.length || visibleHistoryCount);
                renderAdminHistory();

                if(historyShowMoreBtn){
                    historyShowMoreBtn.addEventListener('click', ()=>{
                        if(!adminHistoryData.length) return;
                        visibleHistoryCount = Math.min(adminHistoryData.length, visibleHistoryCount + HISTORY_INCREMENT);
                        renderAdminHistory();
                    });
                }

                if(historyShowAllBtn){
                    historyShowAllBtn.addEventListener('click', ()=>{
                        if(!adminHistoryData.length) return;
                        visibleHistoryCount = adminHistoryData.length;
                        renderAdminHistory();
                    });
                }
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
                        const resUsers = await fetch(`${API_BASE}/get-users`, {
                            credentials: "include",
                            method: "GET",
                            headers: {
                                "Content-Type": "application/json",
                                "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                            }
                        });

                        if(resUsers.ok){
                            const users = await resUsers.json();
                            const activeEl = document.getElementById('active-users');
                            if(activeEl) activeEl.textContent = String((users && users.length) || 0);
                        }
                    }catch(e){ console.log('Failed to fetch users for active count', e); }
                }catch(e){ console.log('Failed to update dashboard stats', e); }
                // Compute language statistics and render only two charts: Bar (languages) and Line (active users)
                try {
                    const history = adminHistoryData.length ? adminHistoryData : result;

                    const languageCounts = {};
                    history.forEach(item => {
                        const lang = (item.language || 'Unknown').toString().trim() || 'Unknown';
                        languageCounts[lang] = (languageCounts[lang] || 0) + 1;
                    });

                    const entries = Object.entries(languageCounts).sort((a, b) => b[1] - a[1]);
                    const top = entries.slice(0, 12);
                    const labels = top.map(e => e[0]);
                    const data = top.map(e => e[1]);

                    // Render languages bar chart
                    const el = document.getElementById('languagesBar');
                    if (el) {
                        try {
                            if (window.languagesBarChart) window.languagesBarChart.destroy();
                            const ctx = el.getContext('2d');
                            window.languagesBarChart = new Chart(ctx, {
                                type: 'bar',
                                data: { labels, datasets: [{ label: 'Requests', data, backgroundColor: labels.map((_, i) => `hsl(${(i * 40) % 360} 70% 55%)`) }] },
                                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
                            });
                        } catch (e) {
                            console.warn('Failed to render languages bar', e);
                        }
                    }

                    // Fetch active usage series and render line chart
                    try {
                        const usageRes = await fetch(`${API_BASE}/admin/active-usage?days=14`, { credentials: 'include' });
                        if (usageRes.ok) {
                            const usage = await usageRes.json();
                            const el2 = document.getElementById('activeUsersLine');
                            if (el2) {
                                try {
                                    if (window.activeUsersChart) window.activeUsersChart.destroy();
                                    const ctx2 = el2.getContext('2d');
                                    window.activeUsersChart = new Chart(ctx2, {
                                        type: 'line',
                                        data: { labels: usage.labels || [], datasets: [{ label: 'Actions per day', data: usage.counts || [], borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.08)', fill: true }] },
                                        options: { responsive: true, maintainAspectRatio: false }
                                    });
                                } catch (e) {
                                    console.warn('Failed to render active users chart', e);
                                }
                            }
                        }
                    } catch (e) {
                        console.warn('Failed to fetch active-usage', e);
                    }
                } catch (err) {
                    console.log('Failed to render dashboard charts', err);
                }
            } catch (e) {
                console.log('Failed to fetch admin history', e);
            }
        }

        // ADMIN USER DATA TABLE
        const tablebody = document.getElementById("admin_user_data");
        if(!tablebody) return;

        const addUserBtn = document.getElementById("add-user-btn");
        const addUserModal = document.getElementById("add-user-modal");
        const addUserForm = document.getElementById("add-user-form");
        const addUserMessage = document.getElementById("add-user-message");
        const addUserClose = document.getElementById("add-user-close");
        const addUserRole = document.getElementById("add-role");

        const showModal = () => {
            if(!addUserModal) return;
            addUserModal.classList.add("open");
            addUserModal.setAttribute("aria-hidden", "false");
            addUserMessage && (addUserMessage.textContent = "");
        };

        const hideModal = () => {
            if(!addUserModal) return;
            addUserModal.classList.remove("open");
            addUserModal.setAttribute("aria-hidden", "true");
            addUserForm && addUserForm.reset();
            if(addUserMessage){
                addUserMessage.textContent = "";
                addUserMessage.className = "modal-message";
            }
        };

        addUserBtn?.addEventListener('click', showModal);
        addUserClose?.addEventListener('click', hideModal);
        addUserModal?.addEventListener('click', (e)=>{
            if(e.target === addUserModal) hideModal();
        });

        const setMessage = (text, kind = "") => {
            if(!addUserMessage) return;
            addUserMessage.textContent = text;
            addUserMessage.className = `modal-message ${kind}`.trim();
        };

        async function fetchAdminUsers(){
            tablebody.innerHTML = `
                <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:18px;">Loading users…</td></tr>
            `;
            try {
                const res = await fetch(`${API_BASE}/get-users`, {
                    credentials: 'include',
                    headers: {
                        "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
                        "Content-Type": "application/json"
                    }
                });
                const users = await res.json();
                if(!res.ok) throw new Error(users.message || 'Unable to load users');
                tablebody.innerHTML = "";
                users.forEach(user => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${user.username}</td>
                        <td>${user.email || "—"}</td>
                        <td>${user.requests || 0}</td>
                        <td>${user.role}</td>
                        <td><button class="delete_user" data-username="${user.username}" data-user-id="${user._id || ''}">Delete</button></td>
                    `;
                    tablebody.appendChild(tr);
                });

                tablebody.querySelectorAll('.delete_user').forEach(btn => {
                    btn.addEventListener('click', async () => {
                        const username = btn.dataset.username;
                        const userId = btn.dataset.userId;
                        if(!username && !userId) return;
                        const label = username || 'this user';
                        if(!confirm(`Delete user ${label}?`)) return;
                        try {
                            const response = await fetch(`${API_BASE}/delete-user`, {
                                credentials: "include",
                                method: "POST",
                                headers: {
                                    "Content-Type": "application/json",
                                    "Authorization": `Bearer ${localStorage.getItem("jwt")}`
                                },
                                body: JSON.stringify({ username, userId })
                            });
                            const data = await response.json();
                            if(!response.ok) throw new Error(data.message || 'Failed to delete');
                            await fetchAdminUsers();
                        } catch(err) {
                            alert(err.message || 'Unable to delete user');
                        }
                    });
                });
            } catch (error) {
                console.log(error);
                tablebody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--danger);padding:18px;">Unable to load users</td></tr>`;
            }
        }

        addUserForm?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('add-username')?.value.trim();
            const email = document.getElementById('add-email')?.value.trim();
            const password = document.getElementById('add-password')?.value;
            const confirm = document.getElementById('add-confirm')?.value;
            const role = addUserRole?.value === 'admin' ? 'admin' : 'user';

            if(!username || !password){
                setMessage('Username and password are required', 'error');
                return;
            }
            if(!email){
                setMessage('Email is required', 'error');
                return;
            }
            if(password !== confirm){
                setMessage('Passwords do not match', 'error');
                return;
            }

            setMessage('Creating user…');
            try {
                const response = await fetch(`${API_BASE}/admin/create-user`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email, username, password, role })
                });
                const data = await response.json();
                if(!response.ok) throw new Error(data.message || 'Unable to create user');
                setMessage('User created successfully!', 'success');
                await fetchAdminUsers();
                setTimeout(() => hideModal(), 900);
            } catch(err) {
                setMessage(err.message || 'Failed to create user', 'error');
            }
        });

        await fetchAdminUsers();
    });
})();
