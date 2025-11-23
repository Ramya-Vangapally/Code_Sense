// app.js — simple client-side login + redirect using role.json
(function(){
    // Helpers
    function $(s){ return document.querySelector(s); }

    // Create or update the floating auth control (login/logout)
    function ensureAuthControl(){
        // If the page already contains a header logout link, use that instead of creating a floating button
        const headerLogout = document.querySelector('.logout-link');
        if(headerLogout){
            // remove floating button if present
            const old = document.getElementById('auth-btn');
            if(old) old.remove();
            return headerLogout;
        }

        let btn = document.getElementById('auth-btn');
        if(!btn){
            btn = document.createElement('button');
            btn.id = 'auth-btn';
            btn.style = 'position:fixed;top:12px;right:12px;z-index:10001;padding:8px 12px;border-radius:8px;border:0;background:rgba(0,0,0,0.7);color:#fff;cursor:pointer;font-size:13px';
            document.body.appendChild(btn);
        }
        return btn;
    }

    // Theme handling (centralized)
    const THEME_KEY = 'theme';

    function applyTheme(theme){
        const mode = theme === 'dark' ? 'dark' : 'light';
        try{
            document.documentElement.setAttribute('data-theme', mode);
            document.body.setAttribute('data-theme', mode);
        }catch(e){}
        localStorage.setItem(THEME_KEY, mode);
        // update all toggles
        try{
            const toggles = document.querySelectorAll('#theme-toggle');
            toggles.forEach(t=> t.textContent = mode === 'dark' ? '🌙' : '☀️');
        }catch(e){}
        // update any theme-select dropdown
        try{
            const sel = document.getElementById('theme-select');
            if(sel) sel.value = mode === 'dark' ? 'Dark' : 'Light';
        }catch(e){}
    }

    function initThemeControls(){
        // apply saved or default
        const saved = localStorage.getItem(THEME_KEY);
        if(saved) applyTheme(saved); else applyTheme('light');

        // attach to any #theme-toggle buttons
        try{
            const toggles = document.querySelectorAll('#theme-toggle');
            toggles.forEach(t=>{
                t.addEventListener('click', ()=>{
                    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                    applyTheme(cur === 'dark' ? 'light' : 'dark');
                });
            });
        }catch(e){}

        // attach to theme-select if exists
        try{
            const sel = document.getElementById('theme-select');
            if(sel){
                sel.addEventListener('change', ()=>{
                    const next = sel.value === 'Dark' ? 'dark' : 'light';
                    applyTheme(next);
                });
            }
        }catch(e){}

        // listen for storage changes from other tabs
        window.addEventListener('storage', (e)=>{
            if(e.key === THEME_KEY && e.newValue) applyTheme(e.newValue);
        });
    }

    function logout(){
        sessionStorage.removeItem('currentUser');
        // small visual reset then redirect
        const btn = document.getElementById('auth-btn');
        if(btn) btn.textContent = 'Login';
        // also update any header logout links to show Login
        try{ const header = document.querySelector('.logout-link'); if(header) header.textContent = 'Login'; }catch(e){}
        window.location.href = 'index.html';
    }

    // Roles data helpers — keep an in-browser copy in localStorage so user management can update it.
    const ROLES_KEY = 'rolesData';

    async function ensureRolesLoaded(){
        try{
            const existing = localStorage.getItem(ROLES_KEY);
            if(existing) return JSON.parse(existing);
            const res = await fetch('role.json');
            if(!res.ok) throw new Error('role.json not found');
            const data = await res.json();
            localStorage.setItem(ROLES_KEY, JSON.stringify(data));
            return data;
        }catch(e){
            // initialize empty
            const empty = [];
            localStorage.setItem(ROLES_KEY, JSON.stringify(empty));
            return empty;
        }
    }

    function getRoles(){
        try{ return JSON.parse(localStorage.getItem(ROLES_KEY) || '[]'); }catch(e){ return []; }
    }

    function setRoles(list){
        localStorage.setItem(ROLES_KEY, JSON.stringify(list));
        // notify pages
        window.dispatchEvent(new CustomEvent('roles-updated', { detail: list }));
    }

    // Utility to persist roles by offering a download of the JSON file (cannot write to disk from browser)
    function downloadRoles(){
        const data = getRoles();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'role.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    // expose helpers for pages (user_management.html) to use
    window.getRoles = getRoles;
    window.setRoles = setRoles;
    window.downloadRoles = downloadRoles;

    // If roles change (other tab or via setRoles), ensure current session is still valid
    function validateCurrentUserAgainstRoles(newList){
        try{
            const cur = JSON.parse(sessionStorage.getItem('currentUser') || 'null');
            if(!cur || !cur.username) return;
            const found = (newList || getRoles()).find(x=>x.username === cur.username);
            if(!found){
                // user removed -> clear session and redirect if on protected page
                sessionStorage.removeItem('currentUser');
                if(window.location.pathname.endsWith('user.html') || window.location.pathname.endsWith('admin.html')){
                    alert('Your account was removed. You will be redirected to the homepage.');
                    window.location.href = 'index.html';
                }
            }
        }catch(e){/* ignore */}
    }

    window.addEventListener('roles-updated', (e)=> validateCurrentUserAgainstRoles(e.detail));
    window.addEventListener('storage',(e)=>{
        if(e.key === ROLES_KEY){
            try{
                const newList = JSON.parse(e.newValue || '[]');
                validateCurrentUserAgainstRoles(newList);
            }catch(err){}
        }
    });

    function showLoginModal(triggerElement){
        // if modal already exists, focus
        if(document.getElementById('login-modal')) return;

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

        // Handlers
        modal.querySelector('#login-cancel').addEventListener('click', ()=>{ modal.remove(); });

        modal.querySelector('#login-submit').addEventListener('click', ()=>{
            const u = modal.querySelector('#login-username').value.trim();
            const p = modal.querySelector('#login-password').value;
            const err = modal.querySelector('#login-error');
            err.style.display = 'none';
            if(!u || !p){ err.textContent = 'Please enter username and password.'; err.style.display = 'block'; return; }

            fetch('role.json').then(r=>{
                if(!r.ok) throw new Error('Could not load role.json');
                return r.json();
            }).then(users=>{
                const found = users.find(x=>x.username === u && x.password === p);
                if(!found){ err.textContent = 'Invalid credentials.'; err.style.display = 'block'; return; }

                // store basic session info
                sessionStorage.setItem('currentUser', JSON.stringify({ username: found.username, role: found.role }));

                // cleanup modal then redirect
                modal.remove();
                if(found.role === 'admin'){
                    window.location.href = 'admin.html';
                } else {
                    window.location.href = 'user.html';
                }
            }).catch(e=>{
                err.textContent = 'Login failed: ' + e.message; err.style.display = 'block';
            });
        });
    }

    // Attach to dashboard links/buttons
    document.addEventListener('DOMContentLoaded', ()=>{
        // Ensure auth control exists on every page
        const authBtn = ensureAuthControl();

        function updateAuthButton(){
            try{
                const cur = JSON.parse(sessionStorage.getItem('currentUser') || 'null');
                if(cur && cur.username){
                    authBtn.textContent = `Logout (${cur.username})`;
                    authBtn.onclick = logout;
                } else {
                    authBtn.textContent = 'Login';
                    authBtn.onclick = function(){ showLoginModal(authBtn); };
                }
            }catch(e){
                authBtn.textContent = 'Login';
                authBtn.onclick = function(){ showLoginModal(authBtn); };
            }
        }

        updateAuthButton();

        // initialize theme controls (apply saved theme and wire toggles)
        try{ initThemeControls(); }catch(e){}

        // Ensure roles are loaded into localStorage for management operations
        ensureRolesLoaded().then(()=>{/* ready */}).catch(()=>{/* ignore */});

        // If already logged-in, redirect immediately based on role
        try{
            const cur = JSON.parse(sessionStorage.getItem('currentUser') || 'null');
            if(cur && cur.role){
                if(cur.role === 'admin' && window.location.pathname.endsWith('index.html')){
                    window.location.href = 'admin.html';
                    return;
                }
                if(cur.role === 'user' && window.location.pathname.endsWith('index.html')){
                    window.location.href = 'user.html';
                    return;
                }
            }
        }catch(e){/* ignore */}

        const dash = document.getElementById('dashboard-link');
        if(dash) dash.addEventListener('click', (e)=>{ e.preventDefault(); showLoginModal(dash); });

        const goBtn = document.getElementById('go-dashboard');
        if(goBtn) goBtn.addEventListener('click', ()=> showLoginModal(goBtn));

        const tryNow = document.getElementById('try-now');
        if(tryNow) tryNow.addEventListener('click', ()=> window.location.href = 'user.html');
        // Wire any visible logout links (class="logout-link") to the logout function
        try{
            const logoutLinks = document.querySelectorAll('.logout-link');
            logoutLinks.forEach(a=>{ a.addEventListener('click', (e)=>{ e.preventDefault(); logout(); }); });
        }catch(e){/* ignore */}
    });

})();
