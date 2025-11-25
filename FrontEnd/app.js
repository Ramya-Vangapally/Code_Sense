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

    function logout(){
        sessionStorage.removeItem('currentUser');
        window.location.href = 'index.html';
    }

    function showLoginModal(triggerElement){
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

        modal.querySelector('#login-cancel').addEventListener('click', ()=>{ modal.remove(); });

        modal.querySelector('#login-submit').addEventListener('click', async ()=>{
            const u = modal.querySelector('#login-username').value.trim();
            const p = modal.querySelector('#login-password').value;
            const err = modal.querySelector('#login-error');
            err.style.display = 'none';
            if(!u || !p){ err.textContent = 'Please enter username and password.'; err.style.display = 'block'; return; }
            try{
                const response = await fetch("http://localhost:5000/login",{
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ username: u, password: p })
                });
                const result = await response.json();
                sessionStorage.setItem("currentUser", JSON.stringify(result));
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
        try{ initThemeControls(); }catch(e){}

        const dash = document.getElementById('dashboard-link');
        if(dash) dash.addEventListener('click', (e)=>{ e.preventDefault(); showLoginModal(dash); });

        const goBtn = document.getElementById('go-dashboard');
        if(goBtn) goBtn.addEventListener('click', ()=> showLoginModal(goBtn));

        const tryNow = document.getElementById('try-now');
        if(tryNow) tryNow.addEventListener('click', ()=> showLoginModal());

        // USER PAGE: generate explanation
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
        document.querySelector(".btn-primary").addEventListener("click",async()=>{
            const language=document.getElementById("language").value;
            const action=document.getElementById("code-input").value;
            const user=JSON.parse(sessionStorage.getItem("currentUser"))
            const username=user.username;
            const role=user.role
            const response=await fetch("http://localhost:5000/add-history",{
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body:JSON.stringify({username,role,action,language})
            })
        })
        const currentUser = JSON.parse(sessionStorage.getItem("currentUser"));
        const username = currentUser?.username;
        const tblbody=document.getElementById("user_history");
        if(tblbody){
            try{
                const response = await fetch("http://localhost:5000/user-history",{
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({ username })
                });
                result = await response.json();
                tblbody.innerHTML="";
                result.forEach(data=>{
                    const tr=document.createElement('tr');
                    tr.innerHTML=`
                    <td>${data.action}</td>
                    <td>${data.language || "—"}</td>
                    <td>${data.time || data.createdAt || "—"}</td>
                    `;
                    tblbody.append(tr);
                })
            } catch(e){
                console.log("Failed to fetch user history");
            }
        }

        const tbody=document.getElementById("admin_user_history");
        if(tbody){
            try{
                const response=await fetch("http://localhost:5000/admin-history",{
                    method: "GET",
                    headers: {"Content-Type": "application/json"}
                });
                const result=await response.json();
                tbody.innerHTML="";
                result.forEach(user=>{
                    const tr=document.createElement('tr');
                    tr.innerHTML=`
                    <td>${user.username}</td>
                    <td>${user.action}</td>
                    <td>${user.language || "—"}</td>
                    <td>${user.time || user.createdAt || "—"}</td>
                    `;
                    tbody.append(tr);
                });
            }catch(err){
                console.log("Failed to fetch user history");
            }
        }

        const tablebody = document.getElementById("admin_user_data");
        if(!tablebody) return;
        try{
            const res = await fetch("http://localhost:5000/get-users");
            const result = await res.json();
            tablebody.innerHTML="";
            result.forEach(user=>{
                const tr = document.createElement("tr");
                tr.innerHTML= `
                    <td>${user.username}</td>
                    <td>${user.email || "—"}</td>
                    <td>${user.requests || 0}</td>
                    <td>${user.role}</td>
                    <td><button class="delete_user" data-username=${user.username}>Delete</button></td>
                `;
                tablebody.appendChild(tr);
            });    
            document.querySelectorAll(".delete_user").forEach(btn=>{
                btn.addEventListener("click",async ()=>{
                    const username=btn.dataset.username;
                    if(!confirm(`Delete user ${username}`)) return;
                    try{
                        const response=await fetch("http://localhost:5000/delete-user",{
                            method:"POST",
                            headers:{
                                "Content-Type": "application/json"
                            },
                            body:JSON.stringify({username})
                        })
                        const result=await response.json();
                        console.log(result.message)
                        btn.closest("tr").remove();
                    }
                catch(err){
                    console.log(err);
                }
                })
            })    
        } catch (e){
            console.log(e); 
        }
    });
})();
