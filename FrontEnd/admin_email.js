(function(){
  const API_BASE = window.location.hostname === "127.0.0.1"
    ? "http://127.0.0.1:5000"
    : "http://localhost:5000";

  const INITIAL_HISTORY_COUNT = 5;
  const HISTORY_INCREMENT = 10;

  let emailHistoryCache = [];
  let visibleHistoryCount = INITIAL_HISTORY_COUNT;

  async function fetchUsers(){
    try{
      const res = await fetch(`${API_BASE}/get-users`, { credentials: 'include' });
      if(!res.ok) throw new Error('Failed to fetch users');
      return await res.json();
    }catch(e){
      console.error('fetchUsers error', e);
      return [];
    }
  }

  function renderUsers(users){
    const container = document.getElementById('users-list');
    if(!container) return;
    container.innerHTML = '';
    if(!users || users.length === 0){
      container.innerHTML = '<div class="placeholder">No users found.</div>';
      return;
    }

    users.forEach(u=>{
      const wrapper = document.createElement('div');
      wrapper.className = 'user-item';
      const id = 'user-' + (u._id || u.email).replace(/[^a-z0-9\-]/ig, '_');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.id = id;
      input.value = u.email;
      const label = document.createElement('label');
      label.htmlFor = id;
      label.textContent = `${u.username} (${u.email})`;
      wrapper.appendChild(input);
      wrapper.appendChild(label);
      container.appendChild(wrapper);
    });
  }

  async function fetchEmailHistory(){
    try{
      const res = await fetch(`${API_BASE}/admin/email-history`, { credentials: 'include' });
      if(!res.ok) throw new Error('Failed to fetch email history');
      return await res.json();
    }catch(e){
      console.error('fetchEmailHistory error', e);
      return [];
    }
  }

  function renderEmailHistory(rows){
    const tbody = document.getElementById('email-history-body');
    if(!tbody) return;
    tbody.innerHTML = '';
    if(!rows || rows.length === 0){
      tbody.innerHTML = '<tr><td colspan="4" class="placeholder">No email history yet.</td></tr>';
      return;
    }

    rows.forEach(r => {
      const tr = document.createElement('tr');
      const subj = document.createElement('td'); subj.textContent = r.subject || '—';
      const rec = document.createElement('td'); rec.textContent = `${r.recipientsCount || 0}` + (Array.isArray(r.recipients) && r.recipients.length>0 ? ` (${r.recipients.length} shown)` : '');
      const date = document.createElement('td'); date.textContent = new Date(r.sentAt || Date.now()).toLocaleString();
      const status = document.createElement('td');
      const badge = document.createElement('span'); badge.className = 'badge';
      badge.textContent = (r.status || 'pending');
      if(r.status === 'sent') badge.classList.add('badge-success');
      if(r.status === 'failed') badge.classList.add('badge-danger');
      if(r.status === 'pending') badge.classList.add('badge-info');
      status.appendChild(badge);

      tr.appendChild(subj);
      tr.appendChild(rec);
      tr.appendChild(date);
      tr.appendChild(status);
      tbody.appendChild(tr);
    });
  }

  function sortEmailHistory(rows = []){
    return rows.slice().sort((a, b) => {
      return new Date(b?.sentAt || 0) - new Date(a?.sentAt || 0);
    });
  }

  function setEmailHistory(rows = []){
    emailHistoryCache = sortEmailHistory(Array.isArray(rows) ? rows : []);
    visibleHistoryCount = emailHistoryCache.length === 0
      ? 0
      : Math.min(INITIAL_HISTORY_COUNT, emailHistoryCache.length);
    applyEmailHistoryView();
  }

  function applyEmailHistoryView(){
    const subset = emailHistoryCache.slice(0, visibleHistoryCount || 0);
    renderEmailHistory(subset);
    updateHistoryControls();
  }

  function updateHistoryControls(){
    const showMoreBtn = document.getElementById('show-more-history');
    const showAllBtn = document.getElementById('show-all-history');
    const total = emailHistoryCache.length;
    const canShowMore = total > visibleHistoryCount;

    if(showMoreBtn){
      if(total === 0){
        showMoreBtn.style.display = 'none';
      } else {
        showMoreBtn.style.display = 'inline-flex';
        showMoreBtn.disabled = !canShowMore;
        showMoreBtn.textContent = canShowMore ? 'Show more' : 'No more emails';
      }
    }

    if(showAllBtn){
      showAllBtn.style.visibility = total ? 'visible' : 'hidden';
      showAllBtn.disabled = total === 0 || visibleHistoryCount >= total;
    }
  }

  async function fetchActiveUsage(days = 14){
    try{
      const res = await fetch(`${API_BASE}/admin/active-usage?days=${days}`, { credentials: 'include' });
      if(!res.ok) throw new Error('Failed to fetch active usage');
      return await res.json();
    }catch(e){
      console.error('fetchActiveUsage error', e);
      return { labels: [], counts: [] };
    }
  }

  function renderActiveChart(labels, counts){
    const ctx = document.getElementById('active-usage-chart');
    if(!ctx) return;
    try{
      if(window._activeChart) window._activeChart.destroy();
      window._activeChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Actions per day',
            data: counts,
            borderColor: '#4f46e5',
            backgroundColor: 'rgba(79,70,229,0.08)',
            fill: true
          }]
        },
        options: { responsive: true, maintainAspectRatio: false }
      });
    }catch(e){ console.error('Chart error', e); }
  }

  function wireControls(){
    const selectAll = document.getElementById('select-all-btn');
    const recipientSelect = document.getElementById('recipient-select');
    const customSelection = document.getElementById('custom-selection');
    const usersContainer = document.getElementById('users-list');

    if(recipientSelect){
      recipientSelect.addEventListener('change', ()=>{
        if(recipientSelect.value === 'custom'){
          if(customSelection) customSelection.style.display = 'block';
        } else {
          if(customSelection) customSelection.style.display = 'none';
        }
      });
    }

    if(selectAll){
      selectAll.addEventListener('click', ()=>{
        if(!usersContainer) return;
        const checks = usersContainer.querySelectorAll('input[type="checkbox"]');
        const allChecked = Array.from(checks).every(c=>c.checked);
        checks.forEach(c=> c.checked = !allChecked);
      });
    }

    // Preview live update
    const subjectEl = document.getElementById('email-subject');
    const bodyEl = document.getElementById('email-body');
    const previewSubj = document.getElementById('preview-subject');
    const previewBody = document.getElementById('preview-body');
    function updatePreview(){
      if(previewSubj) previewSubj.textContent = subjectEl?.value || '(Subject will appear here)';
      if(previewBody){
        const text = bodyEl?.value || '(Email body will appear here)';
        const esc = String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        previewBody.innerHTML = esc.replace(/\n/g,'<br>');
      }
    }
    subjectEl?.addEventListener('input', updatePreview);
    bodyEl?.addEventListener('input', updatePreview);
    updatePreview();

    const form = document.getElementById('bulk-email-form');
    if(form){
      form.addEventListener('submit', async (e)=>{
        e.preventDefault();
        const subject = document.getElementById('email-subject')?.value?.trim();
        const message = document.getElementById('email-body')?.value?.trim();
        const mode = document.getElementById('recipient-select')?.value;

        if(!subject || !message){
          alert('Please fill subject and message');
          return;
        }

        let recipients = [];
        if(mode === 'all'){
          recipients = 'all';
        } else if(mode === 'custom'){
          const checks = usersContainer.querySelectorAll('input[type="checkbox"]:checked');
          recipients = Array.from(checks).map(c=>c.value);
          if(recipients.length === 0){
            alert('Please select at least one user or choose another recipient option.');
            return;
          }
        } else {
          // active/inactive - fallback to 'all' if not implemented server-side
          recipients = mode;
        }

        try{
          const res = await fetch(`${API_BASE}/admin/bulk-email`, {
          method: "POST",
          credentials: "include",
          headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${localStorage.getItem("jwt")}`
          },
          body: JSON.stringify({
              recipients,
              subject,
              message
          })
      });

          const data = await res.json().catch(()=>({}));
          if(!res.ok) throw new Error(data.message || 'Failed to send');
          alert(data.message || 'Emails sent successfully');
          form.reset();
          if(customSelection) customSelection.style.display = 'none';
          // refresh history and chart
          try{
            const rows = await fetchEmailHistory();
            setEmailHistory(rows);
            const usage = await fetchActiveUsage();
            renderActiveChart(usage.labels, usage.counts);
          }catch(e){ console.error('refresh failed', e); }
        }catch(err){
          console.error('Send failed', err);
          alert('Send failed: ' + (err.message || 'Unknown error'));
        }
      });
    }

    const showMoreBtn = document.getElementById('show-more-history');
    if(showMoreBtn){
      showMoreBtn.addEventListener('click', ()=>{
        if(emailHistoryCache.length === 0) return;
        const nextCount = Math.min(visibleHistoryCount + HISTORY_INCREMENT, emailHistoryCache.length);
        if(nextCount !== visibleHistoryCount){
          visibleHistoryCount = nextCount;
          applyEmailHistoryView();
        }
      });
    }

    const showAllBtn = document.getElementById('show-all-history');
    if(showAllBtn){
      showAllBtn.addEventListener('click', ()=>{
        if(emailHistoryCache.length === 0) return;
        visibleHistoryCount = emailHistoryCache.length;
        applyEmailHistoryView();
      });
    }

    updateHistoryControls();
  }

  document.addEventListener('DOMContentLoaded', async ()=>{
    const users = await fetchUsers();
    renderUsers(users);
    wireControls();
    // load history and active usage chart
    try{
      const rows = await fetchEmailHistory();
      setEmailHistory(rows);
      const usage = await fetchActiveUsage();
      renderActiveChart(usage.labels, usage.counts);
    }catch(e){ console.error(e); }
  });
})();
