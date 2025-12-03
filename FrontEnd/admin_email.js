(function(){
  const API_BASE = window.location.hostname === "127.0.0.1"
    ? "http://127.0.0.1:5000"
    : "http://localhost:5000";

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
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipients, subject, message })
          });
          const data = await res.json();
          if(!res.ok) throw new Error(data.message || 'Failed to send');
          alert('Emails sent successfully');
          form.reset();
          if(customSelection) customSelection.style.display = 'none';
        }catch(err){
          console.error('Send failed', err);
          alert('Send failed: ' + (err.message || 'Unknown error'));
        }
      });
    }
  }

  document.addEventListener('DOMContentLoaded', async ()=>{
    const users = await fetchUsers();
    renderUsers(users);
    wireControls();
  });
})();
