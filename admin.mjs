const states = {
  pending: 'รออนุมัติ',
  active: 'ใช้งานได้',
  blocked: 'ยกเลิกสิทธิ์',
};

const actions = {
  pending: ['active', 'อนุมัติ'],
  active: ['blocked', 'ยกเลิกสิทธิ์'],
  blocked: ['active', 'คืนสิทธิ์'],
};

function rosterEditorUrl(rosterId) {
  const url = new URL(process.env.MOU_ROSTER_EDITOR_URL || '');
  const parts = url.pathname.split('/');

  if (
    url.origin !== 'https://docs.google.com' ||
    parts[1] !== 'spreadsheets' ||
    parts[2] !== 'd' ||
    parts[3] !== rosterId ||
    parts[4] !== 'edit'
  ) {
    throw new Error('URL ไม่ตรงกับชีตทะเบียน');
  }

  return url.href;
}

export function renderAdminPanel(db, esc, deleting) {
  const members = db.prepare(`
    SELECT id, name, phone, code, state
    FROM accounts
    WHERE role = 'user'
    ORDER BY state = 'pending' DESC, id
  `).all();

  const confirmation = deleting ? `
    <p>ยืนยันลบบัญชี ${esc(deleting.name)}</p>
    <form method="post" action="/admin/action">
      <input type="hidden" name="id" value="${deleting.id}">
      <button name="action" value="delete">ยืนยันลบ</button>
      <a href="/admin#admin">ยกเลิก</a>
    </form>
  ` : '';

  const rows = members.map(member => {
    const [action, label] = actions[member.state];

    return `
      <li>
        ${esc(member.name)} · ${esc(member.phone)} ·
        ${esc(member.code)} · ${states[member.state]}
        <form method="post" action="/admin/action" style="display:inline">
          <input type="hidden" name="id" value="${member.id}">
          <input type="hidden" name="state" value="${member.state}">
          <button name="action" value="${action}">${label}</button>
        </form>
        <a href="/admin?delete=${member.id}#admin">ลบบัญชี</a>
      </li>
    `;
  });

  return `
    <h2 id="admin">จัดการทะเบียนและสิทธิ์ใช้งาน</h2>
    <p>
      <a href="/admin/roster" target="_blank" rel="noopener noreferrer">
        เปิดทะเบียน Phone and Nameber
      </a>
    </p>
    ${confirmation}
    ${rows.length ? `<ul>${rows.join('')}</ul>` : '<p>ยังไม่มีบัญชีผู้ใช้</p>'}
  `;
}

export function serveAdmin({
  path, url, user, db, rosterId, res, reply, redirect, page,
}) {
  if (!user) return redirect(res, '/#login');
  if (user.role !== 'admin') {
    return reply(res, 403, page(user, 'เฉพาะผู้ดูแลระบบ'));
  }

  if (path === '/admin/roster') {
    let target;
    try {
      target = rosterEditorUrl(rosterId);
    } catch {
      return reply(res, 503, page(
        user,
        'กรุณาตั้ง MOU_ROSTER_EDITOR_URL ให้ตรงกับชีตทะเบียน',
      ));
    }
    return redirect(res, target);
  }

  const deleting = db.prepare(`
    SELECT id, name FROM accounts WHERE id = ? AND role = 'user'
  `).get(url.searchParams.get('delete'));

  return reply(res, 200, page(user, '', false, true, deleting));
}

export function applyAdminAction({ user, db, data, res, reply, redirect }) {
  if (user?.role !== 'admin') return reply(res, 403, 'Forbidden');

  if (data.action === 'delete') {
    db.prepare("DELETE FROM accounts WHERE id = ? AND role = 'user'")
      .run(data.id);
  } else if (Object.hasOwn(actions, data.state) && actions[data.state][0] === data.action) {
    db.exec('BEGIN');
    try {
      const changed = db.prepare(`
        UPDATE accounts SET state = ?
        WHERE id = ? AND role = 'user' AND state = ?
      `).run(data.action, data.id, data.state);

      if (changed.changes && data.action === 'blocked') {
        db.prepare('DELETE FROM sessions WHERE account_id = ?').run(data.id);
      }
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  return redirect(res, '/admin#admin');
}
