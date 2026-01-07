# main.py
# RBAC Roles + Users (persistent SQLite + SQLAlchemy)
# Run:
#   pip install flask flask_sqlalchemy
#   python main.py

from flask import Flask, jsonify, request, render_template_string
from flask_sqlalchemy import SQLAlchemy
import datetime, json, os, sqlite3, traceback

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# -------------------------
# Models
# -------------------------
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    privileges = db.Column(db.Text, nullable=False, default='{}')   # JSON encoded dict {module: [privs]}
    assigned_users = db.Column(db.Text, nullable=False, default='[]')  # JSON encoded list of user names
    created_at = db.Column(db.String(64), nullable=False, default=lambda: datetime.datetime.utcnow().isoformat())

    def to_summary(self):
        privs = json.loads(self.privileges or "{}")
        # count unique privileges across modules (approx)
        priv_count = sum(len(set(v)) for v in privs.values())
        return {
            "id": self.id,
            "name": self.name,
            "privileges_count": priv_count,
            "modules_count": len(privs),
            "created_at": self.created_at,
            "assigned_users": json.loads(self.assigned_users or "[]")
        }

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "privileges": json.loads(self.privileges or "{}"),
            "assigned_users": json.loads(self.assigned_users or "[]"),
            "created_at": self.created_at
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # we use name as unique key (previous code used email as name)
    name = db.Column(db.String(140), unique=True, nullable=False)
    role = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(220), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    branch = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.String(64), nullable=False, default=lambda: datetime.datetime.utcnow().isoformat())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "email": self.email,
            "phone": self.phone,
            "branch": self.branch,
            "created_at": self.created_at
        }


# -------------------------
# Ensure DB compatibility (add missing user columns if older DB)
# -------------------------
def ensure_user_table_columns(db_path='rbac.db'):
    """
    Add missing columns to existing user table (email, phone, branch, created_at)
    using SQLite ALTER TABLE ADD COLUMN (safe).
    """
    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user';")
        if not cur.fetchone():
            conn.close()
            return
        cur.execute("PRAGMA table_info(user);")
        cols = [r[1] for r in cur.fetchall()]
        wanted = {
            'email': "TEXT",
            'phone': "TEXT",
            'branch': "TEXT",
            'created_at': "TEXT"
        }
        for col, coltype in wanted.items():
            if col not in cols:
                try:
                    cur.execute(f"ALTER TABLE user ADD COLUMN {col} {coltype};")
                    conn.commit()
                except Exception:
                    # ignore and continue
                    pass
        conn.close()
    except Exception:
        traceback.print_exc()


# -------------------------
# Create DB + seed defaults
# -------------------------
with app.app_context():
    ensure_user_table_columns('rbac.db')
    db.create_all()

    # seed users if none
    if not User.query.first():
        users_seed = [
            User(name="admin@company.com", role="Admin", email="admin@company.com", phone="9999999999", branch="HO"),
            User(name="ops@company.com", role="Ops User", email="ops@company.com", phone="8888888888", branch="HO"),
            User(name="branch1@company.com", role="Branch User", email="branch1@company.com", phone="7777777777", branch="Branch-1"),
            User(name="branch2@company.com", role="Branch User", email="branch2@company.com", phone="6666666666", branch="Branch-2"),
            User(name="rm1@company.com", role="RM User", email="rm1@company.com", phone="5555555555", branch="HO"),
        ]
        db.session.add_all(users_seed)
        db.session.commit()

    # seed roles if none (including the roles you listed)
    if not Role.query.first():
        default_modules = [
            "Manage Roles", "Manage Branches", "Manage Relationship Managers",
            "Manage States", "Manage Satellites", "POSP",
            "Premium Register", "Commission Statements"
        ]
        admin_privs = {m: ["create", "read", "update", "delete", "bulkupload"] for m in default_modules}
        ops_privs = {m: ["read", "update"] for m in default_modules[:6]}
        exp_privs = {m: ["read"] for m in default_modules[:2]}

        r1 = Role(name="Admin", privileges=json.dumps(admin_privs), assigned_users=json.dumps(["admin@company.com"]))
        r2 = Role(name="Ops User", privileges=json.dumps(ops_privs), assigned_users=json.dumps(["ops@company.com"]))
        r3 = Role(name="Exp User", privileges=json.dumps(exp_privs), assigned_users=json.dumps([]))
        r4 = Role(name="super user", privileges=json.dumps({m: ["create", "read", "update", "delete"] for m in default_modules[:5]}), assigned_users=json.dumps(["branch1@company.com"]))
        r5 = Role(name="Exp super user", privileges=json.dumps({m: ["read", "update"] for m in default_modules[:5]}), assigned_users=json.dumps(["branch2@company.com"]))
        r6 = Role(name="HO Finance", privileges=json.dumps({m: ["read","update"] for m in default_modules[:4]}), assigned_users=json.dumps(["rm1@company.com"]))
        r7 = Role(name="Operations manager", privileges=json.dumps({m: ["read","update"] for m in default_modules[:5]}), assigned_users=json.dumps([]))
        r8 = Role(name="Branch user", privileges=json.dumps({m: ["create","read","update"] for m in default_modules[:5]}), assigned_users=json.dumps([]))

        db.session.add_all([r1, r2, r3, r4, r5, r6, r7, r8])
        db.session.commit()


# -------------------------
# Config: modules & possible privs (frontend will use)
# -------------------------
DEFAULT_MODULES = [
    "Manage Roles", "Manage Branches", "Manage Relationship Managers",
    "Manage States", "Manage Satellites", "POSP",
    "Premium Register", "Commission Statements"
]
POSSIBLE_PRIVS = ["create", "read", "update", "delete", "bulkupload"]


# -------------------------
# API endpoints (roles & users)
# -------------------------
@app.route("/api/roles", methods=["GET"])
def api_get_roles():
    q = request.args.get("q", "").strip().lower()
    query = Role.query
    if q:
        query = query.filter(Role.name.ilike(f"%{q}%"))
    rows = query.order_by(Role.id).all()
    out = [r.to_summary() for r in rows]
    return jsonify(out)


@app.route("/api/roles/<int:role_id>", methods=["GET"])
def api_get_role(role_id):
    r = Role.query.get(role_id)
    if not r:
        return jsonify({"error": "not found"}), 404
    return jsonify(r.to_dict())


@app.route("/api/roles", methods=["POST"])
def api_create_role():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    privileges = data.get("privileges") or {}
    assigned_users = data.get("assigned_users") or []
    if not name:
        return jsonify({"error": "missing name"}), 400
    if Role.query.filter_by(name=name).first():
        return jsonify({"error": "role exists"}), 400
    r = Role(name=name, privileges=json.dumps(privileges), assigned_users=json.dumps(assigned_users))
    db.session.add(r)
    db.session.commit()
    return jsonify({"message": "role created", "role": r.to_dict()})


@app.route("/api/roles/<int:role_id>", methods=["PUT"])
def api_update_role(role_id):
    r = Role.query.get(role_id)
    if not r:
        return jsonify({"error": "not found"}), 404
    data = request.json or {}
    name = data.get("name")
    privileges = data.get("privileges")
    assigned_users = data.get("assigned_users")
    if name:
        if Role.query.filter(Role.name == name, Role.id != role_id).first():
            return jsonify({"error": "role name conflict"}), 400
        r.name = name
    if privileges is not None:
        r.privileges = json.dumps(privileges)
    if assigned_users is not None:
        r.assigned_users = json.dumps(assigned_users)
    db.session.commit()
    return jsonify({"message": "updated", "role": r.to_dict()})


@app.route("/api/roles/<int:role_id>", methods=["DELETE"])
def api_delete_role(role_id):
    r = Role.query.get(role_id)
    if not r:
        return jsonify({"error": "not found"}), 404
    db.session.delete(r)
    db.session.commit()
    return jsonify({"message": "deleted"})


@app.route("/api/roles/<int:role_id>/duplicate", methods=["POST"])
def api_duplicate_role(role_id):
    orig = Role.query.get(role_id)
    if not orig:
        return jsonify({"error": "not found"}), 404
    new = Role(
        name=f"{orig.name} Copy",
        privileges=orig.privileges,
        assigned_users=orig.assigned_users
    )
    db.session.add(new)
    db.session.commit()
    return jsonify({"message": "duplicated", "role": new.to_dict()})


# Users API (full fields)
@app.route("/api/users", methods=["GET"])
def api_get_users():
    q = request.args.get("q", "").strip().lower()
    query = User.query
    if q:
        query = query.filter(
            (User.name.ilike(f"%{q}%")) |
            (User.email.ilike(f"%{q}%")) |
            (User.role.ilike(f"%{q}%")) |
            (User.branch.ilike(f"%{q}%"))
        )
    rows = query.order_by(User.id).all()
    return jsonify([u.to_dict() for u in rows])


@app.route("/api/users/<int:user_id>", methods=["GET"])
def api_get_user(user_id):
    u = User.query.get(user_id)
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(u.to_dict())


@app.route("/api/users", methods=["POST"])
def api_add_user():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    role_name = data.get("role") or None
    email = (data.get("email") or "").strip() or None
    phone = (data.get("phone") or "").strip() or None
    branch = (data.get("branch") or "").strip() or None

    if not name:
        return jsonify({"error": "missing name"}), 400
    if User.query.filter_by(name=name).first():
        return jsonify({"error": "user exists"}), 400

    u = User(name=name, role=role_name, email=email, phone=phone, branch=branch)
    db.session.add(u)
    db.session.commit()
    return jsonify({"message": "user added", "user": u.to_dict()})


@app.route("/api/users/<int:user_id>", methods=["PUT"])
def api_update_user(user_id):
    u = User.query.get(user_id)
    if not u:
        return jsonify({"error": "not found"}), 404
    data = request.json or {}
    if "name" in data:
        nm = (data.get("name") or "").strip()
        if nm and User.query.filter(User.name == nm, User.id != user_id).first():
            return jsonify({"error": "name already exists"}), 400
        u.name = nm or u.name
    if "role" in data:
        u.role = data.get("role")
    if "email" in data:
        u.email = data.get("email")
    if "phone" in data:
        u.phone = data.get("phone")
    if "branch" in data:
        u.branch = data.get("branch")
    db.session.commit()
    return jsonify({"message": "updated", "user": u.to_dict()})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id):
    u = User.query.get(user_id)
    if not u:
        return jsonify({"error": "not found"}), 404
    db.session.delete(u)
    db.session.commit()
    return jsonify({"message": "deleted"})


# -------------------------
# Frontend: single-file HTML (Roles page + Users page + sidebar)
# -------------------------
PAGE_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RBAC Admin — Users & Roles</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background:#f5f7fb; }
    .sidebar { width:220px; min-height:100vh; background:white; border-right:1px solid #e9ecef; position:fixed; }
    .main { margin-left:220px; padding:24px; max-width:1200px; }
    .menu-item { padding:12px 18px; color:#333; cursor:pointer; display:flex; align-items:center; gap:10px; text-decoration:none; }
    .menu-item.active { background:#f1f9ff; border-left:3px solid #2fa4e7; color:#0b79c1; }
    .box { background:white; padding:18px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
    .small-muted { color:#6c757d; font-size:0.9rem; }
    .priv-badge { background:#dff5e6; color:#1a7a3d; padding:4px 8px; border-radius:6px; font-size:0.85rem; margin-right:6px; }
  h1, h2, h3 {
  color: #007bff; /* soft blue for headings */
}

table, th, td {
  border: 1px solid #ddd; /* light border around rows and columns */
  border-collapse: collapse;
}
  </style>
</head>
<body>
  <div class="sidebar d-flex flex-column">
    <div class="p-3 border-bottom">
      <h5 class="m-0">RBAC</h5>
      <div class="small-muted">Admin panel</div>
    </div>
    <div id="navLinks" class="mt-2">
      <a class="menu-item" id="navUsers" onclick="showPage('users')">Users</a>
      <a class="menu-item active" id="navRoles" onclick="showPage('roles')">Roles</a>
    </div>
  </div>

  <div class="main">
  <nav class="navbar navbar-light bg-white shadow-sm px-4 py-2 mb-3" style="border-bottom:1px solid #ddd;">
  <span class="navbar-brand mb-0 h5">RBAC Admin Panel</span>
</nav>
    <!-- USERS PAGE -->
    <div id="page-users" style="display:none">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
          <h4>Users</h4>
          <div class="small-muted">Manage users — add / edit / delete</div>
        </div>
        <div class="d-flex gap-2 align-items-center">
          <button class="btn btn-success" id="btnCreateUser" onclick="openCreateUser()">Create User</button>
          <input id="userSearch" class="form-control form-control-sm" style="width:220px" placeholder="Search users...">
        </div>
      </div>

      <div class="box">
        <table class="table table-borderless align-middle">
          <thead>
            <tr class="small-muted">
              <th>NAME</th>
              <th>ROLE</th>
              <th>EMAIL</th>
              <th>MOBILE</th>
              <th>BRANCH</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody id="usersTableBody"></tbody>
        </table>
      </div>
    </div>
    <!-- ROLES PAGE -->
    <div id="page-roles">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
          <h4>Roles</h4>
          <div class="small-muted">Manage roles, privileges and assigned users</div>
        </div>
        <div class="d-flex gap-2 align-items-center">
          <button class="btn btn-success" id="btnCreateRole">Create Role</button>
          <input id="roleSearch" class="form-control form-control-sm" style="width:220px" placeholder="Search roles...">
        </div>
      </div>

      <div class="box">
        <table class="table table-borderless align-middle">
          <thead>
            <tr class="small-muted">
              <th>ROLE NAME</th>
              <th>PRIVILEGES</th>
              <th>USERS</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody id="rolesTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- User Modal (Create/Edit) -->
  <div class="modal fade" id="modalUser" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <form id="userForm">
          <div class="modal-header">
            <h5 class="modal-title" id="userModalTitle">Create User</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-2">
              <label class="form-label">Name (unique)</label>
              <input id="userName" class="form-control" placeholder="john@company.com" required>
            </div>
            <div class="mb-2">
              <label class="form-label">Role</label>
              <select id="userRole" class="form-select"></select>
            </div>
            <div class="mb-2">
              <label class="form-label">Email</label>
              <input id="userEmail" type="email" class="form-control">
            </div>
            <div class="mb-2">
              <label class="form-label">Mobile</label>
              <input id="userPhone" class="form-control">
            </div>
            <div class="mb-2">
              <label class="form-label">Branch</label>
              <input id="userBranch" class="form-control">
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button class="btn btn-primary" type="submit" id="userSaveBtn">Save User</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Role Modal (Create/Edit, with C/R/E/D checkboxes per module) -->
  <div class="modal fade" id="modalEdit" tabindex="-1">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <form id="roleForm">
          <div class="modal-header">
            <h5 class="modal-title" id="editTitle">Create Role</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label class="form-label">Role Name</label>
              <input id="roleName" class="form-control" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Assign Users</label>
              <select id="assignUsers" class="form-select" multiple></select>
              <div class="small-muted mt-1">Hold Ctrl/Cmd to select multiple users.</div>
            </div>
            <div class="mb-2">
              <label class="form-label">Privileges (C / R / E / D per module)</label>
              <div id="modulesPrivs" style="max-height:360px; overflow:auto; padding-right:6px;"></div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button class="btn btn-primary" type="submit">Save Role</button>
          </div>
        </form>
      </div>
    </div>
  </div>


<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const ROLE_API = "/api/roles";
const USER_API = "/api/users";
const MODULES = {{ modules|tojson }};
const POSSIBLE_PRIVS = {{ possible_privs|tojson }};

let usersList = [];
let rolesCache = [];
let editingRoleId = null;
let editingUserId = null;

// ---------- navigation ----------
function showPage(p){
  document.getElementById('page-users').style.display = (p==='users') ? '' : 'none';
  document.getElementById('page-roles').style.display = (p==='roles') ? '' : 'none';
  document.getElementById('navUsers').classList.toggle('active', p==='users');
  document.getElementById('navRoles').classList.toggle('active', p==='roles');
  if(p==='users') loadUsers();
  if(p==='roles') fetchRoles();
}
// start on roles
showPage('roles');

// ---------- Users logic ----------
async function loadUsers(q=''){
  const url = q ? `${USER_API}?q=${encodeURIComponent(q)}` : USER_API;
  const res = await fetch(url).then(r=>r.json());
  usersList = res;
  const tbody = document.getElementById('usersTableBody');
  tbody.innerHTML = '';
  if(!res.length){
    tbody.innerHTML = '<tr><td colspan="6" class="small-muted text-center">No users found</td></tr>';
    return;
  }
  res.forEach(u=>{
    tbody.innerHTML += `
      <tr>
        <td><strong>${u.name}</strong></td>
        <td>${u.role || '-'}</td>
        <td>${u.email || '-'}</td>
        <td>${u.phone || '-'}</td>
        <td>${u.branch || '-'}</td>
        <td>
          <button class="btn btn-outline-primary btn-sm" onclick="openEditUser(${u.id})">✏️</button>
          <button class="btn btn-outline-danger btn-sm" onclick="deleteUser(${u.id})">🗑️</button>
        </td>
      </tr>
    `;
  });
  populateRolesInUserForm();
}

function openCreateUser(){
  editingUserId = null;
  document.getElementById('userModalTitle').innerText = 'Create User';
  document.getElementById('userSaveBtn').innerText = 'Create User';
  document.getElementById('userName').value = '';
  document.getElementById('userRole').value = '';
  document.getElementById('userEmail').value = '';
  document.getElementById('userPhone').value = '';
  document.getElementById('userBranch').value = '';
  populateRolesInUserForm();
  new bootstrap.Modal(document.getElementById('modalUser')).show();
}

async function openEditUser(id){
  const u = await fetch(`${USER_API}/${id}`).then(r=>r.json());
  editingUserId = id;
  document.getElementById('userModalTitle').innerText = 'Edit User';
  document.getElementById('userSaveBtn').innerText = 'Update User';
  document.getElementById('userName').value = u.name;
  document.getElementById('userRole').value = u.role || '';
  document.getElementById('userEmail').value = u.email || '';
  document.getElementById('userPhone').value = u.phone || '';
  document.getElementById('userBranch').value = u.branch || '';
  populateRolesInUserForm();
  new bootstrap.Modal(document.getElementById('modalUser')).show();
}

function populateRolesInUserForm(){
  fetch(ROLE_API).then(r=>r.json()).then(data=>{
    const sel = document.getElementById('userRole');
    sel.innerHTML = '<option value="">Select role</option>';
    data.forEach(r=>{
      const opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = r.name;
      sel.appendChild(opt);
    });
  });
}

document.getElementById('userForm').addEventListener('submit', function(e){
  e.preventDefault();
  const payload = {
    name: document.getElementById('userName').value.trim(),
    role: document.getElementById('userRole').value || '',
    email: document.getElementById('userEmail').value.trim(),
    phone: document.getElementById('userPhone').value.trim(),
    branch: document.getElementById('userBranch').value.trim()
  };
  if(!payload.name) return alert('Enter name');
  const url = editingUserId ? `${USER_API}/${editingUserId}` : USER_API;
  const method = editingUserId ? 'PUT' : 'POST';
  fetch(url, {method, headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)})
    .then(r=>r.json()).then(res=>{
      if(res.error) alert(res.error);
      else {
        bootstrap.Modal.getInstance(document.getElementById('modalUser')).hide();
        loadUsers();
        fetchRoles(); // refresh roles user counts
      }
    });
});

function deleteUser(id){
  if(!confirm('Delete user id '+id+'?')) return;
  fetch(`${USER_API}/${id}`, {method:'DELETE'}).then(()=> { loadUsers(); fetchRoles(); });
}

document.getElementById('userSearch').addEventListener('input', function(e){
  loadUsers(e.target.value.trim());
});

// ---------- Roles logic ----------
function fetchUsersList(){
  return fetch(USER_API).then(r=>r.json()).then(data=>{
    usersList = data;
  });
}

function populateUserSelect(selected=[]){
  const sel = document.getElementById("assignUsers");
  if(!sel) return;
  sel.innerHTML = "";
  usersList.forEach(u=>{
    const opt = document.createElement("option");
    opt.value = u.name;
    opt.textContent = u.name;
    if(selected.includes(u.name)) opt.selected = true;
    sel.appendChild(opt);
  });
}

function fetchRoles(q=""){
  fetch(ROLE_API + (q ? "?q="+encodeURIComponent(q):"")).then(r=>r.json()).then(data=>{
    rolesCache = data;
    renderRolesTable();
  });
}

function renderRolesTable(){
  const tbody = document.getElementById("rolesTableBody");
  tbody.innerHTML = "";
  if(!rolesCache.length){
    tbody.innerHTML = `<tr><td colspan="4" class="small-muted">No roles found</td></tr>`;
    return;
  }
  rolesCache.forEach(r=>{
    const tr = document.createElement("tr");
    const userCount = r.assigned_users ? r.assigned_users.length : 0;
    tr.innerHTML = `
      <td><strong>${r.name}</strong></td>
      <td>${r.privileges_count} privs / ${r.modules_count} modules</td>
      <td>${userCount} user${userCount!==1?"s":""}</td>
      <td>
        <button class="btn btn-outline-primary btn-sm" onclick="editRole(${r.id})">✏️</button>
        <button class="btn btn-outline-danger btn-sm" onclick="deleteRole(${r.id})">🗑️</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

function renderModulesPrivs(privObj){
  const c = document.getElementById("modulesPrivs");
  c.innerHTML = "";
  MODULES.forEach(m=>{
    const wrap = document.createElement("div");
    wrap.className = "mb-2";
    wrap.innerHTML = `<div><strong>${m}</strong></div>`;
    // Only show Create/Read/Update/Delete checkboxes (C/R/E/D)
    ["create","read","update","delete"].forEach(p=>{
      const id = `chk_${encodeURIComponent(m)}_${p}`;
      const checked = (privObj[m]||[]).includes(p);
      wrap.insertAdjacentHTML("beforeend", `<div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="${id}" value="${p}" ${checked?"checked":""}><label class="form-check-label" for="${id}">${p.toUpperCase()}</label></div>`);
    });
    c.appendChild(wrap);
  });
}

function openCreateModal(){
  editingRoleId = null;
  document.getElementById("editTitle").innerText = "Create Role";
  document.getElementById("roleName").value = "";
  populateUserSelect([]);
  renderModulesPrivs({});
  new bootstrap.Modal(document.getElementById("modalEdit")).show();
}

function editRole(id){
  fetch(ROLE_API+"/"+id).then(r=>r.json()).then(role=>{
    editingRoleId = id;
    document.getElementById("editTitle").innerText = "Edit Role";
    document.getElementById("roleName").value = role.name || "";
    populateUserSelect(role.assigned_users || []);
    renderModulesPrivs(role.privileges || {});
    new bootstrap.Modal(document.getElementById("modalEdit")).show();
  });
}

document.getElementById("btnCreateRole").addEventListener("click", function(){ fetchUsersList().then(()=> openCreateModal()); });

// Role modal: save
document.getElementById("roleForm").addEventListener("submit", function(e){
  e.preventDefault();
  const name = document.getElementById("roleName").value.trim();
  if(!name) return alert("Enter role name");
  const sel = document.getElementById("assignUsers");
  const selectedUsers = sel ? Array.from(sel.selectedOptions).map(o=>o.value) : [];
  const priv = {};
  MODULES.forEach(m=>{
    const perms = [];
    ["create","read","update","delete"].forEach(p=>{
      const id = `chk_${encodeURIComponent(m)}_${p}`;
      const el = document.getElementById(id);
      if(el && el.checked) perms.push(p);
    });
    if(perms.length) priv[m] = perms;
  });
  const payload = { name:name, privileges:priv, assigned_users:selectedUsers };
  const method = editingRoleId ? "PUT":"POST";
  const url = editingRoleId ? ROLE_API+"/"+editingRoleId : ROLE_API;
  fetch(url, {method, headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)})
    .then(r=>r.json()).then(res=>{
      if(res.error) alert(res.error);
      else { fetchRoles(); bootstrap.Modal.getInstance(document.getElementById("modalEdit")).hide(); }
    });
});

function deleteRole(id){
  if(!confirm("Delete role id "+id+"?")) return;
  fetch(ROLE_API+"/"+id,{method:"DELETE"}).then(r=>r.json()).then(()=>fetchRoles());
}

document.getElementById("roleSearch").addEventListener("input",e=>fetchRoles(e.target.value.trim()));

// initial loads
fetchUsersList().then(()=>fetchRoles());
</script>
</body>
</html>
"""


# -------------------------
# Routes / Run
# -------------------------
@app.route("/")
def root():
    return ("", 302, {"Location": "/roles"})


@app.route("/roles")
def page_roles():
    return render_template_string(PAGE_HTML, modules=DEFAULT_MODULES, possible_privs=POSSIBLE_PRIVS)


if __name__ == "__main__":
    print("Starting RBAC app on http://127.0.0.1:5000/roles")
    app.run(debug=True)
