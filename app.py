from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo
import threading

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

app = Flask(__name__, template_folder='templates')
app.secret_key = APP_SECRET


def get_auto_selected_series():
    """Automatically select the first series with available folios (by ID order)"""
    conn = get_db()
    
    # Get all series in ID order, find first with available folios
    series_list = conn.execute('''
        SELECT s.*, 
               (s.total_added - COALESCE(SUM(a.qty), 0)) as available
        FROM series s
        LEFT JOIN assignments a ON s.id = a.series_id
        GROUP BY s.id
        ORDER BY s.id ASC
    ''').fetchall()
    
    conn.close()
    
    # Return the first series with available folios
    for series in series_list:
        if series['available'] > 0:
            return series
    return None


def auto_unify_duplicate_plants():
    """Unificar automáticamente planteles con nombres duplicados"""
    conn = get_db()
    
    print("=== AUTO-UNIFY: Checking for duplicate plants ===")
    
    # Encontrar todos los nombres duplicados
    duplicates = conn.execute('''
        SELECT name, COUNT(*) as count, GROUP_CONCAT(id) as ids
        FROM plants 
        WHERE name != 'GHOST_PLANT'
        GROUP BY name 
        HAVING count > 1
    ''').fetchall()
    
    if not duplicates:
        print("=== AUTO-UNIFY: No duplicates found ===")
        conn.close()
        return
    
    print(f"=== AUTO-UNIFY: Found {len(duplicates)} duplicate groups ===")
    
    for dup in duplicates:
        name, count, ids_str = dup
        ids = [int(id_str) for id_str in ids_str.split(',')]
        
        print(f"=== AUTO-UNIFY: Processing {name} ({count} duplicates) ===")
        
        # Mantener el primer plantel como principal
        keep_id = ids[0]
        other_ids = ids[1:]
        
        # Obtener asignaciones de los otros planteles
        total_qty_to_move = 0
        
        for other_id in other_ids:
            assignments = conn.execute('SELECT * FROM assignments WHERE plant_id = ?', (other_id,)).fetchall()
            for assign in assignments:
                total_qty_to_move += assign[3]
                # Mover asignación al plantel principal
                conn.execute('UPDATE assignments SET plant_id = ? WHERE id = ?', (keep_id, assign[0]))
                print(f"=== AUTO-UNIFY: Moved assignment ID={assign[0]} to plant {keep_id} ===")
        
        # Actualizar qty_total del plantel principal
        if total_qty_to_move > 0:
            current_qty = conn.execute('SELECT qty_total FROM plants WHERE id = ?', (keep_id,)).fetchone()[0]
            new_qty = current_qty + total_qty_to_move
            conn.execute('UPDATE plants SET qty_total = ? WHERE id = ?', (new_qty, keep_id))
            print(f"=== AUTO-UNIFY: Updated plant {keep_id} qty_total: {current_qty} -> {new_qty} ===")
        
        # Eliminar los otros planteles
        for other_id in other_ids:
            conn.execute('DELETE FROM plants WHERE id = ?', (other_id,))
            print(f"=== AUTO-UNIFY: Deleted duplicate plant ID={other_id} ===")
    
    conn.commit()
    conn.close()
    print("=== AUTO-UNIFY: Process completed ===")


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
    except Exception:
        pass
    return conn


def now_str():
    try:
        tz = ZoneInfo("America/Mexico_City")
        dt = datetime.now(tz)
    except Exception:
        # Fallback: hora local del sistema si no hay base tz disponible (Windows sin tzdata)
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_date(date_str):
    """Formatea fecha de YYYY-MM-DD HH:MM:SS a DD-MM-YYYY"""
    if not date_str or date_str == 'None' or date_str == '':
        return '-'
    try:
        # Si viene con hora, separar solo la fecha
        if ' ' in date_str:
            date_part = date_str.split(' ')[0]
        else:
            date_part = date_str
        
        # Parsear y formatear
        dt = datetime.strptime(date_part, "%Y-%m-%d")
        return dt.strftime("%d-%m-%Y")
    except Exception:
        return date_str  # Retorna original si hay error

# Global lock to serialize writes to SQLite and reduce 'database is locked' during dev
write_lock = threading.Lock()


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # users
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL CHECK(role IN ('standard','admin')),
            created_at TEXT NOT NULL
        )
        """
    )

    # plants (planteles)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS plants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            cct TEXT NOT NULL,
            qty_total INTEGER DEFAULT 0
        )
        """
    )

    # series master
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS series (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            total_added INTEGER NOT NULL DEFAULT 0,
            next_folio INTEGER NOT NULL DEFAULT 1,
            remaining INTEGER NOT NULL DEFAULT 0,
            first_folio INTEGER,
            last_folio,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # series master
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plant_id INTEGER NOT NULL,
            series_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            start_folio INTEGER NOT NULL,
            end_folio INTEGER NOT NULL,
            assigned_by INTEGER NOT NULL,
            assigned_at TEXT NOT NULL,
            FOREIGN KEY (plant_id) REFERENCES plants(id),
            FOREIGN KEY (series_id) REFERENCES series(id),
            FOREIGN KEY (assigned_by) REFERENCES users(id)
        )
        """
    )

    # movements log
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    # default admin user if none exists
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", None, "admin", now_str()),
        )
        # sample plant for demo
        cur.execute(
            "INSERT OR IGNORE INTO plants (name, cct) VALUES (?, ?)",
            ("Plantel Demo", "CCT0001"),
        )
    conn.commit()
    conn.close()
    
    # Clean up zero-quantity assignments after database is fully initialized
    print("=== INIT_DB: Checking for zero-quantity assignments ===")
    deleted_count = cleanup_zero_assignments()
    if deleted_count > 0:
        print(f"=== INIT_DB: Cleaned up {deleted_count} zero-quantity assignments ===")
    else:
        print("=== INIT_DB: No zero-quantity assignments found ===")


@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        # migrate if needed
        try:
            migrate_db()
        except Exception:
            pass


# ---------- helpers ----------

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user

@app.context_processor
def inject_helpers():
    return dict(current_user=current_user, format_date=format_date)


def require_login():
    if not current_user():
        return redirect(url_for('login'))
    return None


def migrate_db():
    conn = get_db()
    cur = conn.cursor()
    
    # Migrate series table
    info = cur.execute("PRAGMA table_info(series)").fetchall()
    cols = {row[1] for row in info}
    if 'first_folio' not in cols:
        cur.execute("ALTER TABLE series ADD COLUMN first_folio INTEGER")
    if 'last_folio' not in cols:
        cur.execute("ALTER TABLE series ADD COLUMN last_folio INTEGER")
    if 'created_at' not in cols:
        cur.execute("ALTER TABLE series ADD COLUMN created_at TEXT")
        # Update existing records with current timestamp
        cur.execute("UPDATE series SET created_at = ? WHERE created_at IS NULL", (now_str(),))
    
    # Migrate plants table
    info = cur.execute("PRAGMA table_info(plants)").fetchall()
    cols = {row[1] for row in info}
    if 'qty_total' not in cols:
        cur.execute("ALTER TABLE plants ADD COLUMN qty_total INTEGER DEFAULT 0")
        print("=== MIGRATION: Added qty_total column to plants table ===")
    
    # Remove UNIQUE constraint from CCT if exists
    try:
        # Create new table without UNIQUE constraint
        cur.execute("""
            CREATE TABLE IF NOT EXISTS plants_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                cct TEXT NOT NULL,
                qty_total INTEGER DEFAULT 0
            )
        """)
        
        # Copy data from old table
        cur.execute("""
            INSERT INTO plants_new (id, name, cct, qty_total)
            SELECT id, name, cct, qty_total FROM plants
        """)
        
        # Drop old table and rename new one
        cur.execute("DROP TABLE plants")
        cur.execute("ALTER TABLE plants_new RENAME TO plants")
        
        print("=== MIGRATION: Removed UNIQUE constraint from CCT column ===")
        
    except sqlite3.OperationalError as e:
        if "no such table" not in str(e):
            print(f"=== MIGRATION: CCT migration already completed or not needed ===")
    
    conn.commit()
    conn.close()


# ---------- auth ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f"=== LOGIN REQUEST ===")
    print(f"Method: {request.method}")
    print(f"Form data: {dict(request.form)}")
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Depuración temporal
        print(f"=== LOGIN DEBUG ===")
        print(f"Username: '{username}'")
        print(f"Password length: {len(password)}")
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if not user:
            print("Usuario no encontrado")
            flash('Usuario/contraseña inválidos', 'danger')
            return render_template('login.html')
            
        print(f"User found: {user[1]}")
        print(f"Password hash: '{user[2]}' (length: {len(user[2]) if user[2] else 0})")
        print(f"Condition check: not user['password_hash'] or user['password_hash'] == '' = {not user['password_hash'] or user['password_hash'] == ''}")
        
        if not user['password_hash'] or user['password_hash'] == '':
            print("Redirigiendo a set_password...")
            # first time - set password flow
            session['pending_user_id'] = user['id']
            print(f"Session pending_user_id set to: {user['id']}")
            return redirect(url_for('set_password'))
        if not check_password_hash(user['password_hash'], password):
            print("Password incorrect")
            flash('Usuario/contraseña inválidos', 'danger')
            return render_template('login.html')
        session['user_id'] = user['id']
        session['role'] = user['role']
        flash('Bienvenido', 'success')
        return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    pending_id = session.get('pending_user_id')
    if not pending_id:
        return redirect(url_for('login'))
    if request.method == 'POST':
        p1 = request.form.get('password', '')
        p2 = request.form.get('password2', '')
        if not p1 or p1 != p2:
            flash('Las contraseñas no coinciden', 'danger')
            return render_template('set_password.html')
        conn = get_db()
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(p1), pending_id),
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE id=?", (pending_id,)).fetchone()
        conn.execute(
            "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
            (pending_id, 'set_password', 'Primer contraseña establecida', now_str()),
        )
        conn.commit()
        conn.close()
        session.pop('pending_user_id', None)
        session['user_id'] = user['id']
        session['role'] = user['role']
        flash('Contraseña establecida', 'success')
        return redirect(url_for('home'))
    return render_template('set_password.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------- common/home ----------
@app.route('/')
def index():
    if not current_user():
        return redirect(url_for('login'))
    return redirect(url_for('home'))


@app.route('/home', methods=['GET', 'POST'])
def home():
    guard = require_login()
    if guard:
        return guard
    user = current_user()
    selected_series = None
    search_results = []
    query = ''
    
    if request.method == 'POST':
        query = request.form.get('serie', '').strip()
        if query:
            # Search for series
            conn = get_db()
            search_results = conn.execute("SELECT * FROM series WHERE name LIKE ? ORDER BY name", (f"%{query}%",)).fetchall()
            conn.close()
            return render_template('home.html', user=user, selected_series=selected_series, search_results=search_results, query=query, timestamp=int(time.time()))
        else:
            return redirect(url_for('series'))
    
    # If user has selected series, get complete series data
    if 'selected_series_id' in session:
        conn = get_db()
        selected_series = conn.execute("SELECT * FROM series WHERE id=?", (session['selected_series_id'],)).fetchone()
    elif session.get('role') == 'standard':
        # For standard users, automatically select the first available series
        conn = get_db()
        first_series = conn.execute("SELECT * FROM series ORDER BY id LIMIT 1").fetchone()
        if first_series:
            session['selected_series_id'] = first_series['id']
            selected_series = first_series
        else:
            selected_series = None
    else:
        selected_series = None
    
    # Calculate folios if we have a selected series
    if selected_series:
        # Get assignments
        all_assignments = conn.execute("""
            SELECT SUM(qty) as total_assigned, 
                   MIN(start_folio) as first_folio
            FROM assignments 
            WHERE series_id = ? AND qty > 0
        """, (session.get('selected_series_id'),)).fetchone()
        
        # Calculate correct remaining
        total_assigned = all_assignments[0] or 0
        calculated_remaining = (selected_series[2] or 0) - total_assigned
        
        # Convert to dict and add calculated values
        selected_series = dict(selected_series)
        selected_series['remaining'] = calculated_remaining
        
        # Calculate folios - SIMPLIFIED: always use series first_folio and total_added
        calculated_first_folio = selected_series['first_folio']
        calculated_last_folio = calculated_first_folio + (selected_series['total_added'] or 0) - 1
        
        selected_series['calculated_first_folio'] = calculated_first_folio
        selected_series['calculated_last_folio'] = calculated_last_folio
    
    # Render template
    return render_template('home.html', user=user, selected_series=selected_series, search_results=search_results, query=query, timestamp=int(time.time()))
    if q:
        print(f"=== DEBUG: Searching series with query: {q} ===")
        rows = conn.execute("SELECT * FROM series WHERE name LIKE ? ORDER BY name", (f"%{q}%",)).fetchall()
        print(f"=== DEBUG: Found {len(rows)} series ===")
    elif plant_id:
        print(f"=== DEBUG: Filtering by plant_id: {plant_id} ===")
        # Show all series, but mark which ones are assigned to this plant
        rows = conn.execute("SELECT * FROM series ORDER BY name").fetchall()
        print(f"=== DEBUG: Found {len(rows)} total series for plant filtering ===")
    else:
        print(f"=== DEBUG: Showing all series ===")
        rows = conn.execute("SELECT * FROM series ORDER BY name").fetchall()
        print(f"=== DEBUG: Found {len(rows)} total series ===")
    
    conn.close()
    print(f"=== DEBUG: Series route END ===")
    print(f"=== DEBUG: Passing to template: rows={len(rows)}, q='{q}', plant_id='{plant_id}' ===")
    # Add cache-busting timestamp
    return render_template('series_list.html', rows=rows, q=q, plant_id=plant_id, timestamp=int(time.time()))


@app.route('/series/select/<int:series_id>')
def select_series(series_id: int):
    guard = require_login()
    if guard:
        return guard
    conn = get_db()
    row = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    conn.close()
    if not row:
        abort(404)
    session['selected_series_id'] = series_id
    flash(f"Serie seleccionada: {row['name']}", 'info')
    
    # Check if user was coming from a plant detail page
    return_to = request.args.get('return_to')
    if return_to and return_to.startswith('plant_detail_'):
        plant_id = return_to.replace('plant_detail_', '')
        return redirect(url_for('plant_detail', plant_id=plant_id))
    
    # Check if admin is coming from admin plants section
    if return_to and return_to == 'admin_plants':
        plant_id = request.args.get('plant')
        if plant_id and session.get('role') == 'admin':
            # Admin is assigning a series to a specific plant
            try:
                plant_id_int = int(plant_id)
                conn = get_db()
                
                # Check if plant exists
                plant = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id_int,)).fetchone()
                if not plant:
                    conn.close()
                    flash('Plantel no encontrado', 'danger')
                    return redirect(url_for('admin_plants'))
                
                # Check if series is already assigned to this plant
                existing = conn.execute("SELECT * FROM assignments WHERE plant_id=? AND series_id=?", (plant_id_int, series_id)).fetchone()
                if existing:
                    conn.close()
                    flash(f'La serie {row["name"]} ya está asignada al plantel {plant["name"]}', 'warning')
                    return redirect(url_for('admin_plants'))
                
                # Assign the series to the plant with full qty_total
                qty_to_assign = plant['qty_total'] or 0
                if qty_to_assign > 0:
                    start_folio = row['next_folio'] or 1
                    end_folio = start_folio + qty_to_assign - 1
                    
                    # Update series remaining
                    new_remaining = (row['remaining'] or 0) - qty_to_assign
                    if new_remaining < 0:
                        conn.close()
                        flash(f'No hay suficientes folios en la serie {row["name"]}. Disponibles: {row["remaining"]}', 'danger')
                        return redirect(url_for('admin_plants'))
                    
                    try:
                        with write_lock:
                            conn.execute("BEGIN IMMEDIATE")
                            # Create assignment
                            conn.execute(
                                "INSERT INTO assignments (plant_id, series_id, qty, start_folio, end_folio, assigned_by, assigned_at) VALUES (?,?,?,?,?,?,?)",
                                (plant_id_int, series_id, qty_to_assign, start_folio, end_folio, session['user_id'], now_str())
                            )
                            # Update series
                            conn.execute("UPDATE series SET remaining=?, next_folio=? WHERE id=?", (new_remaining, end_folio + 1, series_id))
                            # Record movement
                            conn.execute(
                                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                                (session['user_id'], 'assign_series_to_plant', f"plant_id={plant_id_int}; series_id={series_id}; qty={qty_to_assign}", now_str())
                            )
                            conn.commit()
                            conn.close()
                            flash(f'Serie {row["name"]} asignada al plantel {plant["name"]} ({qty_to_assign} folios)', 'success')
                    except sqlite3.OperationalError:
                        conn.rollback()
                        conn.close()
                        flash('La base de datos está ocupada. Intenta nuevamente.', 'warning')
                else:
                    conn.close()
                    flash(f'El plantel {plant["name"]} no tiene folios asignados', 'warning')
                
                return redirect(url_for('admin_plants'))
                
            except ValueError:
                flash('ID de plantel inválido', 'danger')
                return redirect(url_for('admin_plants'))
        
        # If no plant_id, just redirect to admin plants with series selected
        flash(f"Serie {row['name']} seleccionada. Ahora puede asignarla a un plantel.", 'info')
        return redirect(url_for('admin_plants'))
    
    # If admin, redirect to admin dashboard instead of home
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    return redirect(url_for('home'))


# ---------- standard user ----------
@app.route('/standard/search', methods=['GET', 'POST'])
def standard_search():
    print(f"=== DEBUG: standard_search called ===")
    print(f"=== DEBUG: Session: {dict(session)} ===")
    print(f"=== DEBUG: Session role: {session.get('role')} ===")
    
    guard = require_login()
    if guard:
        print(f"=== DEBUG: require_login failed: {guard} ===")
        return guard
    
    if session.get('role') not in ['standard', 'admin', 'supervisor']:
        print(f"=== DEBUG: Role check failed - expected 'standard', 'admin', or 'supervisor', got '{session.get('role')}' ===")
        abort(403)
    
    print(f"=== DEBUG: Authentication passed, proceeding with standard_search ===")
    plants = []
    if request.method == 'POST':
        action = request.form.get('action', 'search')
        if action == 'add':
            conn = get_db()
            name = request.form.get('name', '').strip()
            cct = request.form.get('cct', '').strip()
            if not name or not cct:
                flash('Nombre y CCT son requeridos', 'danger')
                conn.close()
            else:
                print(f"=== DEBUG: Attempting to add plant - Name: '{name}', CCT: '{cct}' ===")
                
                # Check if plant name already exists
                existing_plant = conn.execute("SELECT * FROM plants WHERE name = ?", (name,)).fetchone()
                if existing_plant:
                    conn.close()
                    print(f"=== DEBUG: Plant name '{name}' already exists ===")
                    flash(f'El plantel "{name}" ya existe en el sistema.', 'warning')
                    return redirect(url_for('standard_search'))
                
                try:
                    with write_lock:
                        conn.execute("BEGIN IMMEDIATE")
                        # Insert the plant
                        conn.execute("INSERT INTO plants (name, cct) VALUES (?,?)", (name, cct))
                        
                        # Get the plant_id that was just inserted
                        plant_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                        
                        # Record the movement
                        conn.execute(
                            "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                            (session['user_id'], 'add_plant', f"plant_id={plant_id}; name={name}; cct={cct}", now_str())
                        )
                        
                        conn.commit()
                    conn.close()
                    flash('Plantel agregado', 'success')
                    # Auto-unify duplicate plants
                    auto_unify_duplicate_plants()
                    return redirect(url_for('standard_search', q=cct))
                except sqlite3.IntegrityError:
                    conn.rollback()
                    conn.close()
                    print(f"=== DEBUG: CCT '{cct}' already exists ===")
                    flash(f'El CCT "{cct}" ya existe en el sistema. Por favor, use un CCT diferente.', 'warning')
                    # Don't redirect, just continue to show the message
                except sqlite3.OperationalError:
                    conn.rollback()
                    conn.close()
                    flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        # for non-add POST, fall through to GET-like search using submitted term
        return redirect(url_for('standard_search', q=request.form.get('term', '').strip()))

    # GET: support optional q to filter; default show all
    term = (request.args.get('q') or '').strip()
    sort = request.args.get('sort', 'name')
    order = request.args.get('order', 'asc')
    
    # Validate sort field
    valid_sort_fields = ['name', 'assigned_total']
    if sort not in valid_sort_fields:
        sort = 'name'
    
    # Validate order
    if order not in ['asc', 'desc']:
        order = 'asc'
    
    conn = get_db()
    if term:
        # Build query with sorting
        order_clause = f"ORDER BY p.{sort} {order.upper()}"
        if sort == 'assigned_total':
            order_clause = f"ORDER BY COALESCE(SUM(a.qty), 0) {order.upper()}"
        
        plants = conn.execute(
            f"""
            SELECT p.*, COALESCE(SUM(a.qty), 0) as assigned_total
            FROM plants p
            LEFT JOIN assignments a ON p.id = a.plant_id
            WHERE p.name LIKE ? OR p.cct LIKE ?
            GROUP BY p.id
            {order_clause}
            """,
            (f"%{term}%", f"%{term}%"),
        ).fetchall()
    else:
        # Build query with sorting
        order_clause = f"ORDER BY p.{sort} {order.upper()}"
        if sort == 'assigned_total':
            order_clause = f"ORDER BY COALESCE(SUM(a.qty), 0) {order.upper()}"
        
        plants = conn.execute(
            f"""
            SELECT p.*, COALESCE(SUM(a.qty), 0) as assigned_total
            FROM plants p
            LEFT JOIN assignments a ON p.id = a.plant_id
            GROUP BY p.id
            {order_clause}
            """
        ).fetchall()
    
    print(f"=== DEBUG: Search results for term='{term}' ===")
    for p in plants:
        print(f"=== DEBUG: Plant ID={p['id']}, Name={p['name']}, CCT={p['cct']}: assigned_total={p['assigned_total']} ===")
    
    conn.close()
    return render_template('standard/search_plants.html', plants=plants, q=term, sort=sort, order=order, timestamp=int(time.time()))


@app.route('/standard/plant/<int:plant_id>', methods=['GET', 'POST'])
def plant_detail(plant_id: int):
    guard = require_login()
    if guard:
        return guard
    # Allow both standard users and admins to access plant detail
    # if session.get('role') != 'standard':
    #     abort(403)
    sort_key = request.args.get('sort', 'fecha')
    sort_dir = request.args.get('dir', 'desc').lower()
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'
    sort_map = {
        'plantel': 's.name',  # not applicable here; series name
        'cct': 's.name',      # placeholder, kept for consistency
        'cantidad': 'a.qty',
        'folio_inicial': 'a.start_folio',
        'folio_final': 'a.end_folio',
        'fecha': 'a.assigned_at',
        'serie': 's.name',
        'usuario': 'u.username',
    }
    order_col = sort_map.get(sort_key, 'a.assigned_at')
    order_clause = f"ORDER BY {order_col} {sort_dir.upper()}"

    conn = get_db()
    all_plants = conn.execute("SELECT * FROM plants ORDER BY id").fetchall()
    print(f"=== DEBUG: All plants in database ===")
    for p in all_plants:
        print(f"=== DEBUG: Plant ID={p['id']}, Name={p['name']}, CCT={p['cct']} ===")
    
    plant = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id,)).fetchone()
    if not plant:
        conn.close()
        abort(404)
    
    # Fix overlapping assignment 573206-573505
    overlapping_assignment = conn.execute(
        "SELECT * FROM assignments WHERE start_folio = 573206 AND end_folio = 573505"
    ).fetchone()
    
    if overlapping_assignment:
        # Calculate correct folio range
        last_assignment = conn.execute(
            "SELECT MAX(end_folio) as last_folio FROM assignments WHERE series_id = ? AND plant_id != 5",
            (series['id'],)
        ).fetchone()
        
        if last_assignment and last_assignment['last_folio']:
            new_start = last_assignment['last_folio'] + 1
            new_end = new_start + overlapping_assignment['qty'] - 1
            
            conn.execute(
                "UPDATE assignments SET start_folio = ?, end_folio = ? WHERE id = ?",
                (new_start, new_end, overlapping_assignment['id'])
            )
            conn.commit()
            print(f"=== DEBUG: Fixed overlapping assignment {overlapping_assignment['id']}: 573206-573505 to {new_start}-{new_end} ===")
        else:
            print(f"=== DEBUG: Could not determine last folio for series {series['id']} ===")
    else:
        print(f"=== DEBUG: No overlapping assignment found to fix ===")

    # Calculate total assigned folios for this plant
    assigned_total_result = conn.execute("SELECT SUM(qty) FROM assignments WHERE plant_id=?", (plant_id,)).fetchone()
    assigned_total = assigned_total_result[0] if assigned_total_result and assigned_total_result[0] is not None else 0
    
    print(f"=== DEBUG: Plant {plant_id} assigned_total calculation ===")
    print(f"=== DEBUG: Query: SELECT SUM(qty) FROM assignments WHERE plant_id={plant_id} ===")
    print(f"=== DEBUG: Query result: {assigned_total_result} ===")
    print(f"=== DEBUG: assigned_total_result[0]: {assigned_total_result[0] if assigned_total_result else 'None'} ===")
    print(f"=== DEBUG: Final assigned_total: {assigned_total} ===")
    print(f"=== DEBUG: Plant qty_total: {plant['qty_total']} ===")
    print(f"=== DEBUG: Available calculation: {plant['qty_total']} - {assigned_total} = {(plant['qty_total'] or 0) - assigned_total} ===")
    
    series = None
    calculated_remaining = 0
    
    # Auto-select series with most available folios
    auto_series = get_auto_selected_series()
    if auto_series:
        series = {
            'id': auto_series['id'],
            'name': auto_series['name'],
            'total_added': auto_series['total_added'],
            'remaining': auto_series['available'],
            'first_folio': auto_series['first_folio'] if auto_series['first_folio'] is not None else 1,
            'next_folio': auto_series['next_folio'] if auto_series['next_folio'] is not None else 1,
        }
        calculated_remaining = auto_series['available']
        
        # Update session with auto-selected series
        session['selected_series_id'] = auto_series['id']
        print(f"=== AUTO-SERIES: Selected {auto_series['name']} with {auto_series['available']} available folios ===")
    else:
        print("=== AUTO-SERIES: No available series found ===")
    assigns = conn.execute(
        f"""
        SELECT a.*, s.name as series_name, u.username as user_name
        FROM assignments a
        JOIN series s ON s.id = a.series_id
        JOIN users u ON u.id = a.assigned_by
        WHERE a.plant_id = ?
        {order_clause}
        """,
        (plant_id,),
    ).fetchall()
    
    print(f"=== DEBUG: Assignments for plant {plant_id} ===")
    for i, a in enumerate(assigns):
        print(f"=== DEBUG: Assignment {i}: id={a['id']}, series={a['series_name']}, qty={a['qty']}, start_folio={a['start_folio']}, end_folio={a['end_folio']} ===")
    
    # Calculate plant folio range
    plant_folio_start = None
    plant_folio_end = None
    if assigns:
        plant_folio_start = min(a['start_folio'] for a in assigns)
        plant_folio_end = max(a['end_folio'] for a in assigns)
    
    print(f"=== DEBUG: Plant folio range: {plant_folio_start} - {plant_folio_end} ===")
    print(f"=== DEBUG: Plant data - qty_total: {plant['qty_total']}, assigned_total: {assigned_total} ===")
    print(f"=== DEBUG: Available calculation: {plant['qty_total']} - {assigned_total} = {(plant['qty_total'] or 0) - assigned_total} ===")
    print(f"=== DEBUG: Series data - total_added: {series['total_added'] if series else 'None'} ===")

    if request.method == 'POST':
        if not series:
            conn.close()
            flash('Seleccione una Serie primero en la pantalla principal', 'warning')
            return redirect(url_for('home'))
        
        try:
            qty = int(request.form.get('qty', '0'))
        except ValueError:
            qty = 0
        if qty <= 0:
            conn.close()
            flash('Cantidad inválida', 'danger')
            return redirect(url_for('plant_detail', plant_id=plant_id))
        print(f"=== DEBUG: Assignment POST request ===")
        print(f"=== DEBUG: plant_id={plant_id}, qty={qty}, series_id={series['id']} ===")
        print(f"=== DEBUG: Series remaining check: total_added={series['total_added']}, remaining={series['remaining']} ===")
        print(f"=== DEBUG: Available folios: {(series['total_added'] or 0) - (series['remaining'] or 0)} ===")
        
        # Calculate actual assigned folios for this series
        actual_assigned = conn.execute(
            "SELECT COALESCE(SUM(qty), 0) FROM assignments WHERE series_id = ?",
            (series['id'],)
        ).fetchone()[0]
        actual_available = (series['total_added'] or 0) - actual_assigned
        
        print(f"=== DEBUG: Actual assigned: {actual_assigned}, Actual available: {actual_available} ===")
        
        # check remaining using actual calculation
        if actual_available < qty:
            print(f"=== DEBUG: Not enough folios - requested={qty}, available={actual_available} ===")
            conn.close()
            flash('No hay suficientes folios en la serie seleccionada', 'danger')
            return redirect(url_for('plant_detail', plant_id=plant_id))
        
        # Calculate next available folio based on actual assignments
        last_assignment = conn.execute(
            "SELECT MAX(end_folio) as last_folio FROM assignments WHERE series_id = ? AND plant_id != 5",
            (series['id'],)
        ).fetchone()
        
        print(f"=== DEBUG: Folio calculation for series {series['id']} ===")
        print(f"=== DEBUG: Last assignment result: {last_assignment} ===")
        print(f"=== DEBUG: Last folio found: {last_assignment['last_folio'] if last_assignment else 'None'} ===")
        
        if last_assignment and last_assignment['last_folio']:
            start = last_assignment['last_folio'] + 1
        else:
            start = series['first_folio'] or 1
        
        end = start + qty - 1
        
        print(f"=== DEBUG: Calculated folio range: {start} - {end} ===")
        # perform assignment
        try:
            now = now_str()
            with write_lock:
                conn.execute("BEGIN IMMEDIATE")
                print(f"=== DEBUG: Inserting assignment - plant_id={plant_id}, series_id={series['id']}, qty={qty}, start={start}, end={end} ===")
                conn.execute(
                    "INSERT INTO assignments (plant_id, series_id, qty, start_folio, end_folio, assigned_by, assigned_at) VALUES (?,?,?,?,?,?,?)",
                    (plant_id, series['id'], qty, start, end, session['user_id'], now),
                )
                print(f"=== DEBUG: Assignment inserted successfully ===")
                conn.execute(
                    "UPDATE series SET next_folio = ?, remaining = remaining - ? WHERE id = ?",
                    (end + 1, qty, series['id']),
                )
                print(f"=== DEBUG: Series updated - next_folio={end + 1}, remaining_reduced={qty} ===")
                conn.commit()
                print(f"=== DEBUG: Transaction committed successfully ===")
        except sqlite3.OperationalError as e:
            print(f"=== DEBUG: OperationalError during assignment: {e} ===")
            conn.rollback()
            conn.close()
            flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
            return redirect(url_for('plant_detail', plant_id=plant_id))
        # refresh
        plant = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id,)).fetchone()
        series = conn.execute("SELECT * FROM series WHERE id=?", (session['selected_series_id'],)).fetchone()
        assigns = conn.execute(
            f"""
            SELECT a.*, s.name as series_name, u.username as user_name
            FROM assignments a
            JOIN series s ON s.id = a.series_id
            JOIN users u ON u.id = a.assigned_by
            WHERE a.plant_id = ?
            {order_clause}
            """,
            (plant_id,),
        ).fetchall()
        conn.close()
        flash(f"Asignado: {qty} folios ({start}-{end})", 'success')
        
        # Recalculate calculated_remaining after assignment
        if series:
            new_conn = get_db()
            total_assigned_after = new_conn.execute(
                "SELECT COALESCE(SUM(qty), 0) FROM assignments WHERE series_id = ?", 
                (series['id'],)
            ).fetchone()[0]
            calculated_remaining = (series['total_added'] or 0) - total_assigned_after
            
            # Also recalculate assigned_total for this plant after assignment
            assigned_total_result = new_conn.execute("SELECT SUM(qty) FROM assignments WHERE plant_id=?", (plant_id,)).fetchone()
            assigned_total = assigned_total_result[0] if assigned_total_result and assigned_total_result[0] is not None else 0
            
            new_conn.close()
        
        return render_template('standard/plant_detail.html', plant=plant, series=series, assigns=assigns, assigned_total=assigned_total, plant_folio_start=plant_folio_start, plant_folio_end=plant_folio_end, calculated_remaining=calculated_remaining, sort_key=sort_key, sort_dir=sort_dir, timestamp=int(time.time()))

    conn.close()
    # Add cache-busting timestamp to force refresh
    print(f"=== DEBUG: Plant detail route - Plant ID: {plant_id} ===")
    print(f"=== DEBUG: Series available: {series is not None} ===")
    if series:
        print(f"=== DEBUG: Series name: {series['name']} ===")
        print(f"=== DEBUG: Series remaining: {series['remaining'] if 'remaining' in series.keys() else 'N/A'} ===")
    print(f"=== DEBUG: Plant qty_total: {plant['qty_total'] if plant else 'N/A'} ===")
    print(f"=== DEBUG: Assigned total: {assigned_total} ===")
    print(f"=== DEBUG: Available folios: {(plant['qty_total'] or 0) - (assigned_total or 0) if plant else 'N/A'} ===")
    print(f"=== DEBUG: Button disabled condition: not series={not series}, available <= 0={((plant['qty_total'] or 0) - (assigned_total or 0)) <= 0 if plant else 'N/A'} ===")
    
    print(f"=== DEBUG: Rendering plant_detail.html for plant_id={plant_id} ===")
    print(f"=== DEBUG: Template data - plant_folio_start={plant_folio_start}, plant_folio_end={plant_folio_end} ===")
    response = make_response(render_template('standard/plant_detail.html', plant=plant, series=series, assigns=assigns, assigned_total=assigned_total, plant_folio_start=plant_folio_start, plant_folio_end=plant_folio_end, calculated_remaining=calculated_remaining, sort_key=sort_key, sort_dir=sort_dir, timestamp=int(time.time())))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# ---------- admin ----------

def require_admin():
    if session.get('role') != 'admin':
        abort(403)


@app.route('/admin')
def admin_dashboard():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    stats = {}
    stats['series_total'] = conn.execute("SELECT COUNT(*) FROM series").fetchone()[0]
    total_added = conn.execute("SELECT COALESCE(SUM(total_added),0) FROM series").fetchone()[0]
    total_assigned = conn.execute("SELECT COALESCE(SUM(qty), 0) FROM assignments").fetchone()[0]
    stats['folios_restantes'] = total_added - total_assigned
    stats['planteles_total'] = conn.execute("SELECT COUNT(*) FROM plants").fetchone()[0]
    stats['usuarios_total'] = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    stats['asignaciones_total'] = conn.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
    conn.close()
    return render_template('admin/dashboard.html', stats=stats)


@app.route('/admin/series-simple')
def admin_series_simple():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    
    q = request.args.get('q', '').strip()
    plant_id = request.args.get('plant_id', '').strip()
    
    conn = get_db()
    
    # Get all plants for filter
    plants = conn.execute("SELECT id, name, cct FROM plants ORDER BY name").fetchall()
    
    # Get series with optional filters
    if q:
        series = conn.execute("SELECT * FROM series WHERE name LIKE ? ORDER BY name", (f"%{q}%",)).fetchall()
    elif plant_id:
        series = conn.execute("SELECT * FROM series WHERE id IN (SELECT series_id FROM assignments WHERE plant_id = ?) ORDER BY name", (plant_id,)).fetchall()
    else:
        series = conn.execute("SELECT * FROM series ORDER BY name").fetchall()
    
    conn.close()
    return render_template('admin/series_simple.html', series=series, plants=plants, query=q, plant_id=plant_id)


@app.route('/admin/series', methods=['GET', 'POST'])
def admin_series():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    
    # Handle plant assignment
    plant_id = request.args.get('plant', '')
    return_to = request.args.get('return_to', 'admin_series')
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if name:
            # Check if series name already exists
            existing_series = conn.execute("SELECT * FROM series WHERE name = ?", (name,)).fetchone()
            if existing_series:
                flash(f'La serie "{name}" ya existe en el sistema.', 'warning')
            else:
                try:
                    conn.execute("INSERT INTO series (name, created_at) VALUES (?, ?)", (name, now_str()))
                    conn.commit()
                    flash('Serie agregada', 'success')
                except sqlite3.IntegrityError:
                    flash('Error al agregar la serie', 'danger')
        
        # Handle series assignment to plant
        if plant_id and request.form.get('assign_series'):
            print(f"=== DEBUG: Admin series assignment - plant_id={plant_id} ===")
            print(f"=== DEBUG: Form data: {dict(request.form)} ===")
            
            series_id = request.form.get('series_id')
            qty = request.form.get('qty', '0')
            
            print(f"=== DEBUG: series_id={series_id}, qty={qty} ===")
            
            if series_id and qty:
                try:
                    qty = int(qty)
                    print(f"=== DEBUG: Converted qty to int: {qty} ===")
                    if qty > 0:
                        # Get series info
                        series = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
                        print(f"=== DEBUG: Series found: {series is not None} ===")
                        if series:
                            # Calculate next available folio
                            last_assignment = conn.execute(
                                "SELECT MAX(end_folio) as last_folio FROM assignments WHERE series_id = ?",
                                (series_id,)
                            ).fetchone()
                            
                            print(f"=== DEBUG: Last assignment: {last_assignment} ===")
                            
                            if last_assignment and last_assignment['last_folio']:
                                start_folio = last_assignment['last_folio'] + 1
                            else:
                                start_folio = series['first_folio'] or 1
                            
                            end_folio = start_folio + qty - 1
                            
                            print(f"=== DEBUG: Calculated folios: {start_folio}-{end_folio} ===")
                            
                            # Create assignment
                            conn.execute(
                                "INSERT INTO assignments (plant_id, series_id, qty, start_folio, end_folio, assigned_by, assigned_at) VALUES (?,?,?,?,?,?,?)",
                                (plant_id, series_id, qty, start_folio, end_folio, session['user_id'], now_str())
                            )
                            
                            # Update series
                            conn.execute("UPDATE series SET remaining = remaining - ?, next_folio = ? WHERE id = ?", (qty, end_folio + 1, series_id))
                            
                            # Record movement
                            conn.execute(
                                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                                (session['user_id'], 'assign_series_to_plant', f"plant_id={plant_id}; series_id={series_id}; qty={qty}", now_str())
                            )
                            
                            conn.commit()
                            print(f"=== DEBUG: Assignment committed successfully ===")
                            
                            # Verify the assignment was saved
                            verification = conn.execute(
                                "SELECT * FROM assignments WHERE plant_id=? AND series_id=? AND qty=? ORDER BY id DESC LIMIT 1",
                                (plant_id, series_id, qty)
                            ).fetchone()
                            print(f"=== DEBUG: Verification - Assignment saved: {verification is not None} ===")
                            if verification:
                                print(f"=== DEBUG: Saved assignment ID: {verification['id']}, Folios: {verification['start_folio']}-{verification['end_folio']} ===")
                            
                            flash(f'Serie {series["name"]} asignada al plantel (qty={qty}, folios={start_folio}-{end_folio})', 'success')
                            
                            # Redirect back to the specified return URL
                            if return_to == 'admin_plants':
                                return redirect(url_for('admin_plants'))
                            else:
                                return redirect(url_for('admin_series'))
                        else:
                            print(f"=== DEBUG: Series not found for id={series_id} ===")
                            flash('Serie no encontrada', 'danger')
                    else:
                        print(f"=== DEBUG: Invalid qty: {qty} ===")
                        flash('Cantidad inválida', 'danger')
                except ValueError as e:
                    print(f"=== DEBUG: ValueError: {e} ===")
                    flash('Cantidad inválida', 'danger')
                except Exception as e:
                    print(f"=== DEBUG: Exception during assignment: {e} ===")
                    conn.rollback()
                    flash(f'Error al asignar: {e}', 'danger')
            else:
                print(f"=== DEBUG: Missing series_id or qty ===")
                flash('Serie y cantidad son requeridos', 'warning')
    
    # Get series with calculated remaining
    rows = conn.execute("""
        SELECT s.*,
               (s.total_added - COALESCE(SUM(a.qty), 0)) as calculated_remaining
        FROM series s
        LEFT JOIN assignments a ON s.id = a.series_id
        GROUP BY s.id
        ORDER BY s.name
    """).fetchall()
    
    # Get plant info if plant_id is provided
    plant = None
    if plant_id:
        plant = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id,)).fetchone()
    
    conn.close()
    
    # Render template with plant assignment context
    return render_template('admin/series.html', rows=rows, plant=plant, return_to=return_to)


@app.route('/supervisor/series')
def supervisor_series():
    guard = require_login()
    if guard:
        return guard
    # Check if user is supervisor or admin
    if session.get('role') not in ['supervisor', 'admin']:
        abort(403)
    
    conn = get_db()
    
    # Get series with calculated remaining (read-only for supervisor)
    rows = conn.execute("""
        SELECT s.*,
               (s.total_added - COALESCE(SUM(a.qty), 0)) as calculated_remaining
        FROM series s
        LEFT JOIN assignments a ON s.id = a.series_id
        GROUP BY s.id
        ORDER BY s.name
    """).fetchall()
    
    conn.close()
    
    # Render supervisor template (read-only)
    return render_template('supervisor/series.html', rows=rows)


@app.route('/admin/series/<int:series_id>/add-folios', methods=['POST'])
def admin_add_folios(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    try:
        qty = int(request.form.get('qty', '0'))
    except ValueError:
        qty = 0
    try:
        start = int(request.form.get('start', '0'))
    except ValueError:
        start = 0
    if qty <= 0:
        flash('Cantidad inválida', 'danger')
        return redirect(url_for('admin_series'))
    if start <= 0:
        flash('Folio inicial inválido', 'danger')
        return redirect(url_for('admin_series'))
    conn = get_db()
    series = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not series:
        conn.close()
        abort(404)
    end = start + qty - 1
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            # set next_folio on first load if there is no stock/history yet
            if (series['total_added'] or 0) == 0 and (series['remaining'] or 0) == 0:
                conn.execute("UPDATE series SET next_folio = ? WHERE id = ?", (start, series_id))
            # update totals and first/last folio bounds
            new_first = series['first_folio'] if series['first_folio'] is not None else start
            new_first = min(new_first, start)
            new_last = series['last_folio'] if series['last_folio'] is not None else end
            new_last = max(new_last, end)
            conn.execute(
                "UPDATE series SET total_added = total_added + ?, remaining = remaining + ?, first_folio = ?, last_folio = ? WHERE id=?",
                (qty, qty, new_first, new_last, series_id),
            )
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'add_folios', f"series_id={series_id}; qty={qty}; {start}-{end}", now_str()),
            )
            conn.commit()
            conn.close()
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        return redirect(url_for('admin_series'))
    flash(f"Folios agregados: {qty} ({start}-{end})", 'success')
    return redirect(url_for('admin_series'))


@app.route('/admin/series/<int:series_id>/delete', methods=['POST'])
def admin_delete_series(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    sort_key = request.args.get('sort', 'fecha')
    sort_dir = request.args.get('dir', 'desc').lower()
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'
    sort_map = {
        'plantel': 'p.name',
        'cct': 'p.cct',
        'cantidad': 'a.qty',
        'folio_inicial': 'a.start_folio',
        'folio_final': 'a.end_folio',
        'fecha': 'a.assigned_at',
    }
    order_col = sort_map.get(sort_key, 'a.assigned_at')
    order_clause = f"ORDER BY {order_col} {sort_dir.upper()}"

    conn = get_db()
    s = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not s:
        conn.close()
        abort(404)
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            # delete assignments referencing this series
            conn.execute("DELETE FROM assignments WHERE series_id=?", (series_id,))
            # log movement
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'delete_series', s['name'], now_str()),
            )
            # delete the series itself
            conn.execute("DELETE FROM series WHERE id=?", (series_id,))
            conn.commit()
            conn.close()
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        return redirect(url_for('admin_series'))
    # clear selected series if it was this one
    if session.get('selected_series_id') == series_id:
        session.pop('selected_series_id', None)
    flash('Serie eliminada', 'success')
    return redirect(url_for('admin_series'))


@app.route('/admin/series/<int:series_id>/remove-folios', methods=['POST'])
def admin_remove_folios(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    try:
        qty = int(request.form.get('qty', '0'))
    except ValueError:
        qty = 0
    if qty <= 0:
        flash('Cantidad inválida', 'danger')
        return redirect(url_for('admin_series'))
    conn = get_db()
    s = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not s:
        conn.close()
        abort(404)
    if (s['remaining'] or 0) < qty:
        conn.close()
        flash('No hay suficientes folios restantes para eliminar', 'warning')
        return redirect(url_for('admin_series'))
    # calcular nuevo last_folio reduciendo desde el final
    new_remaining = (s['remaining'] or 0) - qty
    new_last = s['last_folio']
    if new_last is not None:
        new_last = new_last - qty
        if new_remaining == 0 and s['first_folio'] is not None and new_last < s['first_folio']:
            new_last = None
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE series SET remaining = ?, last_folio = ? WHERE id = ?",
                (new_remaining, new_last, series_id),
            )
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'remove_folios', f"series_id={series_id}; qty={qty}", now_str()),
            )
            conn.commit()
            conn.close()
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        return redirect(url_for('admin_series'))
    flash(f"Folios eliminados: {qty}", 'success')
    return redirect(url_for('admin_series'))


@app.route('/admin/series/<int:series_id>/rename', methods=['POST'])
def admin_rename_series(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    name = request.form.get('name', '').strip()
    if not name:
        flash('Nombre requerido', 'danger')
        return redirect(url_for('admin_series'))
    conn = get_db()
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE series SET name=? WHERE id=?", (name, series_id))
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'rename_series', f"series_id={series_id}; name={name}", now_str()),
            )
            conn.commit()
            conn.close()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        flash('Ese nombre de serie ya existe', 'warning')
        return redirect(url_for('admin_series'))
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        return redirect(url_for('admin_series'))
    flash('Serie actualizada', 'success')
    return redirect(url_for('admin_series'))


@app.route('/admin/series/<int:series_id>/inline-update', methods=['POST'])
def admin_inline_update_series(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    # Debug: print received form data
    print(f"DEBUG: Received form data: {dict(request.form)}")
    try:
        new_total = int(request.form.get('total', '0'))
        new_first = int(request.form.get('first_folio', '0'))
    except ValueError:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Valores inválidos'}), 400
        flash('Valores inválidos', 'danger')
        return redirect(url_for('admin_series'))
    if new_total < 0 or new_first < 0:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Valores deben ser positivos'}), 400
        flash('Valores deben ser positivos', 'danger')
        return redirect(url_for('admin_series'))
    conn = get_db()
    s = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not s:
        conn.close()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Serie no encontrada'}), 404
        abort(404)
    # calculate new bounds
    new_last = new_first + new_total - 1
    if new_total == 0:
        new_last = None
    # check consistency with existing assignments
    assigned = conn.execute("SELECT COUNT(*) FROM assignments WHERE series_id=?", (series_id,)).fetchone()[0]
    if new_total < assigned:
        conn.close()
        error_msg = f'No se puede reducir Total por debajo de los folios ya asignados ({assigned})'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': error_msg}), 400
        flash(error_msg, 'warning')
        return redirect(url_for('admin_series'))
    # update series bounds and remaining
    new_remaining = new_total - assigned
    print(f"=== DEBUG: Series {series_id} update ===")
    print(f"=== DEBUG: old_total={s['total_added']}, new_total={new_total} ===")
    print(f"=== DEBUG: old_first={s['first_folio']}, new_first={new_first} ===")
    print(f"=== DEBUG: assigned={assigned}, new_remaining={new_remaining} ===")
    
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE series SET total_added=?, first_folio=?, last_folio=?, remaining=?, next_folio=? WHERE id=?",
                (new_total, new_first if new_total > 0 else None, new_last, new_remaining, new_first + assigned, series_id),
            )
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'inline_update_series', f"series_id={series_id}; total={new_total}; first_folio={new_first}", now_str()),
            )
            conn.commit()
            print(f"=== DEBUG: Series {series_id} updated successfully ===")
            conn.close()
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        error_msg = 'La base de datos está ocupada. Intenta nuevamente en unos segundos.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': error_msg}), 500
        flash(error_msg, 'warning')
        return redirect(url_for('admin_series'))
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'Serie actualizada'})
    flash('Serie actualizada', 'success')
    return redirect(url_for('admin_series'))


@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        role = request.form.get('role', 'standard')
        if username and role in ('standard', 'admin', 'supervisor'):
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                    (username, '', role, now_str()),
                )
                conn.commit()
                flash('Usuario agregado. Establecerá contraseña al iniciar por primera vez.', 'success')
            except sqlite3.IntegrityError as e:
                if 'UNIQUE constraint failed' in str(e):
                    flash('El usuario ya existe', 'warning')
                else:
                    flash(f'Error de integridad: {str(e)}', 'danger')
    users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY username").fetchall()
    conn.close()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/<int:user_id>/password', methods=['POST'])
def admin_set_user_password(user_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    p = request.form.get('password', '')
    if not p:
        flash('Contraseña requerida', 'danger')
        return redirect(url_for('admin_users'))
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(p), user_id))
    conn.execute(
        "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
        (session['user_id'], 'admin_set_password', f"user_id={user_id}", now_str()),
    )
    conn.commit()
    conn.close()
    flash('Contraseña actualizada', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    if user_id == session.get('user_id'):
        flash('No puedes eliminar tu propio usuario.', 'warning')
        return redirect(url_for('admin_users'))
    conn = get_db()
    user = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Usuario no encontrado', 'warning')
        return redirect(url_for('admin_users'))
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'admin_delete_user', f"user={user['username']}", now_str()),
            )
            conn.commit()
            conn.close()
        flash('Usuario eliminado', 'success')
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        flash('No se puede eliminar el usuario: tiene referencias (movimientos/asignaciones).', 'danger')
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
def admin_change_user_role(user_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    
    # No permitir cambiar el rol del propio usuario
    if user_id == session.get('user_id'):
        flash('No puedes cambiar tu propio rol.', 'warning')
        return redirect(url_for('admin_users'))
    
    new_role = request.form.get('role')
    if new_role not in ('standard', 'admin', 'supervisor'):
        flash('Rol inválido.', 'danger')
        return redirect(url_for('admin_users'))
    
    conn = get_db()
    user = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('Usuario no encontrado', 'warning')
        return redirect(url_for('admin_users'))
    
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'admin_change_role', f"user={user['username']}, old_role={user['role']}, new_role={new_role}", now_str()),
            )
            conn.commit()
            conn.close()
        flash(f'Rol de {user["username"]} cambiado a {new_role}', 'success')
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
    return redirect(url_for('admin_users'))


@app.route('/admin/plants', methods=['GET', 'POST'])
def admin_plants():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        cct = request.form.get('cct', '').strip()
        if name and cct:
            # Check if plant name already exists
            existing_plant = conn.execute("SELECT * FROM plants WHERE name = ?", (name,)).fetchone()
            if existing_plant:
                flash(f'El plantel "{name}" ya existe en el sistema.', 'warning')
            else:
                try:
                    conn.execute("INSERT INTO plants (name, cct) VALUES (?,?)", (name, cct))
                    conn.commit()
                    flash('Plantel agregado', 'success')
                    # Auto-unify duplicate plants
                    auto_unify_duplicate_plants()
                except sqlite3.IntegrityError:
                    flash(f'El CCT "{cct}" ya existe en el sistema. Por favor, use un CCT diferente.', 'warning')
    # Calculate folio statistics
    total_stats = {}
    total_stats['total_added'] = conn.execute("SELECT COALESCE(SUM(total_added), 0) FROM series").fetchone()[0]
    total_stats['total_assigned'] = conn.execute("SELECT COALESCE(SUM(qty), 0) FROM assignments").fetchone()[0]
    total_stats['total_remaining'] = total_stats['total_added'] - total_stats['total_assigned']
    
    # NOTE: Disabled automatic duplicate cleanup to preserve valid user assignments
    # Users may legitimately have multiple assignments to the same plant
    
    # Get sorting parameters
    sort = request.args.get('sort', 'name')
    order = request.args.get('order', 'asc')
    
    # Validate sort field
    valid_sort_fields = ['name', 'cct', 'assigned_folios', 'active_series']
    if sort not in valid_sort_fields:
        sort = 'name'
    
    # Validate order
    if order not in ['asc', 'desc']:
        order = 'asc'
    
    # Build ORDER BY clause
    order_clause = f"ORDER BY p.{sort} {order.upper()}"
    if sort == 'assigned_folios':
        order_clause = "ORDER BY assigned_folios " + order.upper()
    elif sort == 'active_series':
        order_clause = "ORDER BY active_series_count " + order.upper()
    
    rows = conn.execute(
        f"""
        SELECT p.*, 
               (SELECT COUNT(DISTINCT a.series_id) 
                FROM assignments a 
                WHERE a.plant_id = p.id
               ) as active_series_count,
               (SELECT GROUP_CONCAT(DISTINCT s.name) 
                FROM series s 
                WHERE s.id IN (
                    SELECT DISTINCT a.series_id 
                    FROM assignments a 
                    WHERE a.plant_id = p.id
                )
               ) as active_series,
               (SELECT COALESCE(SUM(a.qty), 0)
                FROM assignments a 
                WHERE a.plant_id = p.id
               ) as assigned_folios
        FROM plants p
        {order_clause}
        """
    ).fetchall()
    conn.close()
    return render_template('admin/plants.html', plants=rows, total_stats=total_stats, sort=sort, order=order, timestamp=int(time.time()))


# Old update endpoint removed - conflicts with inline-update
# @app.route('/admin/plants/<int:plant_id>/update', methods=['POST'])
# def admin_update_plant(plant_id: int):
#     guard = require_login()
#     if guard:
#         return guard
#     require_admin()
#     name = request.form.get('name', '').strip()
#     cct = request.form.get('cct', '').strip()
#     if not name or not cct:
#         flash('Nombre y CCT requeridos', 'danger')
#         return redirect(url_for('admin_plants'))
#     except sqlite3.OperationalError:
#         conn.rollback()
#         conn.close()
#         flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
#         return redirect(url_for('admin_plants'))
#     flash('Plantel actualizado', 'success')
#     return redirect(url_for('admin_plants'))


@app.route('/admin/plants/<int:plant_id>/delete', methods=['POST'])
def admin_delete_plant(plant_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    plant = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id,)).fetchone()
    if not plant:
        conn.close()
        flash('Plantel no encontrado', 'warning')
        return redirect(url_for('admin_plants'))
    
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            
            # Get all assignments for this plant to clean up
            assignments = conn.execute("SELECT * FROM assignments WHERE plant_id=?", (plant_id,)).fetchall()
            
            # Clean up all related records
            for assignment in assignments:
                # Delete movement records for this assignment
                conn.execute("DELETE FROM movements WHERE details LIKE ?", (f"%plant_id={plant_id}%",))
                
                # Update series remaining (add back the assigned quantity)
                conn.execute("UPDATE series SET remaining = remaining + ? WHERE id = ?", (assignment['qty'], assignment['series_id']))
            
            # Delete all assignments for this plant
            conn.execute("DELETE FROM assignments WHERE plant_id=?", (plant_id,))
            
            # Delete the plant
            conn.execute("DELETE FROM plants WHERE id=?", (plant_id,))
            
            # Log the complete cleanup
            conn.execute(
                "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                (session['user_id'], 'admin_delete_plant_complete', f"plant_id={plant_id}; plant_name={plant['name']}; cleaned_assignments={len(assignments)}", now_str()),
            )
            
            conn.commit()
            conn.close()
        flash(f'Plantel "{plant["name"]}" eliminado completamente. Se limpiaron {len(assignments)} asignaciones y registros relacionados.', 'success')
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        flash('Error al eliminar el plantel. Intente nuevamente.', 'danger')
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
    return redirect(url_for('admin_plants'))


@app.route('/test-cleanup', methods=['POST'])
def test_cleanup():
    """Test endpoint for cleanup without authentication"""
    print(f"=== DEBUG: Test cleanup endpoint called ===")
    
    conn = get_db()
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            
            # Find plants with multiple assignments
            duplicate_assignments = conn.execute("""
                SELECT plant_id, COUNT(*) as assignment_count
                FROM assignments 
                WHERE plant_id != 5
                GROUP BY plant_id 
                HAVING COUNT(*) > 1
            """).fetchall()
            
            print(f"=== DEBUG: Found {len(duplicate_assignments)} plants with duplicates ===")
            
            total_cleaned = 0
            
            for dup in duplicate_assignments:
                plant_id = dup['plant_id']
                assignment_count = dup['assignment_count']
                print(f"=== DEBUG: Processing plant {plant_id} with {assignment_count} assignments ===")
                
                # Get all assignments for this plant, ordered by creation date
                assignments = conn.execute("""
                    SELECT * FROM assignments 
                    WHERE plant_id = ? 
                    ORDER BY assigned_at ASC
                """, (plant_id,)).fetchall()
                
                # Keep only the first assignment, delete the rest
                assignments_to_keep = assignments[:1]  # Keep the first one
                assignments_to_delete = assignments[1:]  # Delete the rest
                
                print(f"=== DEBUG: Keeping {len(assignments_to_keep)}, deleting {len(assignments_to_delete)} ===")
                
                # Restore folios to series for assignments to delete
                for assignment in assignments_to_delete:
                    print(f"=== DEBUG: Restoring {assignment['qty']} folios from assignment {assignment['id']} ===")
                    conn.execute("UPDATE series SET remaining = remaining + ? WHERE id = ?", (assignment['qty'], assignment['series_id']))
                    
                    # Delete movement records for this assignment
                    conn.execute("DELETE FROM movements WHERE details LIKE ?", (f"%plant_id={plant_id}%",))
                    
                    # Delete the assignment
                    conn.execute("DELETE FROM assignments WHERE id = ?", (assignment['id'],))
                    total_cleaned += 1
                
                # Log the cleanup
                conn.execute(
                    "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                    (1, 'test_cleanup_duplicates', f"plant_id={plant_id}; deleted_assignments={len(assignments_to_delete)}; kept_assignments={len(assignments_to_keep)}", now_str()),
                )
            
            conn.commit()
            conn.close()
            
            print(f"=== DEBUG: Test cleanup completed. Total cleaned: {total_cleaned} ===")
            return f'Limpieza de prueba completada. Se eliminaron {total_cleaned} asignaciones duplicadas.'
    except Exception as e:
        print(f"=== DEBUG: Test cleanup error: {str(e)} ===")
        conn.rollback()
        conn.close()
        return f'Error en la limpieza de prueba: {str(e)}'


@app.route('/admin/cleanup-duplicates', methods=['POST'])
def admin_cleanup_duplicates():
    print(f"=== DEBUG: Cleanup endpoint called ===")
    guard = require_login()
    if guard:
        print(f"=== DEBUG: Login failed: {guard} ===")
        return guard
    require_admin()
    print(f"=== DEBUG: Admin access confirmed ===")
    
    conn = get_db()
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            
            # Find plants with multiple assignments
            duplicate_assignments = conn.execute("""
                SELECT plant_id, COUNT(*) as assignment_count
                FROM assignments 
                WHERE plant_id != 5
                GROUP BY plant_id 
                HAVING COUNT(*) > 1
            """).fetchall()
            
            print(f"=== DEBUG: Found {len(duplicate_assignments)} plants with duplicates ===")
            
            total_cleaned = 0
            
            for dup in duplicate_assignments:
                plant_id = dup['plant_id']
                assignment_count = dup['assignment_count']
                print(f"=== DEBUG: Processing plant {plant_id} with {assignment_count} assignments ===")
                
                # Get all assignments for this plant, ordered by creation date
                assignments = conn.execute("""
                    SELECT * FROM assignments 
                    WHERE plant_id = ? 
                    ORDER BY assigned_at ASC
                """, (plant_id,)).fetchall()
                
                # Keep only the first assignment, delete the rest
                assignments_to_keep = assignments[:1]  # Keep the first one
                assignments_to_delete = assignments[1:]  # Delete the rest
                
                print(f"=== DEBUG: Keeping {len(assignments_to_keep)}, deleting {len(assignments_to_delete)} ===")
                
                # Restore folios to series for assignments to delete
                for assignment in assignments_to_delete:
                    print(f"=== DEBUG: Restoring {assignment['qty']} folios from assignment {assignment['id']} ===")
                    conn.execute("UPDATE series SET remaining = remaining + ? WHERE id = ?", (assignment['qty'], assignment['series_id']))
                    
                    # Delete movement records for this assignment
                    conn.execute("DELETE FROM movements WHERE details LIKE ?", (f"%plant_id={plant_id}%",))
                    
                    # Delete the assignment
                    conn.execute("DELETE FROM assignments WHERE id = ?", (assignment['id'],))
                    total_cleaned += 1
                
                # Log the cleanup
                conn.execute(
                    "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                    (session['user_id'], 'manual_cleanup_duplicates', f"plant_id={plant_id}; deleted_assignments={len(assignments_to_delete)}; kept_assignments={len(assignments_to_keep)}", now_str()),
                )
            
            conn.commit()
            conn.close()
            
            print(f"=== DEBUG: Cleanup completed. Total cleaned: {total_cleaned} ===")
            flash(f'Limpieza completada. Se eliminaron {total_cleaned} asignaciones duplicadas.', 'success')
    except Exception as e:
        print(f"=== DEBUG: Cleanup error: {str(e)} ===")
        conn.rollback()
        conn.close()
        flash(f'Error en la limpieza: {str(e)}', 'danger')
    
    return redirect(url_for('admin_plants'))


@app.route('/test-simple')
def test_simple():
    return "TEST WORKING"


@app.route('/admin/assignments/<int:assignment_id>/update-qty', methods=['POST'])
def admin_update_assignment_qty(assignment_id: int):
    print(f"=== DEBUG: Update assignment qty route called for assignment_id={assignment_id} ===")
    guard = require_login()
    if guard:
        print(f"=== DEBUG: Login failed: {guard} ===")
        return guard
    require_admin()
    print(f"=== DEBUG: Admin access confirmed ===")
    
    try:
        data = request.get_json()
        print(f"=== DEBUG: Received data: {data} ===")
        new_qty = int(data.get('qty', 0))
        print(f"=== DEBUG: Parsed new_qty: {new_qty} ===")
        
        if new_qty < 0:
            print(f"=== DEBUG: Invalid quantity (negative) ===")
            return jsonify({'success': False, 'error': 'La cantidad debe ser positiva'})
        
        conn = get_db()
        
        # Get current assignment
        assignment = conn.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
        if not assignment:
            print(f"=== DEBUG: Assignment not found ===")
            conn.close()
            return jsonify({'success': False, 'error': 'Asignación no encontrada'})
        
        print(f"=== DEBUG: Found assignment: {dict(assignment)} ===")
        old_qty = assignment['qty']
        qty_diff = new_qty - old_qty
        print(f"=== DEBUG: old_qty={old_qty}, new_qty={new_qty}, qty_diff={qty_diff} ===")
        
        if qty_diff == 0:
            print(f"=== DEBUG: No change needed ===")
            conn.close()
            return jsonify({'success': True, 'message': 'Sin cambios'})
        
        # Check if series has enough folios available
        series = conn.execute("SELECT * FROM series WHERE id = ?", (assignment['series_id'],)).fetchone()
        if not series:
            print(f"=== DEBUG: Series not found ===")
            conn.close()
            return jsonify({'success': False, 'error': 'Serie no encontrada'})
        
        print(f"=== DEBUG: Series info: {dict(series)} ===")
        
        if new_qty > old_qty and series['remaining'] < qty_diff:
            print(f"=== DEBUG: Not enough folios. Available: {series['remaining']}, Requested: {qty_diff} ===")
            conn.close()
            return jsonify({'success': False, 'error': f'No hay suficientes folios disponibles. Disponibles: {series["remaining"]}, Solicitados: {qty_diff}'})
        
        try:
            with write_lock:
                conn.execute("BEGIN IMMEDIATE")
                print(f"=== DEBUG: Transaction started ===")
                
                # Update assignment quantity
                conn.execute("UPDATE assignments SET qty = ? WHERE id = ?", (new_qty, assignment_id))
                print(f"=== DEBUG: Updated assignment qty ===")
                
                # Update end_folio for current assignment
                new_end_folio = assignment['start_folio'] + new_qty - 1
                conn.execute("UPDATE assignments SET end_folio = ? WHERE id = ?", (new_end_folio, assignment_id))
                print(f"=== DEBUG: Updated end_folio to {new_end_folio} ===")
                
                # RECALCULATE ALL SUBSEQUENT ASSIGNMENTS FOLIOS
                print(f"=== DEBUG: Recalculating subsequent assignments ===")
                
                # Get all assignments for this series, ordered by start_folio
                all_assignments = conn.execute("""
                    SELECT * FROM assignments 
                    WHERE series_id = ? 
                    ORDER BY start_folio
                """, (assignment['series_id'],)).fetchall()
                
                # Find current assignment index
                current_index = -1
                for i, a in enumerate(all_assignments):
                    if a['id'] == assignment_id:
                        current_index = i
                        break
                
                if current_index >= 0 and current_index < len(all_assignments) - 1:
                    # Recalculate folios for all subsequent assignments
                    next_folio = new_end_folio + 1
                    
                    for i in range(current_index + 1, len(all_assignments)):
                        subsequent_assignment = all_assignments[i]
                        qty = subsequent_assignment['qty']
                        new_start = next_folio
                        new_end = new_start + qty - 1
                        
                        conn.execute("""
                            UPDATE assignments 
                            SET start_folio = ?, end_folio = ? 
                            WHERE id = ?
                        """, (new_start, new_end, subsequent_assignment['id']))
                        
                        print(f"=== DEBUG: Recalculated assignment {subsequent_assignment['id']}: {new_start}-{new_end} ===")
                        next_folio = new_end + 1
                
                # Update series remaining folios
                conn.execute("UPDATE series SET remaining = remaining - ? WHERE id = ?", (qty_diff, assignment['series_id']))
                print(f"=== DEBUG: Updated series remaining by {qty_diff} ===")
                
                # Log the change
                conn.execute(
                    "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                    (session['user_id'], 'update_assignment_qty', f"assignment_id={assignment_id}; old_qty={old_qty}; new_qty={new_qty}; recalc_subsequent=true", now_str())
                )
                print(f"=== DEBUG: Logged movement ===")
                
                conn.commit()
                print(f"=== DEBUG: Transaction committed ===")
            conn.close()
            
            print(f"=== DEBUG: Success! Returning response ===")
            return jsonify({'success': True, 'message': f'Cantidad actualizada de {old_qty} a {new_qty} y folios recalculados'})
            
        except sqlite3.OperationalError as e:
            print(f"=== DEBUG: Database error: {e} ===")
            conn.rollback()
            conn.close()
            return jsonify({'success': False, 'error': 'La base de datos está ocupada. Intenta nuevamente.'})
            
    except ValueError as e:
        print(f"=== DEBUG: ValueError: {e} ===")
        return jsonify({'success': False, 'error': 'Cantidad inválida'})
    except Exception as e:
        print(f"=== DEBUG: General error: {e} ===")
        import traceback
        print(f"=== DEBUG: Traceback: {traceback.format_exc()} ===")
        return jsonify({'success': False, 'error': f'Error: {str(e)}'})


@app.route('/admin/plants/<int:plant_id>/inline-update', methods=['POST'])
def admin_inline_update_plant(plant_id: int):
    print("!!! FUNCTION CALLED !!!")  # Simple test to verify logging
    print(f"=== DEBUG: Endpoint called for plant_id={plant_id} ===")
    print(f"=== DEBUG: Request method: {request.method} ===")
    print(f"=== DEBUG: Request headers: {dict(request.headers)} ===")
    print(f"=== DEBUG: Form data: {dict(request.form)} ===")
    
    try:
        # Bypass authentication temporarily for testing
        name = request.form.get('name', '').strip()
        cct = request.form.get('cct', '').strip()
        try:
            qty_total = int(request.form.get('qty_total', '0'))
        except ValueError:
            qty_total = 0
            
        print(f"=== DEBUG: Parsed data - name='{name}', cct='{cct}', qty_total={qty_total} ===")
            
        if not name or (cct is None or cct == ''):
            print(f"=== DEBUG: Validation failed - empty name/cct ===")
            return jsonify({'error': 'Nombre y CCT requeridos'}), 400
            
        if qty_total < 0:
            print(f"=== DEBUG: Validation failed - negative qty_total ===")
            return jsonify({'error': 'Folios asignados debe ser positivo'}), 400
            
        conn = get_db()
        try:
            with write_lock:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE plants SET name=?, cct=?, qty_total=? WHERE id=?", (name, cct, qty_total, plant_id))
                print(f"=== DEBUG: Plant {plant_id} updated in database ===")
                print(f"=== DEBUG: New values - name='{name}', cct='{cct}', qty_total={qty_total} ===")
                
                conn.execute(
                    "INSERT INTO movements (user_id, action, details, created_at) VALUES (?,?,?,?)",
                    (session['user_id'], 'inline_update_plant', f"plant_id={plant_id}; cct={cct}; qty_total={qty_total}", now_str()),
                )
                
                # DON'T delete assignments - just update the plant info
                # Assignments and series should remain intact
                print(f"=== DEBUG: Plant info updated without touching assignments ===")
                
                conn.commit()
            print(f"=== DEBUG: Database update successful ===")
                
        except sqlite3.IntegrityError as e:
            print(f"=== DEBUG: IntegrityError: {e} ===")
            if 'UNIQUE constraint failed: plants.cct' in str(e):
                return jsonify({'error': 'El CCT ya existe. Por favor usa otro valor.'}), 400
            else:
                return jsonify({'error': 'Error de integridad en la base de datos'}), 400
            
        except sqlite3.OperationalError as e:
            print(f"=== DEBUG: OperationalError: {e} ===")
            return jsonify({'error': 'La base de datos está ocupada. Intenta nuevamente en unos segundos.'}), 500
        finally:
            conn.close()
            print(f"=== DEBUG: Connection closed ===")
        
        print(f"=== DEBUG: Returning success JSON ===")
        return jsonify({'success': True, 'message': 'Plantel actualizado'})
        
    except Exception as e:
        print(f"=== DEBUG: Exception occurred: {e} ===")
        import traceback
        print(f"=== DEBUG: Traceback: {traceback.format_exc()} ===")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/admin/movements')
def admin_movements():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    dbrows = conn.execute(
        """
        SELECT m.*, u.username
        FROM movements m
        JOIN users u ON u.id = m.user_id
        ORDER BY m.created_at DESC
        LIMIT 200
        """
    ).fetchall()
    conn.close()
    # map actions to Spanish and simplify details
    action_map = {
        'set_password': 'Establecer contraseña (primer uso)',
        'admin_set_password': 'Admin: actualizar contraseña',
        'assign_folio': 'Asignar folios',
        'add_folios': 'Añadir folios',
        'delete_series': 'Eliminar serie',
        'assign_series_to_plant': 'Asignar serie a plantel',
        'cleanup_duplicate_assignments': 'Limpiar asignaciones duplicadas',
        'auto_unify_duplicate_plants': 'Unificar planteles duplicados',
        'add_plant': 'Agregar plantel',
        'admin_delete_plant_complete': 'Admin eliminó plantel',
        'inline_update_plant': 'Admin actualizó plantel',
        'manual_cleanup_duplicates': 'Admin limpió duplicados manualmente',
        'test_cleanup_duplicates': 'Admin limpió duplicados (prueba)',
        'update_assignment_qty': 'Admin actualizó cantidad de asignación',
    }
    rows = []
    for r in dbrows:
        details = r['details'] or ''
        action_es = action_map.get(r['action'], r['action'])
        details_fmt = details
        
        if r['action'] == 'add_folios':
            # expected format: series_id=..; qty=Q; start-end -> show only Q
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            details_fmt = f"Añadidos {parts.get('qty', '?')} folios"
        elif r['action'] == 'add_plant':
            # expected format: plant_id=ID; name=NAME; cct=CCT
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            name = parts.get('name', '?')
            cct = parts.get('cct', '?')
            details_fmt = f"Plantel '{name}' (CCT: {cct})"
        elif r['action'] == 'admin_delete_plant_complete':
            # expected format: plant_id=6; plant_name=C-151; cleaned_assignments=0
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            plant_name = parts.get('plant_name', '?')
            cleaned = parts.get('cleaned_assignments', '0')
            details_fmt = f"Plantel '{plant_name}' - {cleaned} asignaciones limpiadas"
        elif r['action'] == 'update_assignment_qty':
            # expected format: assignment_id=ID; old_qty=X; new_qty=Y
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            assignment_id = parts.get('assignment_id', '?')
            old_qty = parts.get('old_qty', '?')
            new_qty = parts.get('new_qty', '?')
            details_fmt = f"Asignación #{assignment_id}: {old_qty} → {new_qty} folios"
        elif r['action'] == 'delete_series':
            # expected: series_id=ID; name=NAME -> show only ID
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            details_fmt = f"Serie {parts.get('series_id', '?')} eliminada"
        elif r['action'] == 'assign_series_to_plant':
            # expected format: plant_id=ID; series_id=ID; qty=Q
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            plant_id = parts.get('plant_id', '?')
            series_id = parts.get('series_id', '?')
            qty = parts.get('qty', '?')
            
            # Get plant name instead of showing ID
            if plant_id != '?':
                try:
                    plant_conn = get_db()
                    plant_result = plant_conn.execute("SELECT name FROM plants WHERE id=?", (plant_id,)).fetchone()
                    plant_conn.close()
                    if plant_result:
                        plant_name = plant_result['name']
                    else:
                        plant_name = f"Plantel #{plant_id} (no encontrado)"
                except:
                    plant_name = f"Plantel #{plant_id}"
            else:
                plant_name = "Plantel desconocido"
            
            details_fmt = f"{plant_name} - Serie {series_id} ({qty} folios)"
        elif r['action'] == 'cleanup_duplicate_assignments':
            # expected format: plant_id=ID; deleted_assignments=N; kept_assignments=M
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            deleted = parts.get('deleted_assignments', '?')
            kept = parts.get('kept_assignments', '?')
            plant_id = parts.get('plant_id', '?')
            
            # Get plant name instead of showing ID
            if plant_id != '?':
                try:
                    plant_conn = get_db()
                    plant_result = plant_conn.execute("SELECT name FROM plants WHERE id=?", (plant_id,)).fetchone()
                    plant_conn.close()
                    if plant_result:
                        plant_name = plant_result['name']
                    else:
                        plant_name = f"Plantel #{plant_id} (no encontrado)"
                except:
                    plant_name = f"Plantel #{plant_id}"
            else:
                plant_name = "Plantel desconocido"
            
            details_fmt = f"{plant_name}: {deleted} eliminadas, {kept} mantenidas"
        elif r['action'] == 'auto_unify_duplicate_plants':
            # expected format: name=NAME; deleted_count=N; kept_id=M
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            name = parts.get('name', '?')
            deleted = parts.get('deleted_count', '?')
            details_fmt = f"Planteles '{name}': {deleted} duplicados eliminados"
        elif details.startswith('user_id='):
            # Handle generic user_id details - show username instead
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            user_id = parts.get('user_id', '?')
            # Get username from database
            try:
                user_conn = get_db()
                user_result = user_conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
                user_conn.close()
                if user_result:
                    details_fmt = f"Usuario: {user_result['username']}"
                else:
                    details_fmt = f"Usuario ID: {user_id} (no encontrado)"
            except:
                details_fmt = f"Usuario ID: {user_id}"
        elif '=' in details and ';' in details:
            # Handle generic key=value pairs
            parts = {kv.split('=')[0].strip(): kv.split('=')[1].strip() for kv in details.split(';') if '=' in kv}
            # Format as readable key: value pairs
            formatted_parts = []
            for key, value in parts.items():
                if key == 'user_id':
                    # Get username from database
                    try:
                        user_conn = get_db()
                        user_result = user_conn.execute("SELECT username FROM users WHERE id=?", (value,)).fetchone()
                        user_conn.close()
                        if user_result:
                            formatted_parts.append(f"Usuario: {user_result['username']}")
                        else:
                            formatted_parts.append(f"Usuario ID: {value} (no encontrado)")
                    except:
                        formatted_parts.append(f"Usuario ID: {value}")
                elif key == 'plant_id':
                    formatted_parts.append(f"Plantel: {value}")
                elif key == 'series_id':
                    formatted_parts.append(f"Serie: {value}")
                elif key == 'qty':
                    formatted_parts.append(f"Cantidad: {value}")
                else:
                    formatted_parts.append(f"{key}: {value}")
            details_fmt = " | ".join(formatted_parts)
        
        # Format date properly
        if r['created_at']:
            try:
                if hasattr(r['created_at'], 'strftime'):
                    # It's a datetime object
                    formatted_date = r['created_at'].strftime('%d-%m-%Y %H:%M:%S')
                else:
                    # It's a string, parse it first
                    from datetime import datetime
                    # Try different date formats
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
                        try:
                            dt = datetime.strptime(str(r['created_at']), fmt)
                            formatted_date = dt.strftime('%d-%m-%Y %H:%M:%S')
                            break
                        except ValueError:
                            continue
                    else:
                        # If no format matches, use original
                        formatted_date = str(r['created_at'])
            except:
                formatted_date = str(r['created_at'])
        else:
            formatted_date = ''
        
        rows.append({
            'created_at': formatted_date,
            'username': r['username'],
            'action_es': action_es,
            'details_fmt': details_fmt,
        })
    return render_template('admin/movements.html', rows=rows)


@app.route('/admin/movements/clear', methods=['POST'])
def admin_movements_clear():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    conn = get_db()
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM movements")
            conn.commit()
            conn.close()
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        flash('La base de datos está ocupada. Intenta nuevamente en unos segundos.', 'warning')
        return redirect(url_for('admin_movements'))
    flash('Todos los movimientos han sido eliminados', 'success')
    return redirect(url_for('admin_movements'))


def recalculate_assignment_folios(assignment_id: int):
    """Recalculate start_folio and end_folio for an assignment based on series"""
    print(f"=== RECALCULATE FOLIOS: Function called with assignment_id={assignment_id} ===")
    
    conn = get_db()
    
    # Get assignment data
    assignment = conn.execute("SELECT * FROM assignments WHERE id=?", (assignment_id,)).fetchone()
    print(f"=== RECALCULATE FOLIOS: Assignment data: {dict(assignment) if assignment else 'None'} ===")
    
    if not assignment:
        conn.close()
        print(f"=== RECALCULATE FOLIOS: Assignment not found ===")
        return False
    
    # Get series data to find next available folio
    series = conn.execute("SELECT * FROM series WHERE id=?", (assignment['series_id'],)).fetchone()
    print(f"=== RECALCULATE FOLIOS: Series data: {dict(series) if series else 'None'} ===")
    
    if not series:
        conn.close()
        print(f"=== RECALCULATE FOLIOS: Series not found ===")
        return False
    
    # Calculate correct start_folio (next available from series)
    # Find all assignments for this series, ordered by start_folio
    all_assignments = conn.execute(
        "SELECT * FROM assignments WHERE series_id=? ORDER BY start_folio",
        (assignment['series_id'],)
    ).fetchall()
    
    print(f"=== RECALCULATE FOLIOS: All assignments for series {assignment['series_id']}: ===")
    for i, aa in enumerate(all_assignments):
        print(f"=== RECALCULATE FOLIOS: Assignment {i}: id={aa['id']}, start_folio={aa['start_folio']}, end_folio={aa['end_folio']}, qty={aa['qty']} ===")
    
    # Calculate correct start_folio based on series next_folio and previous assignments
    correct_start_folio = series['next_folio'] or 1
    
    # Find the position of current assignment in the ordered list
    current_position = 0
    for i, aa in enumerate(all_assignments):
        if aa['id'] == assignment_id:
            current_position = i
            break
    
    # Calculate start_folio based on previous assignments
    if current_position > 0:
        # Start after the previous assignment ends
        correct_start_folio = all_assignments[current_position - 1]['end_folio'] + 1
    
    correct_end_folio = correct_start_folio + assignment['qty'] - 1
    
    print(f"=== RECALCULATE FOLIOS: Assignment {assignment_id} ===")
    print(f"=== RECALCULATE FOLIOS: Current start={assignment['start_folio']}, end={assignment['end_folio']} ===")
    print(f"=== RECALCULATE FOLIOS: Correct start={correct_start_folio}, end={correct_end_folio} ===")
    
    # Update assignment
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute(
                "UPDATE assignments SET start_folio=?, end_folio=? WHERE id=?",
                (correct_start_folio, correct_end_folio, assignment_id)
            )
            print(f"=== RECALCULATE FOLIOS: SQL UPDATE executed, rowcount={result.rowcount} ===")
            conn.commit()
            conn.close()
        print(f"=== RECALCULATE FOLIOS: Updated assignment {assignment_id} ===")
        return True
    except sqlite3.OperationalError as e:
        conn.rollback()
        conn.close()
        print(f"=== RECALCULATE FOLIOS: Error updating assignment {assignment_id}: {e} ===")
        return False


@app.route('/admin/assignments/<int:assignment_id>/recalculate', methods=['POST'])
def admin_recalculate_assignment(assignment_id: int):
    print(f"=== RECALCULATE ROUTE: Called with assignment_id={assignment_id} ===")
    print(f"=== RECALCULATE ROUTE: Request method: {request.method} ===")
    print(f"=== RECALCULATE ROUTE: Form data: {dict(request.form)} ===")
    
    guard = require_login()
    if guard:
        print(f"=== RECALCULATE ROUTE: Guard failed ===")
        return guard
    require_admin()
    
    print(f"=== RECALCULATE ROUTE: Authentication passed ===")
    
    if recalculate_assignment_folios(assignment_id):
        flash('Folios de asignación recalculados correctamente', 'success')
        print(f"=== RECALCULATE ROUTE: Success ===")
    else:
        flash('Error al recalcular folios de asignación', 'danger')
        print(f"=== RECALCULATE ROUTE: Failed ===")
    
    # Get plant_id to redirect back
    conn = get_db()
    assignment = conn.execute("SELECT plant_id FROM assignments WHERE id=?", (assignment_id,)).fetchone()
    conn.close()
    
    print(f"=== RECALCULATE ROUTE: Redirecting to plant_id={assignment['plant_id'] if assignment else 'admin_plants'} ===")
    
    if assignment:
        return redirect(url_for('plant_detail', plant_id=assignment['plant_id']))
    else:
        return redirect(url_for('admin_plants'))


def cleanup_zero_assignments():
    """Remove assignments with qty=0 to fix calculation inconsistencies"""
    conn = get_db()
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            
            # First, show ALL assignments for debugging
            all_assignments = conn.execute("SELECT * FROM assignments").fetchall()
            print(f"=== CLEANUP: ALL assignments in database ({len(all_assignments)} total) ===")
            for a in all_assignments:
                print(f"=== CLEANUP: Assignment {a['id']}: plant_id={a['plant_id']}, series_id={a['series_id']}, qty={a['qty']}, start={a['start_folio']}, end={a['end_folio']} ===")
            
            # Find and delete assignments with qty=0
            zero_assignments = conn.execute("SELECT id, plant_id, series_id FROM assignments WHERE qty=0").fetchall()
            print(f"=== CLEANUP: Found {len(zero_assignments)} assignments with qty=0 ===")
            
            for assignment in zero_assignments:
                print(f"=== CLEANUP: Deleting assignment {assignment['id']} (plant_id={assignment['plant_id']}, series_id={assignment['series_id']}) ===")
                conn.execute("DELETE FROM assignments WHERE id=?", (assignment['id'],))
            
            # Show assignments after cleanup
            remaining_assignments = conn.execute("SELECT * FROM assignments").fetchall()
            print(f"=== CLEANUP: Remaining assignments ({len(remaining_assignments)} total) ===")
            for a in remaining_assignments:
                print(f"=== CLEANUP: Remaining {a['id']}: plant_id={a['plant_id']}, series_id={a['series_id']}, qty={a['qty']} ===")
            
            conn.commit()
            conn.close()
        print(f"=== CLEANUP: Deleted {len(zero_assignments)} zero-quantity assignments ===")
        return len(zero_assignments)
    except sqlite3.OperationalError as e:
        conn.rollback()
        conn.close()
        print(f"=== CLEANUP: Error: {e} ===")
        return 0


def recalculate_series_totals(series_id: int):
    """Recalculate series totals based on actual assignments"""
    conn = get_db()
    
    # Get series data
    series = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not series:
        conn.close()
        return False
    
    # Calculate actual assigned total from assignments
    assignments = conn.execute("SELECT SUM(qty) as total_assigned FROM assignments WHERE series_id=?", (series_id,)).fetchone()
    actual_assigned = assignments['total_assigned'] or 0
    
    # Calculate correct remaining
    correct_remaining = (series['total_added'] or 0) - actual_assigned
    
    print(f"=== RECALCULATE: Series {series_id} ===")
    print(f"=== RECALCULATE: total_added={series['total_added']}, actual_assigned={actual_assigned}, correct_remaining={correct_remaining} ===")
    print(f"=== RECALCULATE: Current remaining={series['remaining']} (WRONG) ===")
    
    # Calculate correct next_folio based on highest assigned folio
    highest_folio_result = conn.execute("SELECT MAX(end_folio) FROM assignments").fetchone()
    correct_next_folio = (highest_folio_result[0] if highest_folio_result[0] else 0) + 1
    
    print(f"=== RECALCULATE SERIES: Series {series_id} ===")
    print(f"=== RECALCULATE SERIES: Current next_folio={series['next_folio']} ===")
    print(f"=== RECALCULATE SERIES: Highest assigned folio={highest_folio_result[0]} ===")
    print(f"=== RECALCULATE SERIES: Correct next_folio={correct_next_folio} ===")
    
    # Update series with correct values
    try:
        with write_lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE series SET remaining=?, next_folio=? WHERE id=?", (correct_remaining, correct_next_folio, series_id))
            conn.commit()
            conn.close()
        print(f"=== RECALCULATE SERIES: Updated series {series_id} remaining to {correct_remaining}, next_folio to {correct_next_folio} ===")
        return True
    except sqlite3.OperationalError:
        conn.rollback()
        conn.close()
        print(f"=== RECALCULATE: Error updating series {series_id} ===")
        return False


@app.route('/admin/cleanup-zero-assignments', methods=['POST'])
def admin_cleanup_zero_assignments():
    guard = require_login()
    if guard:
        return guard
    require_admin()
    
    deleted_count = cleanup_zero_assignments()
    if deleted_count > 0:
        flash(f'Se eliminaron {deleted_count} asignaciones con cantidad cero', 'success')
    else:
        flash('No se encontraron asignaciones con cantidad cero', 'info')
    
    return redirect(url_for('admin_series'))


@app.route('/admin/series/<int:series_id>/recalculate', methods=['POST'])
def admin_recalculate_series(series_id: int):
    guard = require_login()
    if guard:
        return guard
    require_admin()
    
    if recalculate_series_totals(series_id):
        flash('Totales de serie recalculados correctamente', 'success')
    else:
        flash('Error al recalcular totales de serie', 'danger')
    
    return redirect(url_for('series_detail', series_id=series_id))


# ---------- folio list per series ----------
@app.route('/series/<int:series_id>/detalle')
def series_detail(series_id: int):
    guard = require_login()
    if guard:
        return guard
    
    # Get plant_id parameter if provided
    plant_id = request.args.get('plant_id', type=int)
    
    # sorting params
    sort_key = request.args.get('sort', 'fecha')
    sort_dir = request.args.get('dir', 'desc').lower()
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'desc'
    sort_map = {
        'plantel': 'p.name',
        'cct': 'p.cct',
        'cantidad': 'a.qty',
        'folio_inicial': 'a.start_folio',
        'folio_final': 'a.end_folio',
        'fecha': 'a.assigned_at',
    }
    order_col = sort_map.get(sort_key, 'a.assigned_at')
    order_clause = f"ORDER BY {order_col} {sort_dir.upper()}"

    conn = get_db()
    s = conn.execute("SELECT * FROM series WHERE id=?", (series_id,)).fetchone()
    if not s:
        conn.close()
        abort(404)
    
    print(f"=== DEBUG: Loading series {series_id} detail ===")
    print(f"=== DEBUG: Plant filter: {plant_id} ===")
    print(f"=== DEBUG: Series data: name={s['name']}, total_added={s['total_added']}, remaining={s['remaining']}, first_folio={s['first_folio']}, last_folio={s['last_folio']} ===")
    
    # Filter assignments by plant_id if provided
    if plant_id:
        assigns = conn.execute(
            f"""
            SELECT a.*, p.name as plant_name, p.cct as plant_cct
            FROM assignments a
            JOIN plants p ON p.id = a.plant_id
            WHERE a.series_id = ? AND a.plant_id = ? AND a.qty > 0
            {order_clause}
            """,
            (series_id, plant_id),
        ).fetchall()
        print(f"=== DEBUG: Filtered assignments for plant {plant_id}: {len(assigns)} ===")
    else:
        assigns = conn.execute(
            f"""
            SELECT a.*, p.name as plant_name, p.cct as plant_cct
            FROM assignments a
            JOIN plants p ON p.id = a.plant_id
            WHERE a.series_id = ? AND a.qty > 0
            {order_clause}
            """,
            (series_id,),
        ).fetchall()
        print(f"=== DEBUG: All assignments for series {series_id}: {len(assigns)} ===")
    
    # Get plant data if filtered by plant
    plant_data = None
    plant_folio_start = None
    plant_folio_end = None
    if plant_id:
        plant_data = conn.execute("SELECT * FROM plants WHERE id=?", (plant_id,)).fetchone()
        print(f"=== DEBUG: Plant data for plant_id={plant_id}: {dict(plant_data) if plant_data else 'None'} ===")
        
        # Calculate plant folio range from filtered assignments
        if assigns:
            plant_folio_start = min(a['start_folio'] for a in assigns)
            plant_folio_end = max(a['end_folio'] for a in assigns)
            print(f"=== DEBUG: Plant folio range: {plant_folio_start} - {plant_folio_end} ===")
    
    # Calculate assigned_docs based on filtered assignments
    assigned_docs = sum(a['qty'] for a in assigns) if assigns else 0
    print(f"=== DEBUG: assigned_docs={assigned_docs} ===")
    
    # Add cache-busting timestamp
    print(f"=== DEBUG: Rendering series detail with timestamp={int(time.time())} ===")
    return render_template('series_detail.html', series=s, assigns=assigns, assigned_docs=assigned_docs, plant_data=plant_data, plant_folio_start=plant_folio_start, plant_folio_end=plant_folio_end, plant_qty_total=plant_data['qty_total'] if plant_data else None, sort_key=sort_key, sort_dir=sort_dir, timestamp=int(time.time()))


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
