from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS
from datetime import timedelta, datetime, timezone
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_jwt_extended.utils import decode_token
from passlib.hash import pbkdf2_sha256
import MySQLdb
import xml.etree.ElementTree as ET
import redis
import os

# =========================
# App & Config
# =========================
app = Flask(__name__)

# JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
jwt = JWTManager(app)

# CORS (abierto para pruebas)
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type", "Authorization"],
    supports_credentials=False,
    send_wildcard=True,
    max_age=86400,
)

# MariaDB
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "libro_user")
DB_PASS = os.getenv("DB_PASS", "666")
DB_NAME = os.getenv("DB_NAME", "Libros")
DB_CHARSET = "utf8"

def get_db():
    return MySQLdb.connect(
        host=DB_HOST, user=DB_USER, passwd=DB_PASS,
        db=DB_NAME, charset=DB_CHARSET
    )

# Redis
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB   = int(os.getenv("REDIS_DB", "0"))
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

# =========================
# Helpers: JWT + Redis
# =========================
def _now_ts():
    return int(datetime.now(timezone.utc).timestamp())

def _ttl_from_exp(exp_unix: int) -> int:
    ttl = exp_unix - _now_ts()
    return ttl if ttl > 0 else 1

def _allow_key(token_type: str, jti: str) -> str:
    return f"allow:{token_type}:{jti}"

def _block_key(jti: str) -> str:
    return f"block:{jti}"

def store_in_allowlist(encoded_token: str, token_type: str, username: str):
    decoded = decode_token(encoded_token)
    jti = decoded['jti']
    exp = decoded['exp']
    ttl = _ttl_from_exp(exp)
    key = _allow_key(token_type, jti)
    r.hset(key, mapping={"username": username, "type": token_type, "exp": str(exp)})
    r.expire(key, ttl)
    return jti

def is_in_allowlist(jti: str) -> bool:
    # válido si existe en allowlist (access o refresh)
    return r.exists(_allow_key("access", jti)) == 1 or r.exists(_allow_key("refresh", jti)) == 1

def is_revoked(jti: str) -> bool:
    return r.exists(_block_key(jti)) == 1

def revoke_jti(jti: str, exp: int):
    ttl = _ttl_from_exp(exp)
    r.setex(_block_key(jti), ttl, "1")
    # opcional: limpiar allowlist
    r.delete(_allow_key("access", jti))
    r.delete(_allow_key("refresh", jti))

@jwt.token_in_blocklist_loader
def token_check_revoked(jwt_header, jwt_payload):
    # Política estricta: si NO está en allowlist -> inválido
    jti = jwt_payload["jti"]
    return is_revoked(jti) or (not is_in_allowlist(jti))

# Preflight (CORS)
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        resp = make_response()
        resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
        return resp, 200

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return resp

# =========================
# XML helpers
# =========================
def books_to_xml(rows):
    catalog = ET.Element('catalog')
    for b in rows:
        book_elem = ET.Element('book', isbn=b.get('isbn', ''))
        title = ET.SubElement(book_elem, 'title'); title.text = b.get('titulo', 'Desconocido')
        # soporta múltiples autores (si hacen join con GROUP_CONCAT)
        authors_field = b.get('authors') or b.get('autor') or ''
        authors = authors_field.split(',') if authors_field else []
        if not authors:
            ET.SubElement(book_elem, 'author').text = 'Desconocido'
        else:
            for a in authors:
                ET.SubElement(book_elem, 'author').text = a.strip()

        year = ET.SubElement(book_elem, 'year'); year.text = str(b.get('anio_publicacion', '0'))
        genre = ET.SubElement(book_elem, 'genre'); genre.text = b.get('genre_name', b.get('genero', 'Desconocido'))
        price = ET.SubElement(book_elem, 'price'); price.text = str(b.get('price', '0.0'))
        stock = ET.SubElement(book_elem, 'stock'); stock.text = str(b.get('stock', '0'))
        fmt = ET.SubElement(book_elem, 'format'); fmt.text = b.get('formato', 'Desconocido')
        catalog.append(book_elem)
    return ET.tostring(catalog, encoding='utf-8', xml_declaration=True)

# =========================
# AUTH
# =========================

# POST /auth/register
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username'); password = data.get('password')
    if not username or not password:
        return jsonify({"msg": "username y password son requeridos"}), 400
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT 1 FROM Users WHERE username=%s", (username,))
        if cur.fetchone():
            return jsonify({"msg": "Usuario ya existe"}), 409
        cur.execute("INSERT INTO Users (username, password_hash) VALUES (%s,%s)",
                    (username, pbkdf2_sha256.hash(password)))
        conn.commit()
        return jsonify({"msg": "Usuario creado"}), 201
    except Exception as e:
        return jsonify({"msg": "DB error", "error": str(e)}), 500
    finally:
        try: conn.close()
        except: pass

# POST /auth/login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username'); password = data.get('password')
    if not username or not password:
        return jsonify({"msg": "username y password son requeridos"}), 400
    try:
        conn = get_db(); cur = conn.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT password_hash FROM Users WHERE username=%s", (username,))
        row = cur.fetchone()
        if not row or not pbkdf2_sha256.verify(password, row['password_hash']):
            return jsonify({"msg": "Credenciales inválidas"}), 401

        access  = create_access_token(identity=username)
        refresh = create_refresh_token(identity=username)
        jti_a   = store_in_allowlist(access,  "access",  username)
        jti_r   = store_in_allowlist(refresh, "refresh", username)
        return jsonify(access_token=access, refresh_token=refresh,
                       jti_access=jti_a, jti_refresh=jti_r), 200
    except Exception as e:
        return jsonify({"msg":"DB/Auth error","error":str(e)}), 500
    finally:
        try: conn.close()
        except: pass

# POST /auth/refresh
@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    user = get_jwt_identity()
    new_access = create_access_token(identity=user)
    jti_a = store_in_allowlist(new_access, "access", user)
    return jsonify(access_token=new_access, jti_access=jti_a), 200

# POST /auth/logout (revoca el token access actual)
@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    claims = get_jwt()
    revoke_jti(claims['jti'], claims['exp'])
    return jsonify({"msg":"logout ok","revoked_jti":claims['jti']}), 200

# =========================
# BOOKS (TODOS protegidos)
# =========================

# GET /api/books → XML con todos
@app.route('/api/books', methods=['GET'])
@jwt_required()
def books_all():
    try:
        conn = get_db(); cur = conn.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT l.isbn, l.titulo, l.anio_publicacion, l.price, l.stock, l.formato,
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors,
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            GROUP BY l.isbn
        """)
        rows = cur.fetchall()
        xml = books_to_xml(rows)
        return Response(xml, mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# GET /api/books/ISBN → ?isbn=...
@app.route('/api/books/ISBN', methods=['GET'], strict_slashes=False)
@jwt_required()
def books_by_isbn():
    isbn = request.args.get('isbn', '').strip()
    if not isbn:
        return Response("<?xml version='1.0'?><error>isbn requerido</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT l.isbn, l.titulo, l.anio_publicacion, l.price, l.stock, l.formato,
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors,
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE l.isbn = %s
            GROUP BY l.isbn
        """, (isbn,))
        rows = cur.fetchall()
        xml = books_to_xml(rows)
        return Response(xml, mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# GET /api/books/format/ → ?format=...
@app.route('/api/books/format/', methods=['GET'], strict_slashes=False)
@jwt_required()
def books_by_format():
    fmt = request.args.get('format', '').strip()
    if not fmt:
        return Response("<?xml version='1.0'?><error>format requerido</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT l.isbn, l.titulo, l.anio_publicacion, l.price, l.stock, l.formato,
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors,
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE l.formato = %s
            GROUP BY l.isbn
        """, (fmt,))
        rows = cur.fetchall()
        xml = books_to_xml(rows)
        return Response(xml, mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# GET /api/books/autor/ → ?name=...
@app.route('/api/books/autor/', methods=['GET'], strict_slashes=False)
@jwt_required()
def books_by_autor():
    name = request.args.get('name', '').strip()
    if not name:
        return Response("<?xml version='1.0'?><error>name requerido</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("""
            SELECT l.isbn, l.titulo, l.anio_publicacion, l.price, l.stock, l.formato,
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors,
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE a.nombre LIKE %s
            GROUP BY l.isbn
        """, (f"%{name}%",))
        rows = cur.fetchall()
        xml = books_to_xml(rows)
        return Response(xml, mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# POST /api/books/create
@app.route('/api/books/create', methods=['POST'], strict_slashes=False)
@jwt_required()
def book_create():
    data = request.get_json(silent=True) or {}
    req = ['isbn','titulo','id_autor','id_categoria','id_editorial',
           'anio_publicacion','price','stock','formato']
    if any(k not in data for k in req):
        return Response("<?xml version='1.0'?><error>faltan campos</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO Libro (isbn, titulo, id_autor, id_categoria, id_editorial,
                               anio_publicacion, price, stock, formato)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (data['isbn'], data['titulo'], data['id_autor'], data['id_categoria'],
              data['id_editorial'], data['anio_publicacion'], data['price'],
              data['stock'], data['formato']))
        conn.commit()
        return Response("<?xml version='1.0'?><ok>inserted</ok>",
                        mimetype='application/xml', status=201)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# PUT /api/books/update
@app.route('/api/books/update', methods=['PUT'], strict_slashes=False)
@jwt_required()
def book_update():
    data = request.get_json(silent=True) or {}
    isbn = data.get('isbn')
    if not isbn:
        return Response("<?xml version='1.0'?><error>isbn requerido</error>",
                        mimetype='application/xml', status=400)
    fields = {k:v for k,v in data.items() if k in [
        'titulo','id_autor','id_categoria','id_editorial',
        'anio_publicacion','price','stock','formato'
    ] and v not in (None, '')}
    if not fields:
        return Response("<?xml version='1.0'?><error>nada que actualizar</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor()
        sets = ", ".join([f"{k}=%s" for k in fields.keys()])
        params = list(fields.values()) + [isbn]
        cur.execute(f"UPDATE Libro SET {sets} WHERE isbn=%s", params)
        conn.commit()
        return Response("<?xml version='1.0'?><ok>updated</ok>",
                        mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# DELETE /api/books/delete → ?isbn=...
@app.route('/api/books/delete', methods=['DELETE'], strict_slashes=False)
@jwt_required()
def book_delete():
    isbn = request.args.get('isbn','').strip()
    if not isbn:
        return Response("<?xml version='1.0'?><error>isbn requerido</error>",
                        mimetype='application/xml', status=400)
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM Libro WHERE isbn=%s", (isbn,))
        conn.commit()
        return Response("<?xml version='1.0'?><ok>deleted</ok>",
                        mimetype='application/xml', status=200)
    except Exception as e:
        err = f"<?xml version='1.0'?><error>{str(e)}</error>"
        return Response(err, mimetype='application/xml', status=500)
    finally:
        try: conn.close()
        except: pass

# Salud
@app.route('/ping', methods=['GET'])
def ping():
    return jsonify(msg="pong"), 200

if __name__ == '__main__':
    # Escucha en todas las interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)

