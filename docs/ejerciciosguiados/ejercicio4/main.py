from flask import Flask, request, Response, jsonify
import MySQLdb
import xml.etree.ElementTree as ET
from datetime import timedelta
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from passlib.hash import pbkdf2_sha256
from flask_cors import CORS # 1. Importa CORS

# ---------- Flask & JWT Configuration ----------
app = Flask(__name__)
CORS(app) # 2. Habilita CORS para toda la aplicación

# IMPORTANT: In a production environment, use environment variables to store this key.
app.config['JWT_SECRET_KEY'] = 'your-super-secret-key-here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# ----------------------------
# Database Connection
# ----------------------------
def get_db_connection():
    return MySQLdb.connect(
        host="localhost",
        user="libro_user",
        passwd="666",
        db="Libros",
        charset='utf8'
    )

# ----------------------------
# XML Conversion Function
# ----------------------------
def books_to_xml(books):
    catalog = ET.Element('catalog')
    for book in books:
        book_elem = ET.Element('book', isbn=book.get('isbn', ''))
        # Título
        title = ET.SubElement(book_elem, 'title')
        title.text = book.get('titulo', 'Desconocido')
        # Autores
        authors_field = book.get('authors', '')
        authors = authors_field.split(',') if authors_field else ['Desconocido']
        for author_name in authors:
            author = ET.SubElement(book_elem, 'author')
            author.text = author_name.strip()
        # Año
        year = ET.SubElement(book_elem, 'year')
        year.text = str(book.get('anio_publicacion', '0'))
        # Género
        genre = ET.SubElement(book_elem, 'genre')
        genre.text = book.get('genre_name', 'Desconocido')
        # Precio
        price = ET.SubElement(book_elem, 'price')
        price.text = str(book.get('price', '0.0'))
        # Stock
        stock = ET.SubElement(book_elem, 'stock')
        stock.text = str(book.get('stock', '0'))
        # Formato
        fmt = ET.SubElement(book_elem, 'format')
        fmt.text = book.get('formato', 'Desconocido')
        catalog.append(book_elem)
    xml_str = ET.tostring(catalog, encoding='utf-8', xml_declaration=True)
    return xml_str

# ----------------------------
# New Endpoints for User Authentication
# ----------------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"msg": "User already exists"}), 409

        # Hash password and insert into DB
        password_hash = pbkdf2_sha256.hash(password)
        cursor.execute("INSERT INTO Users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()

        return jsonify({"msg": "User created successfully"}), 201

    except Exception as e:
        return jsonify({"msg": "An error occurred", "error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # Retrieve user and check password
        cursor.execute("SELECT password_hash FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and pbkdf2_sha256.verify(password, user['password_hash']):
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)
            return jsonify(access_token=access_token, refresh_token=refresh_token), 200
        else:
            return jsonify({"msg": "Bad username or password"}), 401
    except Exception as e:
        return jsonify({"msg": "An error occurred", "error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token), 200

# ----------------------------
# Existing Endpoints (now protected)
# ----------------------------

@app.route('/api/books', methods=['GET'])
@jwt_required()
def get_books():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT l.*, 
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors, 
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            GROUP BY l.isbn
        """)
        books = cursor.fetchall()
        conn.close()
        xml = books_to_xml(books)
        return Response(xml, mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/<isbn>', methods=['GET'])
@jwt_required()
def get_book_by_isbn(isbn):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT l.*, 
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors, 
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE l.isbn=%s
            GROUP BY l.isbn
        """, (isbn,))
        book = cursor.fetchone()
        conn.close()
        if book:
            xml = books_to_xml([book])
            return Response(xml, mimetype='application/xml')
        else:
            return Response("<?xml version='1.0' encoding='UTF-8'?><error>Libro no encontrado</error>", mimetype='application/xml', status=404)
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/formats/<formato>', methods=['GET'])
@jwt_required()
def get_books_by_format(formato):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT l.*, 
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors, 
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE l.formato=%s
            GROUP BY l.isbn
        """, (formato,))
        books = cursor.fetchall()
        conn.close()
        xml = books_to_xml(books)
        return Response(xml, mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/author/<author_name>', methods=['GET'])
@jwt_required()
def get_books_by_author(author_name):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT l.*, 
                   GROUP_CONCAT(a.nombre SEPARATOR ',') AS authors, 
                   c.nombre AS genre_name
            FROM Libro l
            LEFT JOIN Autor a ON l.id_autor = a.id_autor
            LEFT JOIN Categoria c ON l.id_categoria = c.id_categoria
            WHERE a.nombre LIKE %s
            GROUP BY l.isbn
        """, ('%' + author_name + '%',))
        books = cursor.fetchall()
        conn.close()
        xml = books_to_xml(books)
        return Response(xml, mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/book/insert', methods=['POST'])
@jwt_required()
def insert_book():
    try:
        data = request.json
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Libro (isbn, titulo, id_autor, id_categoria, id_editorial, anio_publicacion, price, stock, formato)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data.get('isbn'), data.get('titulo'), data.get('id_autor'), data.get('id_categoria'), data.get('id_editorial'),
            data.get('anio_publicacion'), data.get('price'), data.get('stock'), data.get('formato')
        ))
        conn.commit()
        conn.close()
        return Response("<?xml version='1.0' encoding='UTF-8'?><success>Libro insertado</success>", mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/book/delete', methods=['DELETE'])
@jwt_required()
def delete_book():
    try:
        isbn = request.args.get('isbn')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Libro WHERE isbn=%s", (isbn,))
        conn.commit()
        conn.close()
        return Response("<?xml version='1.0' encoding='UTF-8'?><success>Libro eliminado</success>", mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

@app.route('/api/books/book/update', methods=['PUT'])
@jwt_required()
def update_book():
    try:
        data = request.json
        isbn = data.get('isbn')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE Libro SET
            titulo=%s,
            id_autor=%s,
            id_categoria=%s,
            id_editorial=%s,
            anio_publicacion=%s,
            price=%s,
            stock=%s,
            formato=%s
            WHERE isbn=%s
        """, (
            data.get('titulo'), data.get('id_autor'), data.get('id_categoria'), data.get('id_editorial'),
            data.get('anio_publicacion'), data.get('price'), data.get('stock'), data.get('formato'), isbn
        ))
        conn.commit()
        conn.close()
        return Response("<?xml version='1.0' encoding='UTF-8'?><success>Libro actualizado</success>", mimetype='application/xml')
    except Exception as e:
        return Response(f"<?xml version='1.0' encoding='UTF-8'?><error>{str(e)}</error>", mimetype='application/xml', status=500)

# ----------------------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
