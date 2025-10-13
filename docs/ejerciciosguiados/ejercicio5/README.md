# 📚 Microservicio de Libros con JWT + Redis + MariaDB

## 🧩 Descripción General

Este proyecto implementa un **microservicio de gestión de libros (Books API)** desarrollado con **Flask**, protegido mediante **autenticación JWT** y con **Redis** como sistema de gestión de sesiones y revocación de tokens.
El sistema se conecta a una base de datos **MariaDB** para el almacenamiento de usuarios y libros.
Además, incluye un **cliente web (HTML + CSS + JavaScript)** para probar la autenticación y todas las operaciones CRUD.

---

## ⚙️ Tecnologías Utilizadas

* **Flask** – Framework backend.
* **MariaDB** – Base de datos relacional (almacena usuarios y libros).
* **Redis** – Gestión de tokens (allowlist / denylist).
* **Flask-JWT-Extended** – Generación y validación de JWT.
* **Flask-CORS** – Permite comunicación entre front y back.
* **Passlib** – Hash seguro de contraseñas.
* **HTML / CSS / JS (Fetch API)** – Cliente web.

---

## 🧱 Arquitectura

```
Cliente Web (HTML/JS)
        ↓
Flask API (main.py)
        ↓
MariaDB ←→ Redis
```

**Flujo:**

1. El usuario se registra o inicia sesión.
2. Flask genera `access_token` y `refresh_token`.
3. Redis almacena los tokens activos (allowlist).
4. Los endpoints `/api/books/...` requieren JWT válido.
5. Logout revoca los tokens en Redis.

---

## 📂 Estructura del Proyecto

```
/ (directorio raíz) 
├── Microservices/ 
│      └── micro02/ 
│              └── main.py   #Backend  Flask
└── WebApplication/  
         ├── index.html      #Pagina web del cliente
         ├── style.css       #Estilo de la pagina web
          └── script.js      # Logica de implemnetacion de los endpoints, JWT y Redis con la BD

```

---

## ⚡ Ejecución del Proyecto

### 1️⃣ Configurar variables

Asegúrate de tener Redis, MariaDB, JWT y CORS en ejecución.

```bash
sudo systemctl start mariadb
sudo systemctl start redis
```

```python
pip install Flask-JWT-Extended passlib
pip install Flask-Cors
```


Verifica la base de datos:

```sql
USE Libros;
SELECT * FROM Users;
SELECT * FROM Books;
```

---

### 2️⃣ Ejecutar el backend Flask

```bash
export FLASK_APP="main.py"
flask run --host=0.0.0.0
```

✅ Si ves el mensaje:

```
Running on all addresses (0.0.0.0)
* Running on http://<tu_IP>:5000
```

El backend está funcionando correctamente.

---

### 3️⃣ Levantar el cliente web

Desde el mismo directorio del proyecto:

```bash
sudo python3 -m http.server 8080
```

Luego entra en tu navegador a:

```
http://<tu_IP>:8080
```

---

## 🧠 Endpoints Principales

### 🔐 Autenticación

| Método | Endpoint         | Descripción                      |
| :----- | :--------------- | :------------------------------- |
| POST   | `/auth/register` | Registra un nuevo usuario        |
| POST   | `/auth/login`    | Devuelve access y refresh tokens |
| POST   | `/auth/refresh`  | Genera un nuevo access token     |
| POST   | `/auth/logout`   | Revoca el access token actual    |

---

### 📚 Libros (protegidos con JWT)

| Método | Endpoint                              | Descripción                     |
| :----- | :------------------------------------ | :------------------------------ |
| GET    | `/api/books`                          | Devuelve todos los libros (XML) |
| GET    | `/api/books/ISBN?isbn=<valor>`        | Busca libro por ISBN            |
| GET    | `/api/books/formats/?format=<valor>`  | Filtra por formato              |
| GET    | `/api/books/author/?name=<nombre>`    | Filtra por autor                |
| POST   | `/api/books/book/insert`              | Inserta un libro nuevo          |
| PUT    | `/api/books/book/update`              | Actualiza datos de un libro     |
| DELETE | `/api/books/book/delete?isbn=<valor>` | Elimina libro por ISBN          |

---

## 🧪 Pruebas con `curl`

### Registro

```bash
curl -X POST http://<IP>:5000/auth/register \
-H "Content-Type: application/json" \
-d '{"username":"test","password":"1234"}'
```

### Login

```bash
curl -X POST http://<IP>:5000/auth/login \
-H "Content-Type: application/json" \
-d '{"username":"test","password":"1234"}'
```

### Acceso protegido

```bash
curl -X GET http://<IP>:5000/api/books \
-H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Refresh

```bash
curl -X POST http://<IP>:5000/auth/refresh \
-H "Authorization: Bearer <REFRESH_TOKEN>"
```

### Logout

```bash
curl -X POST http://<IP>:5000/auth/logout \
-H "Authorization: Bearer <ACCESS_TOKEN>"
```

---

## 🌐 Cliente Web

Desde la interfaz gráfica podrás:

* Registrar e iniciar sesión.
* Ver, buscar, insertar, actualizar y eliminar libros.
* Observar los tokens y logs en tiempo real.

---

## 👤 Autor

**Margarita Concepción Cuervo Citalán**
Ingeniería en Tecnologías Computacionales
Universidad de Monterrey – 2025
