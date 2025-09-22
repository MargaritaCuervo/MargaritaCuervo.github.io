const API_URL = 'http://35.222.91.194:5000';

const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const appSection = document.getElementById('app-section');
const getBooksBtn = document.getElementById('get-books');
const booksContainer = document.getElementById('books-container');
const clientLogs = document.getElementById('client-logs');

// Nuevos selectores para las búsquedas
const searchIsbnForm = document.getElementById('search-isbn-form');
const searchFormatForm = document.getElementById('search-format-form');
const searchAuthorForm = document.getElementById('search-author-form');

// Selectores para operaciones CRUD
const insertForm = document.getElementById('insert-form');
const updateForm = document.getElementById('update-form');
const deleteForm = document.getElementById('delete-form');


// Función para agregar logs al área de logs del cliente
const log = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    clientLogs.innerHTML += `[${timestamp}] [${type.toUpperCase()}] ${message}\n`;
    clientLogs.scrollTop = clientLogs.scrollHeight;
};

// --- Flujo de Autenticación y Token Handling ---

// 1. Manejar el inicio de sesión
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    log('Intentando iniciar sesión...', 'info');
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();
        
        if (response.ok) {
            log('¡Inicio de sesión exitoso!', 'success');
            log(`Tokens recibidos. Guardando en localStorage.`, 'info');
            // Guardar tokens en el almacenamiento local del navegador
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('refresh_token', data.refresh_token);
            
            // Ocultar la sección de login y mostrar la de la app
            document.querySelector('.auth-section').classList.add('hidden');
            appSection.classList.remove('hidden');
        } else {
            log(`Error de autenticación: ${data.msg}`, 'error');
        }
    } catch (error) {
        log(`Error de red al intentar iniciar sesión: ${error.message}`, 'error');
    }
});

// 2. Manejar el registro
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;

    log('Intentando registrar nuevo usuario...', 'info');
    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();
        
        if (response.ok) {
            log('¡Registro exitoso!', 'success');
            log(`Ahora puedes iniciar sesión con tu nuevo usuario.`, 'info');
        } else {
            log(`Error de registro: ${data.msg}`, 'error');
        }
    } catch (error) {
        log(`Error de red al intentar registrar: ${error.message}`, 'error');
    }
});

// 3. Manejar la solicitud de libros con el token
getBooksBtn.addEventListener('click', async () => {
    log('Intentando obtener la lista de libros...', 'info');
    
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        log('Error: No se encontró el token de acceso. Por favor, inicie sesión.', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/api/books`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });
        
        if (response.ok) {
            log('¡Solicitud exitosa!', 'success');
            // Parsear el XML
            const xmlText = await response.text();
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, "text/xml");
            
            // Mostrar los libros
            displayBooks(xmlDoc);
        } else if (response.status === 401) {
            log('Token expirado o inválido. Intentando refrescar el token...', 'warning');
            await refreshToken();
            // Reintentar la solicitud después de refrescar
            await getBooksBtn.click();
        } else {
            const errorText = await response.text();
            log(`Error al obtener libros: ${response.status} - ${errorText}`, 'error');
        }
    } catch (error) {
        log(`Error de red al obtener libros: ${error.message}`, 'error');
    }
});

// 4. Manejar el refresco del token
const refreshToken = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
        log('Error: No se encontró el token de refresco. Por favor, vuelva a iniciar sesión.', 'error');
        // Redirigir al usuario al login
        document.querySelector('.auth-section').classList.remove('hidden');
        appSection.classList.add('hidden');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/refresh`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${refreshToken}`,
            },
        });

        const data = await response.json();
        
        if (response.ok) {
            log('Token de acceso refrescado con éxito.', 'success');
            localStorage.setItem('access_token', data.access_token);
            log('Nuevo token de acceso guardado.', 'info');
        } else {
            log(`Error al refrescar el token: ${data.msg}. Sesión expirada.`, 'error');
            // Redirigir al usuario al login
            document.querySelector('.auth-section').classList.remove('hidden');
            appSection.classList.add('hidden');
        }
    } catch (error) {
        log(`Error de red al intentar refrescar el token: ${error.message}`, 'error');
    }
};

// --- Funciones para manejar la UI ---

function displayBooks(xmlDoc) {
    booksContainer.innerHTML = ''; // Limpiar el contenedor
    const books = xmlDoc.getElementsByTagName('book');
    if (books.length === 0) {
        booksContainer.innerHTML = '<p>No se encontraron libros.</p>';
        return;
    }
    
    for (const book of books) {
	const isbn = book.getAttribute('isbn');
        const title = book.getElementsByTagName('title')[0]?.textContent;
        const author = book.getElementsByTagName('author')[0]?.textContent;
        const year = book.getElementsByTagName('year')[0]?.textContent;
	const genre = book.getElementsByTagName('genre')[0]?.textContent;
	const price = book.getElementsByTagName('price')[0]?.textContent;
	const stock = book.getElementsByTagName('stock')[0]?.textContent;
	const format = book.getElementsByTagName('format')[0]?.textContent;

        const bookDiv = document.createElement('div');
        bookDiv.classList.add('book-item');
        bookDiv.innerHTML = `
	    <strong>ISBN:</strong> ${isbn || 'Desconocido'}<br>
            <strong>Título:</strong> ${title || 'Desconocido'}<br>
            <strong>Autor:</strong> ${author || 'Desconocido'}<br>
            <strong>Año:</strong> ${year || 'Desconocido'}<br>
	    <strong>Género:</strong> ${genre || 'Desconocido'}<br>
	    <strong>Precio:</strong> ${price || 'Desconocido'}<br>
	    <strong>Stock:</strong> ${stock || 'Desconocido'}<br>
	    <strong>Formato:</strong> ${format || 'Desconocido'}
        `;
        booksContainer.appendChild(bookDiv);
    }
}

// --- Manejar el insert ---
insertForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        log('Error: No se encontró el token de acceso. Inicie sesión.', 'error');
        return;
    }

    const bookData = {
        isbn: document.getElementById('isbn-insert').value,
        titulo: document.getElementById('titulo-insert').value,
        id_autor: parseInt(document.getElementById('id_autor-insert').value),
        id_categoria: parseInt(document.getElementById('id_categoria-insert').value),
        id_editorial: parseInt(document.getElementById('id_editorial-insert').value),
        anio_publicacion: parseInt(document.getElementById('anio_publicacion-insert').value),
        price: parseFloat(document.getElementById('price-insert').value),
        stock: parseInt(document.getElementById('stock-insert').value),
        formato: document.getElementById('formato-insert').value,
    };

    log('Intentando insertar un nuevo libro...', 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/book/insert`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            body: JSON.stringify(bookData),
        });

        const text = await response.text();
        if (response.ok) {
            log('Libro insertado con éxito!', 'success');
        } else {
            log(`Error al insertar libro: ${response.status} - ${text}`, 'error');
        }
    } catch (error) {
        log(`Error de red al insertar libro: ${error.message}`, 'error');
    }
});

// --- Manejar el update ---
updateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        log('Error: No se encontró el token de acceso. Inicie sesión.', 'error');
        return;
    }

    const bookData = {
        isbn: document.getElementById('isbn-update').value,
        titulo: document.getElementById('titulo-update').value,
        id_autor: document.getElementById('id_autor-update').value,
        id_categoria: document.getElementById('id_categoria-update').value,
        id_editorial: document.getElementById('id_editorial-update').value,
        anio_publicacion: document.getElementById('anio_publicacion-update').value,
        price: document.getElementById('price-update').value,
        stock: document.getElementById('stock-update').value,
        formato: document.getElementById('formato-update').value,
    };

    // Filtrar los campos vacíos para no enviar datos nulos
    Object.keys(bookData).forEach(key => bookData[key] === '' && delete bookData[key]);

    log('Intentando actualizar un libro...', 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/book/update`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            body: JSON.stringify(bookData),
        });

        const text = await response.text();
        if (response.ok) {
            log('Libro actualizado con éxito!', 'success');
        } else {
            log(`Error al actualizar libro: ${response.status} - ${text}`, 'error');
        }
    } catch (error) {
        log(`Error de red al actualizar libro: ${error.message}`, 'error');
    }
});

// --- Manejar el delete ---
deleteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
        log('Error: No se encontró el token de acceso. Inicie sesión.', 'error');
        return;
    }

    const isbn = document.getElementById('isbn-delete').value;
    log('Intentando eliminar un libro...', 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/book/delete?isbn=${isbn}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });

        const text = await response.text();
        if (response.ok) {
            log('Libro eliminado con éxito!', 'success');
        } else {
            log(`Error al eliminar libro: ${response.status} - ${text}`, 'error');
        }
    } catch (error) {
        log(`Error de red al eliminar libro: ${error.message}`, 'error');
    }
});

// --- Manejar las búsquedas (GET) ---

// Buscar por ISBN
searchIsbnForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    const isbn = document.getElementById('isbn-search').value;
    if (!accessToken) { log('Error: No se encontró el token de acceso.', 'error'); return; }

    log(`Buscando libro con ISBN: ${isbn}...`, 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/${isbn}`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${accessToken}` },
        });
        const xmlText = await response.text();
        if (response.ok) {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, "text/xml");
            displayBooks(xmlDoc);
            log(`Búsqueda por ISBN exitosa.`, 'success');
        } else {
            log(`Error en la búsqueda por ISBN: ${response.status} - ${xmlText}`, 'error');
        }
    } catch (error) { log(`Error de red en la búsqueda por ISBN: ${error.message}`, 'error'); }
});

// Buscar por formato
searchFormatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    const format = document.getElementById('format-search').value;
    if (!accessToken) { log('Error: No se encontró el token de acceso.', 'error'); return; }

    log(`Buscando libros con formato: ${format}...`, 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/formats/${format}`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${accessToken}` },
        });
        const xmlText = await response.text();
        if (response.ok) {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, "text/xml");
            displayBooks(xmlDoc);
            log(`Búsqueda por formato exitosa.`, 'success');
        } else {
            log(`Error en la búsqueda por formato: ${response.status} - ${xmlText}`, 'error');
        }
    } catch (error) { log(`Error de red en la búsqueda por formato: ${error.message}`, 'error'); }
});

// Buscar por autor
searchAuthorForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const accessToken = localStorage.getItem('access_token');
    const author = document.getElementById('author-search').value;
    if (!accessToken) { log('Error: No se encontró el token de acceso.', 'error'); return; }

    log(`Buscando libros por autor: ${author}...`, 'info');
    try {
        const response = await fetch(`${API_URL}/api/books/author/${author}`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${accessToken}` },
        });
        const xmlText = await response.text();
        if (response.ok) {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, "text/xml");
            displayBooks(xmlDoc);
            log(`Búsqueda por autor exitosa.`, 'success');
        } else {
            log(`Error en la búsqueda por autor: ${response.status} - ${xmlText}`, 'error');
        }
    } catch (error) { log(`Error de red en la búsqueda por autor: ${error.message}`, 'error'); }
});
