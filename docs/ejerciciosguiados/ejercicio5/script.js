// =====================
// Config
// =====================
const API_URL = 'http://34.45.183.213:5000'; // <-- cambiarla por la IP actual

// =====================
// Selectores (según tu index.html)
// =====================
const loginForm      = document.getElementById('login-form');
const registerForm   = document.getElementById('register-form');
const appSection     = document.getElementById('app-section');
const getBooksBtn    = document.getElementById('get-books');
const booksContainer = document.getElementById('books-container');
const clientLogs     = document.getElementById('client-logs');

// Opcionales (si existen en tu HTML)
const statusBtn  = document.getElementById('status-btn');
const logoutBtn  = document.getElementById('logout-btn');
const kpiAccess  = document.getElementById('kpi-access');
const kpiRefresh = document.getElementById('kpi-refresh');

// Búsquedas
const searchIsbnForm   = document.getElementById('search-isbn-form');
const searchFormatForm = document.getElementById('search-format-form');
const searchAuthorForm = document.getElementById('search-author-form');

// CRUD
const insertForm = document.getElementById('insert-form');
const updateForm = document.getElementById('update-form');
const deleteForm = document.getElementById('delete-form');

// =====================
// Utils UI + Tokens
// =====================
const log = (message, type = 'info') => {
  const timestamp = new Date().toLocaleTimeString();
  clientLogs.textContent += `[${timestamp}] [${type.toUpperCase()}] ${message}\n`;
  clientLogs.scrollTop = clientLogs.scrollHeight;
};

const redact = (tok) => (!tok ? '—' : (tok.length <= 20 ? tok : `${tok.slice(0,10)}…${tok.slice(-10)}`));

const showApp = (show) => {
  const auth = document.querySelector('.auth-section');
  if (show) { auth?.classList.add('hidden'); appSection?.classList.remove('hidden'); }
  else { appSection?.classList.add('hidden'); auth?.classList.remove('hidden'); }
};

const updateKpis = () => {
  kpiAccess  && (kpiAccess.textContent  = redact(localStorage.getItem('access_token')));
  kpiRefresh && (kpiRefresh.textContent = redact(localStorage.getItem('refresh_token')));
};

const saveTokens = ({ access_token, refresh_token }) => {
  if (access_token)  localStorage.setItem('access_token',  access_token);
  if (refresh_token) localStorage.setItem('refresh_token', refresh_token);
  updateKpis();
};

const clearTokens = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  updateKpis();
};

const getAccess  = () => localStorage.getItem('access_token');
const getRefresh = () => localStorage.getItem('refresh_token');

// =====================
// Auto-Refresh (refresh token)
// =====================
const doRefresh = async () => {
  const rt = getRefresh();
  if (!rt) { log('No hay refresh token para refrescar.', 'warning'); return false; }
  try {
    const res = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${rt}` }
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data?.access_token) {
      log(`Refresh falló: ${res.status} ${JSON.stringify(data)}`, 'error');
      return false;
    }
    saveTokens({ access_token: data.access_token });
    log('Refresh OK → nuevo access token guardado.', 'success');
    return true;
  } catch (e) {
    log(`Error de red en refresh: ${e.message}`, 'error');
    return false;
  }
};

async function fetchWithAuth(path, options = {}, retry = true) {
  const access = getAccess();
  const headers = Object.assign({}, options.headers || {}, access ? { 'Authorization': `Bearer ${access}` } : {});
  const opts = Object.assign({}, options, { headers });

  const res = await fetch(`${API_URL}${path}`, opts);

  if (res.status === 401 && retry && getRefresh()) {
    log(`401 en ${path}. Intentando refresh…`, 'warning');
    const ok = await doRefresh();
    if (ok) return fetchWithAuth(path, options, false);
    log('No fue posible refrescar. Volviendo a login…', 'error');
    clearTokens();
    showApp(false);
  }

  return res;
}

// =====================
// Auth
// =====================
loginForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  log('Intentando iniciar sesión…', 'info');

  try {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(()=>null);
    if (res.ok && data?.access_token && data?.refresh_token) {
      saveTokens({ access_token: data.access_token, refresh_token: data.refresh_token });
      log('¡Inicio de sesión exitoso!', 'success');
      showApp(true);
    } else {
      log(`Error de autenticación: ${data?.msg || res.status}`, 'error');
    }
  } catch (err) {
    log(`Error de red en login: ${err.message}`, 'error');
  }
});

registerForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value.trim();
  log('Intentando registrar usuario…', 'info');

  try {
    const res = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json().catch(()=>null);
    if (res.ok) {
      log('¡Registro exitoso! Ya puedes iniciar sesión.', 'success');
    } else {
      log(`Error de registro: ${data?.msg || res.status}`, 'error');
    }
  } catch (err) {
    log(`Error de red en registro: ${err.message}`, 'error');
  }
});

logoutBtn?.addEventListener('click', async () => {
  log('Cerrando sesión…', 'info');
  const res = await fetchWithAuth('/auth/logout', { method: 'POST' }, /*retry*/ false);
  try {
    const data = await res.json().catch(()=>null);
    if (res.ok) log(`Logout OK.`, 'success');
    else log(`Logout devolvió ${res.status}: ${JSON.stringify(data)}`, 'warning');
  } catch {/* ignore */}
  clearTokens();
  showApp(false);
});

// =====================
// Books (XML render)
// =====================
function displayBooks(xmlDoc) {
  booksContainer.innerHTML = '';
  const books = xmlDoc.getElementsByTagName('book');
  if (!books || books.length === 0) {
    booksContainer.innerHTML = '<p>No se encontraron libros.</p>';
    return;
  }
  for (const book of books) {
    const isbn    = book.getAttribute('isbn');
    const title   = book.getElementsByTagName('title')[0]?.textContent;
    const authors = Array.from(book.getElementsByTagName('author')).map(a=>a.textContent).join(', ');
    const year    = book.getElementsByTagName('year')[0]?.textContent;
    const genre   = book.getElementsByTagName('genre')[0]?.textContent;
    const price   = book.getElementsByTagName('price')[0]?.textContent;
    const stock   = book.getElementsByTagName('stock')[0]?.textContent;
    const format  = book.getElementsByTagName('format')[0]?.textContent;

    const div = document.createElement('div');
    div.classList.add('book-item');
    div.innerHTML = `
      <strong>ISBN:</strong> ${isbn || 'Desconocido'}<br>
      <strong>Título:</strong> ${title || 'Desconocido'}<br>
      <strong>Autores:</strong> ${authors || 'Desconocido'}<br>
      <strong>Año:</strong> ${year || 'Desconocido'}<br>
      <strong>Género:</strong> ${genre || 'Desconocido'}<br>
      <strong>Precio:</strong> ${price || 'Desconocido'}<br>
      <strong>Stock:</strong> ${stock || 'Desconocido'}<br>
      <strong>Formato:</strong> ${format || 'Desconocido'}
    `;
    booksContainer.appendChild(div);
  }
}

// =====================
// Acciones: listado y búsquedas
// =====================
getBooksBtn?.addEventListener('click', async () => {
  log('Solicitando lista de libros…', 'info');
  try {
    const res = await fetchWithAuth('/api/books', { method: 'GET' });
    const xmlText = await res.text();
    if (res.ok) {
      const xmlDoc = new DOMParser().parseFromString(xmlText, 'text/xml');
      displayBooks(xmlDoc);
      log('¡Solicitud de libros exitosa!', 'success');
    } else {
      log(`Error al obtener libros: ${res.status} - ${xmlText.slice(0,200)}`, 'error');
    }
  } catch (err) {
    log(`Error de red al obtener libros: ${err.message}`, 'error');
  }
});

searchIsbnForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const isbn = document.getElementById('isbn-search').value.trim();
  if (!isbn) return;
  log(`Buscando por ISBN: ${isbn}…`, 'info');
  try {
    const res = await fetchWithAuth(`/api/books/ISBN?isbn=${encodeURIComponent(isbn)}`, { method: 'GET' });
    const xmlText = await res.text();
    if (res.ok) {
      const xmlDoc = new DOMParser().parseFromString(xmlText, 'text/xml');
      displayBooks(xmlDoc);
      log('Búsqueda por ISBN exitosa.', 'success');
    } else {
      log(`Error en búsqueda ISBN: ${res.status} - ${xmlText.slice(0,200)}`, 'error');
    }
  } catch (err) {
    log(`Error de red en búsqueda ISBN: ${err.message}`, 'error');
  }
});

searchFormatForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const format = document.getElementById('format-search').value.trim();
  if (!format) return;
  log(`Buscando por formato: ${format}…`, 'info');
  try {
    const res = await fetchWithAuth(`/api/books/format/?format=${encodeURIComponent(format)}`, { method: 'GET' });
    const xmlText = await res.text();
    if (res.ok) {
      const xmlDoc = new DOMParser().parseFromString(xmlText, 'text/xml');
      displayBooks(xmlDoc);
      log('Búsqueda por formato exitosa.', 'success');
    } else {
      log(`Error en búsqueda formato: ${res.status} - ${xmlText.slice(0,200)}`, 'error');
    }
  } catch (err) {
    log(`Error de red en búsqueda formato: ${err.message}`, 'error');
  }
});

searchAuthorForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const author = document.getElementById('author-search').value.trim();
  if (!author) return;
  log(`Buscando por autor: ${author}…`, 'info');
  try {
    const res = await fetchWithAuth(`/api/books/autor/?name=${encodeURIComponent(author)}`, { method: 'GET' });
    const xmlText = await res.text();
    if (res.ok) {
      const xmlDoc = new DOMParser().parseFromString(xmlText, 'text/xml');
      displayBooks(xmlDoc);
      log('Búsqueda por autor exitosa.', 'success');
    } else {
      log(`Error en búsqueda autor: ${res.status} - ${xmlText.slice(0,200)}`, 'error');
    }
  } catch (err) {
    log(`Error de red en búsqueda autor: ${err.message}`, 'error');
  }
});

// =====================
// CRUD
// =====================
insertForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    isbn: document.getElementById('isbn-insert').value.trim(),
    titulo: document.getElementById('titulo-insert').value.trim(),
    id_autor: parseInt(document.getElementById('id_autor-insert').value, 10),
    id_categoria: parseInt(document.getElementById('id_categoria-insert').value, 10),
    id_editorial: parseInt(document.getElementById('id_editorial-insert').value, 10),
    anio_publicacion: parseInt(document.getElementById('anio_publicacion-insert').value, 10),
    price: parseFloat(document.getElementById('price-insert').value),
    stock: parseInt(document.getElementById('stock-insert').value, 10),
    formato: document.getElementById('formato-insert').value.trim(),
  };
  log('Insertando libro…', 'info');
  try {
    const res = await fetchWithAuth('/api/books/create', {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify(payload)
    });
    const text = await res.text();
    if (res.ok) log('Libro insertado con éxito.', 'success');
    else log(`Error insert: ${res.status} - ${text.slice(0,200)}`, 'error');
  } catch (err) {
    log(`Error de red en insert: ${err.message}`, 'error');
  }
});

updateForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    isbn: document.getElementById('isbn-update').value.trim(),
    titulo: document.getElementById('titulo-update').value.trim(),
    id_autor: document.getElementById('id_autor-update').value.trim(),
    id_categoria: document.getElementById('id_categoria-update').value.trim(),
    id_editorial: document.getElementById('id_editorial-update').value.trim(),
    anio_publicacion: document.getElementById('anio_publicacion-update').value.trim(),
    price: document.getElementById('price-update').value.trim(),
    stock: document.getElementById('stock-update').value.trim(),
    formato: document.getElementById('formato-update').value.trim(),
  };
  Object.keys(payload).forEach(k => payload[k] === '' && delete payload[k]);
  log('Actualizando libro…', 'info');
  try {
    const res = await fetchWithAuth('/api/books/update', {
      method: 'PUT',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify(payload)
    });
    const text = await res.text();
    if (res.ok) log('Libro actualizado con éxito.', 'success');
    else log(`Error update: ${res.status} - ${text.slice(0,200)}`, 'error');
  } catch (err) {
    log(`Error de red en update: ${err.message}`, 'error');
  }
});

deleteForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const isbn = document.getElementById('isbn-delete').value.trim();
  if (!isbn) return;
  log('Eliminando libro…', 'info');
  try {
    const res = await fetchWithAuth(`/api/books/delete?isbn=${encodeURIComponent(isbn)}`, {
      method: 'DELETE'
    });
    const text = await res.text();
    if (res.ok) log('Libro eliminado con éxito.', 'success');
    else log(`Error delete: ${res.status} - ${text.slice(0,200)}`, 'error');
  } catch (err) {
    log(`Error de red en delete: ${err.message}`, 'error');
  }
});

// =====================
// Estado (opcional): botón “Estado de Autenticación”
// =====================
statusBtn?.addEventListener('click', async () => {
  const token = getAccess();
  if (!token) { log('Sin access token en localStorage.', 'warning'); return; }
  // Hacemos una llamada ligera para verificar validez del access:
  const res = await fetchWithAuth('/api/books', { method: 'GET' });
  if (res.ok) log('Estado: autenticado (access válido).', 'success');
  else log(`Estado: token inválido/expirado (${res.status}).`, 'warning');
});

// =====================
// Init
// =====================
(function init() {
  const hasTokens = !!getAccess() && !!getRefresh();
  showApp(hasTokens);
  updateKpis();
  if (hasTokens) log('Sesión restaurada desde localStorage.', 'info');
})();

