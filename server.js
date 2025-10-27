// =======================================================================
//        Servidor Backend con Autenticación JWT y Base de Datos JSON
// =======================================================================

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// --- Configuración ---
const app = express();
const PORT = process.env.PORT || 3000;
const dbFilePath = path.join(__dirname, 'db.json');

const SECRET_KEY = '12345';

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Funciones Helper (Leer/Escribir JSON) ---
function readData() {
  try {
    const data = fs.readFileSync(dbFilePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Error al leer la base de datos:", err);
    return { productos: [], usuarios: [] };
  }
}

function writeData(data) {
  try {
    fs.writeFileSync(dbFilePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error("Error al escribir en la base de datos:", err);
  }
}

// --- Middleware de Autenticación JWT ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.log("Token inválido:", err.message);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// --- Middleware de Verificación de Rol (Superadmin) ---
function requireSuperadmin(req, res, next) {
    if (req.user && req.user.role === 'Superadmin') {
        next();
    } else {
        res.status(403).json({ error: 'Acceso denegado. Se requiere rol de Superadmin.' });
    }
}

app.post('/api/register', (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son obligatorios.' });
  }
  const data = readData();
  const userExists = data.usuarios.find(u => u.email === email);
  if (userExists) {
    return res.status(409).json({ error: 'El email ya está registrado.' });
  }
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  const maxId = data.usuarios.reduce((max, u) => u.id > max ? u.id : max, 0);
  const newUser = { id: maxId + 1, email: email, password: hashedPassword, role: role || 'Operador' };
  data.usuarios.push(newUser);
  writeData(data);
  res.status(201).json({ message: 'Usuario registrado exitosamente.' });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son obligatorios.' });
  }
  const data = readData();
  const user = data.usuarios.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }
  
  // Logs de depuración (puedes quitarlos si ya funciona)
  console.log('Email recibido:', email);
  console.log('Contraseña recibida (texto plano):', password);
  console.log('Usuario encontrado en db.json:', user); 
  console.log('Hash guardado en db.json:', user.password);
  
  const isPasswordValid = bcrypt.compareSync(password, user.password);
  console.log('¿La contraseña coincide?:', isPasswordValid); 

  if (!isPasswordValid) {
    console.log('Resultado: Contraseña incorrecta.');
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }
  
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ message: 'Inicio de sesión exitoso.', token: token, user: { email: user.email, role: user.role } });
});

app.get('/api/productos', authenticateToken, (req, res) => {
  const data = readData();
  res.json(data.productos);
});

// GET: Obtener un producto por su SKU
app.get('/api/productos/sku/:sku', authenticateToken, (req, res) => {
  const { sku } = req.params;
  const data = readData();
  const producto = data.productos.find(p => p.SKU === sku);
  if (producto) { res.json(producto); } 
  else { res.status(404).json({ error: 'Producto no encontrado.' }); }
});

// POST: Crear un nuevo producto
app.post('/api/productos', authenticateToken, (req, res) => {
  const data = readData();
  const { SKU, Nombre_Producto, Descripcion, Costo } = req.body;
  if (!SKU || !Nombre_Producto || Costo === null || Costo === undefined) {
    return res.status(400).json({ error: 'SKU, Nombre y Costo son obligatorios.' });
  }
  if (data.productos.find(p => p.SKU === SKU)) {
    return res.status(409).json({ error: `El SKU '${SKU}' ya existe.` });
  }
  const maxId = data.productos.reduce((max, p) => p.ID_Producto > max ? p.ID_Producto : max, 0);
  const nuevoProducto = { ID_Producto: maxId + 1, SKU, Nombre_Producto, Descripcion, Costo, Stock_Actual: 0 };
  data.productos.push(nuevoProducto);
  writeData(data);
  res.status(201).json({ message: 'Producto creado exitosamente.', insertedId: nuevoProducto.ID_Producto });
});

// PUT: Actualizar un producto existente por su SKU
app.put('/api/productos/sku/:sku', authenticateToken, (req, res) => {
  const { sku } = req.params;
  const { Descripcion, Costo } = req.body;
  if (Costo === null || Costo === undefined || Costo < 0) {
    return res.status(400).json({ error: 'El costo es obligatorio y no puede ser negativo.' });
  }
  const data = readData();
  const productIndex = data.productos.findIndex(p => p.SKU === sku);
  if (productIndex === -1) {
    return res.status(404).json({ error: 'Producto no encontrado para actualizar.' });
  }
  data.productos[productIndex].Descripcion = Descripcion;
  data.productos[productIndex].Costo = Costo;
  writeData(data);
  res.json({ message: 'Producto actualizado exitosamente.' });
});

// GET: Obtener todos los usuarios
app.get('/api/usuarios', authenticateToken, requireSuperadmin, (req, res) => {
  const data = readData();
  const usersWithoutPassword = data.usuarios.map(({ password, ...user }) => user);
  res.json(usersWithoutPassword);
});

app.get('/api/usuarios/:id', authenticateToken, requireSuperadmin, (req, res) => {
  const userIdToGet = parseInt(req.params.id, 10);
  const data = readData();
  const user = data.usuarios.find(u => u.id === userIdToGet);

  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }

  // No enviamos la contraseña
  const { password, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

app.put('/api/usuarios/:id', authenticateToken, requireSuperadmin, (req, res) => {
  const userIdToUpdate = parseInt(req.params.id, 10); // ID del usuario a modificar
  const requestingUserId = req.user.id; // ID del Superadmin que hace la petición
  const { role } = req.body; // Nuevo rol enviado en el cuerpo de la petición

  // Validación básica: ¿se envió un rol?
  if (!role || (role !== 'Superadmin' && role !== 'Operador')) {
    return res.status(400).json({ error: 'Rol inválido o faltante. Debe ser "Superadmin" u "Operador".' });
  }

  // Impedir que el Superadmin cambie su propio rol (podría bloquearse a sí mismo)
  if (userIdToUpdate === requestingUserId) {
    return res.status(400).json({ error: 'No puedes modificar tu propio rol.' });
  }

  const data = readData();
  const userIndex = data.usuarios.findIndex(user => user.id === userIdToUpdate);

  // Verificar si el usuario a modificar existe
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }

  // Actualizar el rol del usuario encontrado
  data.usuarios[userIndex].role = role;

  // Guardar los cambios en el archivo db.json
  writeData(data);

  // Devolver solo los datos actualizados (sin contraseña)
  const { password, ...updatedUser } = data.usuarios[userIndex];
  res.json({ message: 'Rol de usuario actualizado exitosamente.', user: updatedUser });
});

// DELETE: Eliminar un usuario por ID
app.delete('/api/usuarios/:id', authenticateToken, requireSuperadmin, (req, res) => {
  const userIdToDelete = parseInt(req.params.id, 10);
  const requestingUserId = req.user.id; 

  if (userIdToDelete === requestingUserId) {
    return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta.' });
  }

  const data = readData();
  const initialLength = data.usuarios.length;
  data.usuarios = data.usuarios.filter(user => user.id !== userIdToDelete);

  if (data.usuarios.length === initialLength) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }

  writeData(data);
  res.json({ message: 'Usuario eliminado exitosamente.' });
});


// --- Iniciar el Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});