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
    return { productos: [], usuarios: [], movimientos: [] };
  }
}

function writeData(data) {
  try {
    fs.writeFileSync(dbFilePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error("Error al escribir en la base de datos:", err);
  }
}

// =======================================================================
//        Middlewares de Autenticación
// =======================================================================

/**
 * Verifica el token JWT en las cabeceras
 */
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

/**
 * Verifica que el rol del usuario sea 'Superadmin'
 */
function requireSuperadmin(req, res, next) {
    if (req.user && req.user.role === 'Superadmin') {
        next(); // Continuar si es Superadmin
    } else {
        res.status(403).json({ error: 'Acceso denegado. Se requiere rol de Superadmin.' });
    }
}

// =======================================================================
//        Rutas de Autenticación (Públicas)
// =======================================================================

// --- Ruta de Registro de Usuario (POST) ---
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

// --- Ruta de Inicio de Sesión (POST) ---
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
  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ message: 'Inicio de sesión exitoso.', token: token, user: { email: user.email, role: user.role } });
});

// =======================================================================
//        Rutas de Productos (Protegidas)
// =======================================================================

// GET: Obtener todos los productos
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

// =======================================================================
//        NUEVO: Rutas de Movimientos de Inventario (Protegidas)
// =======================================================================

// POST: Registrar una Entrada de Inventario
app.post('/api/movimientos/entrada', authenticateToken, (req, res) => {
  const { SKU, Cantidad } = req.body;
  const idUsuario = req.user.id; 

  if (!SKU || !Cantidad || Cantidad <= 0) {
    return res.status(400).json({ error: 'Se requiere un SKU y una Cantidad positiva.' });
  }

  const data = readData();
  const productIndex = data.productos.findIndex(p => p.SKU === SKU);

  if (productIndex === -1) {
    return res.status(404).json({ error: `Producto con SKU '${SKU}' no encontrado.` });
  }

  // Actualizar el stock del producto
  data.productos[productIndex].Stock_Actual += Cantidad;

  // Crear el registro del movimiento
  const maxMovimientoId = data.movimientos.reduce((max, m) => m.id > max ? m.id : max, 0);
  const nuevoMovimiento = {
    id: maxMovimientoId + 1,
    tipo: 'Entrada',
    SKU: SKU,
    Cantidad: Cantidad,
    ID_Usuario: idUsuario,
    Fecha: new Date().toISOString()
  };
  data.movimientos.push(nuevoMovimiento);

  writeData(data);

  res.status(201).json({ 
    message: 'Entrada registrada exitosamente.',
    productoActualizado: data.productos[productIndex]
  });
});

// --- NUEVO: Registrar una Salida de Inventario (POST) ---
app.post('/api/movimientos/salida', authenticateToken, (req, res) => {
  const { SKU, Cantidad } = req.body;
  const idUsuario = req.user.id;

  // 1. Validaciones
  if (!SKU || !Cantidad || Cantidad <= 0) {
    return res.status(400).json({ error: 'Se requiere un SKU y una Cantidad positiva.' });
  }

  const data = readData();
  const productIndex = data.productos.findIndex(p => p.SKU === SKU);

  // 2. Verificar que el producto existe
  if (productIndex === -1) {
    return res.status(404).json({ error: `Producto con SKU '${SKU}' no encontrado.` });
  }

  const producto = data.productos[productIndex];

  // 3. VERIFICACIÓN DE STOCK (la diferencia clave con 'entrada')
  if (producto.Stock_Actual < Cantidad) {
    return res.status(400).json({ 
      error: 'Stock insuficiente.',
      stockDisponible: producto.Stock_Actual 
    });
  }

  // 4. Actualizar el stock
  data.productos[productIndex].Stock_Actual -= Cantidad;

  // 5. Crear el registro del movimiento
  const maxMovimientoId = data.movimientos.reduce((max, m) => m.id > max ? m.id : max, 0);
  const nuevoMovimiento = {
    id: maxMovimientoId + 1,
    tipo: 'Salida',
    SKU: SKU,
    Cantidad: Cantidad,
    ID_Usuario: idUsuario,
    Fecha: new Date().toISOString()
  };
  data.movimientos.push(nuevoMovimiento);

  // 6. Guardar cambios
  writeData(data);

  res.status(201).json({ 
    message: 'Salida registrada exitosamente.',
    productoActualizado: data.productos[productIndex]
  });
});

app.get('/api/movimientos', authenticateToken, (req, res) => {
  // 1. Obtenemos los datos del usuario que hace la petición (del token)
  const { id: userId, role: userRole } = req.user;

  // 2. Leemos la base de datos completa
  const data = readData();
  let movimientosARetornar = [];

  // 3. --- LÓGICA DE PERMISOS ---
  if (userRole === 'Superadmin') {
    // Si es Superadmin, obtenemos todos los movimientos
    movimientosARetornar = data.movimientos;
  } else {
    // Si es Operador (o cualquier otro rol), filtramos solo sus movimientos
    movimientosARetornar = data.movimientos.filter(m => m.ID_Usuario === userId);
  }

  // 4. (Opcional pero recomendado) Enriquecemos los datos
  //    Añadimos el nombre del producto y el email del usuario a cada movimiento
  //    para que el frontend no tenga que hacer más peticiones.
  const enrichedMovements = movimientosARetornar.map(mov => {
    const producto = data.productos.find(p => p.SKU === mov.SKU);
    const usuario = data.usuarios.find(u => u.id === mov.ID_Usuario);
    
    return {
      ...mov, // Copia el movimiento (id, tipo, SKU, Cantidad, ID_Usuario, Fecha)
      Nombre_Producto: producto ? producto.Nombre_Producto : 'Producto Desconocido',
      Email_Usuario: usuario ? usuario.email : 'Usuario Desconocido'
    };
  });

  // 5. Ordenamos por fecha (el más reciente primero) y enviamos
  enrichedMovements.sort((a, b) => new Date(b.Fecha).getTime() - new Date(a.Fecha).getTime());
  
  res.json(enrichedMovements);
});

// =======================================================================
//        Rutas de Usuarios (Protegidas y Restringidas a Superadmin)
// =======================================================================

// GET: Obtener todos los usuarios
app.get('/api/usuarios', authenticateToken, requireSuperadmin, (req, res) => {
  const data = readData();
  const usersWithoutPassword = data.usuarios.map(({ password, ...user }) => user);
  res.json(usersWithoutPassword);
});

// GET: Obtener un Usuario por ID
app.get('/api/usuarios/:id', authenticateToken, requireSuperadmin, (req, res) => {
  const userIdToGet = parseInt(req.params.id, 10);
  const data = readData();
  const user = data.usuarios.find(u => u.id === userIdToGet);
  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }
  const { password, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

// PUT: Actualizar el Rol de un Usuario
app.put('/api/usuarios/:id', authenticateToken, requireSuperadmin, (req, res) => {
  const userIdToUpdate = parseInt(req.params.id, 10);
  const requestingUserId = req.user.id;
  const { role } = req.body;
  if (!role || (role !== 'Superadmin' && role !== 'Operador')) {
    return res.status(400).json({ error: 'Rol inválido o faltante. Debe ser "Superadmin" u "Operador".' });
  }
  if (userIdToUpdate === requestingUserId) {
    return res.status(400).json({ error: 'No puedes modificar tu propio rol.' });
  }
  const data = readData();
  const userIndex = data.usuarios.findIndex(user => user.id === userIdToUpdate);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }
  data.usuarios[userIndex].role = role;
  writeData(data);
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