require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { addDays, addHours, addMinutes, addWeeks } = require("date-fns");

// Convertir la variable de entorno en un objeto JSON
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// Inicializar Firebase Admin
try {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id, // Se obtiene directamente del archivo .env
    });
    console.log('Firebase Admin SDK inicializado correctamente');
} catch (error) {
    console.error('Error al inicializar Firebase Admin SDK:', error.message);
    process.exit(1);
}

const db = admin.firestore();
const auth = admin.auth();
const app = express();

// Middleware
app.use(express.json());

const corsOptions = {
  origin: ['http://localhost:3000', 'https://task-manager-frontend-c9pe.onrender.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));




app.post('/register', async (req, res) => {
    const { email, username, password } = req.body; 

    if (!email || !username || !password) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    try {
        // Verificar si el correo electrónico ya está registrado
        const emailExists = await db.collection('users').where("email", "==", email).get();
        if (!emailExists.empty) {
            return res.status(400).json({ error: 'El correo electrónico ya está en uso' });
        }

        // Verificar si el nombre de usuario ya está registrado
        const usernameExists = await db.collection('users').where("username", "==", username).get();
        if (!usernameExists.empty) {
            return res.status(400).json({ error: 'El nombre de usuario ya está en uso' });
        }

        // Si no existe, proceder con la creación del usuario
        const userRecord = await auth.createUser({
            email,
            password,
            displayName: username
        });

        // Encriptar la contraseña antes de guardarla en Firestore
        const hashedPassword = await bcrypt.hash(password, 10);

        // Definir rol automáticamente (admin si el correo es especial, usuario normal si no)
        let rol = 2; // Usuario normal
        const adminEmails = ["admin@example.com", "otroadmin@empresa.com"];
        const masterEmails = ["master@example.com", "otromaster@empresa.com"];
        if (adminEmails.includes(email)) {
            rol = 1;
        } else if (masterEmails.includes(email)) {
            rol = 3;
        }

        await db.collection('users').doc(userRecord.uid).set({
            uid: userRecord.uid,
            email,
            username,
            password: hashedPassword,  
            rol, 
            last_login: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message: 'Usuario registrado exitosamente y guardado en Firestore',
            userId: userRecord.uid
        });

    } catch (error) {
        console.error('Error en la creación del usuario:', error);
        res.status(500).json({ error: error.message });
    }
});


// Generar Token JWT con datos del usuario
const generateToken = (user) => {
    return jwt.sign(
        {
            uid: user.uid,
            username: user.username,
            email: user.email,
            rol: user.rol,
        },
        'secretKey', // Usa una clave secreta segura (idealmente desde variables de entorno)
        { expiresIn: '10m' }
    );
};

// Login de usuario
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    try {
        const userQuery = await db.collection('users').where('username', '==', username.trim()).get();

        if (userQuery.empty) {
            return res.status(400).json({ error: 'Usuario no encontrado' });
        }

        const userData = userQuery.docs[0].data();
        const userId = userQuery.docs[0].id;

        // Verificación de la contraseña con bcrypt
        const validPassword = await bcrypt.compare(password, userData.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        // Generar el token con la información completa del usuario
        const token = generateToken({
            uid: userId,
            username: userData.username,
            email: userData.email,
            rol: userData.rol,
        });

        // Imprimir los datos del usuario en la consola 
        console.log('✅ Usuario ha iniciado sesión:', {
            uid: userId,
            username: userData.username,
            email: userData.email,
            rol: userData.rol,
            token: token,
        });

        res.json({
            message: 'Login exitoso',
            token,
            userId,
            user: {
                uid: userId,
                username: userData.username,
                email: userData.email,
                rol: userData.rol,
                password: userData.password,
            }
        });

    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ error: error.message });
    }
});


//Esta es la parte de las TASK

// Middleware para verificar el token
const authenticateUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado' });
    }

    const token = authHeader.split(" ")[1]; // Extraer el token real
    if (!token) {
        return res.status(401).json({ error: 'Formato de token inválido' });
    }

    try {
        const decoded = jwt.verify(token, 'secretKey'); // Asegúrate de que 'secretKey' sea la correcta
        req.user = decoded;
        next();
    } catch (error) {
        console.error("Error de autenticación:", error);
        return res.status(403).json({ error: 'Token inválido o expirado' });
    }
};

// 📌 **Crear una nueva tarea (solo para usuarios autenticados)**
app.post("/tasks", authenticateUser, async (req, res) => {
    const { nameTask, descripcion, categoria, estatus, time, timeUnit } = req.body; // Ahora el frontend también debe enviar 'time' y 'timeUnit'

    const userId = req.user.uid; // Se obtiene del token

    if (!nameTask || !estatus) {
        return res.status(400).json({ error: "Los campos nameTask y estatus son obligatorios" });
    }

    let deadline;
    try {
        // Calcular la fecha de vencimiento en base al tiempo proporcionado
        const currentTime = new Date();

        if (time && timeUnit) {
            switch (timeUnit) {
                case 'days':
                    deadline = addDays(currentTime, parseInt(time));
                    break;
                case 'hours':
                    deadline = addHours(currentTime, parseInt(time));
                    break;
                case 'minutes':
                    deadline = addMinutes(currentTime, parseInt(time));
                    break;
                case 'weeks':
                    deadline = addWeeks(currentTime, parseInt(time));
                    break;
                default:
                    return res.status(400).json({ error: "Unidad de tiempo inválida" });
            }
        } else {
            // Si no se especifica tiempo, usar el timestamp del servidor
            deadline = admin.firestore.FieldValue.serverTimestamp();
        }

        const newTask = {
            userId,
            nameTask,
            descripcion: descripcion || "",
            categoria: categoria || "",
            estatus,
            deadLine: deadline,
        };

        const taskRef = await db.collection("task").add(newTask);

        res.status(201).json({ message: "Tarea creada exitosamente", taskId: taskRef.id });
    } catch (error) {
        console.error("Error al crear la tarea:", error);
        res.status(500).json({ error: error.message });
    }
});

// 📌 **Obtener todas las tareas del usuario autenticado**
app.get("/tasks", authenticateUser, async (req, res) => {
    const userId = req.user.uid;

    try {
        const tasksSnapshot = await db.collection("task").where("userId", "==", userId).get();
        const tasks = tasksSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

        res.json(tasks);
    } catch (error) {
        console.error("Error al obtener tareas:", error);
        res.status(500).json({ error: error.message });
    }
});
// 📌 **Actualizar una tarea (solo el usuario que la creó)**
app.put("/tasks/:taskId", authenticateUser, async (req, res) => {
    const { taskId } = req.params;
    const { nameTask, descripcion, categoria, estatus, deadLine } = req.body;
    const userId = req.user.uid;
  
    try {
      const taskRef = db.collection("task").doc(taskId);
      const taskDoc = await taskRef.get();
  
      if (!taskDoc.exists) {
        return res.status(404).json({ error: "Tarea no encontrada" });
      }
  
      // Verificamos que el usuario sea el dueño de la tarea
      if (taskDoc.data().userId !== userId) {
        return res.status(403).json({ error: "No tienes permiso para editar esta tarea" });
      }
  
      // Creamos el objeto que contiene solo los campos que han sido proporcionados
      const updateData = {};
  
      if (nameTask) updateData.nameTask = nameTask;
      if (descripcion) updateData.descripcion = descripcion;
      if (categoria) updateData.categoria = categoria;
      if (estatus) updateData.estatus = estatus;
      if (deadLine) updateData.deadLine = admin.firestore.Timestamp.fromDate(new Date(deadLine));
  
      updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp(); // Actualizamos la fecha de modificación
  
      // Actualizamos los datos en Firestore
      await taskRef.update(updateData);
  
      res.json({ message: "Tarea actualizada correctamente" });
    } catch (error) {
      console.error("Error al actualizar tarea:", error);
      res.status(500).json({ error: error.message });
    }
  });

// 📌 **Eliminar una tarea (solo el usuario que la creó)**
app.delete("/tasks/:taskId", authenticateUser, async (req, res) => {
    const { taskId } = req.params;
    const userId = req.user.uid;

    // Verificar si taskId está definido
    if (!taskId) {
        console.error("❌ Error: No se proporcionó taskId en la URL.");
        return res.status(400).json({ error: "Se requiere un ID de tarea válido" });
    }

    console.log("Intentando eliminar tarea con ID:", taskId);
    console.log("Usuario autenticado:", userId);

    try {
        const taskRef = db.collection("task").doc(taskId);
        const taskDoc = await taskRef.get();

        if (!taskDoc.exists) {
            console.log("⚠️ Tarea no encontrada en la base de datos.");
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        console.log("Tarea encontrada:", taskDoc.data());

        if (taskDoc.data().userId !== userId) {
            console.log("⛔ Usuario no autorizado para eliminar esta tarea.");
            return res.status(403).json({ error: "No tienes permiso para eliminar esta tarea" });
        }

        await taskRef.delete();
        console.log("✅ Tarea eliminada correctamente.");
        res.json({ message: "Tarea eliminada correctamente" });
    } catch (error) {
        console.error("❌ Error al eliminar tarea:", error);
        res.status(500).json({ error: error.message });
    }
});

// 📌 **Obtener los grupos según el rol del usuario**
app.get("/groups", authenticateUser, async (req, res) => {
    const userId = req.user.uid;
    const userRole = req.user.rol;

    try {
        let groupsSnapshot;
        if (userRole === 1) {  // Si es un admin
            groupsSnapshot = await db.collection("groups").where("createdBy", "==", userId).get();
        } else {  // Si es un usuario normal
            groupsSnapshot = await db.collection("groups").where("members", "array-contains", userId).get();
        }

        if (groupsSnapshot.empty) {
            return res.status(200).json([]);
        }
        
        const groups = groupsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(groups);
    } catch (error) {
        console.error("❌ Error al obtener grupos:", error);
        res.status(500).json({ error: "Hubo un problema al obtener los grupos. Intenta de nuevo más tarde." });
    }
});

// 📌 Crear un grupo (Solo administradores)
app.post("/groups", authenticateUser, async (req, res) => {
    const { name, members } = req.body;
    const userId = req.user.uid;

    try {
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists || userDoc.data().rol !== 1) { 
            return res.status(403).json({ error: "No tienes permiso para crear grupos o asignar tareas" });
        }
        
        // Verificar si ya existe un grupo con el mismo nombre
        const groupsRef = db.collection("groups");
        const snapshot = await groupsRef.where("name", "==", name).get();
        
        if (!snapshot.empty) {
            return res.status(400).json({ error: "Ya existe un grupo con este nombre" });
        }
        
        const newGroup = {
            name,
            createdBy: userId,
            members,
            tasks: {},
            status: "Activo",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        const groupRef = await groupsRef.add(newGroup);

        // Obtener el documento recién creado para incluir el nombre y otros datos
        const groupDoc = await groupRef.get();
        const groupData = groupDoc.data();

        res.json({
            message: "Grupo creado",
            id: groupRef.id,
            name: groupData.name,  // Incluye el nombre del grupo en la respuesta
            status: groupData.status,  // Incluye el estado si lo necesitas
            members: groupData.members, // Y otros campos si es necesario
        });

    } catch (error) {
        console.error("Error al crear grupo:", error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/users', async (req, res) => {
    try {
        // Obtener la referencia a la colección 'users' en Firebase Firestore
        const usersSnapshot = await admin.firestore().collection('users').get();

        // Mapear los documentos a un array de usuarios
        const users = usersSnapshot.docs.map(doc => {
            return { id: doc.id, ...doc.data() };  // Asegúrate de enviar la data correctamente
        });

        // Responder con los usuarios obtenidos
        res.json(users);
    } catch (error) {
        console.error('Error al obtener usuarios desde Firebase:', error);
        res.status(500).json({ error: 'Error al obtener los usuarios' });
    }
});

// 📌 Asignar una tarea a un grupo (Solo administradores)
// Ruta para asignar una tarea a un grupo
app.post("/groups/:groupId/tasks", async (req, res) => {
    try {
        const { title, description, dueDate, assignedTo } = req.body;
        const { groupId } = req.params;

        if (!title || !description || !dueDate || !assignedTo) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc();
        await taskRef.set({
            title,
            description,
            dueDate: admin.firestore.Timestamp.fromDate(new Date(dueDate)),
            assignedTo,
            status: "pendiente",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        res.status(201).json({ message: "Tarea asignada correctamente", taskId: taskRef.id });
    } catch (error) {
        console.error("Error al asignar tarea:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});


// 📌 Obtener tareas de un grupo
app.get("/groups/:groupId/tasks", authenticateUser, async (req, res) => {
    const { groupId } = req.params;

    try {
        const tasksSnapshot = await db.collection("groups").doc(groupId).collection("tasks").get();

        if (tasksSnapshot.empty) {
            return res.status(200).json([]);
        }

        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(tasks);
    } catch (error) {
        console.error("❌ Error al obtener tareas:", error);
        res.status(500).json({ error: "Hubo un problema al obtener las tareas. Intenta de nuevo más tarde." });
    }
});

// 📌 Actualizar estado de la tarea
app.patch("/groups/:groupId/tasks/:taskId", async (req, res) => {
    const { groupId, taskId } = req.params;
    const { status, updatedBy } = req.body;  // Extraemos `updatedBy` del cuerpo de la solicitud

    if (!status || !updatedBy) {
        return res.status(400).json({ error: "El estado de la tarea y el usuario que actualiza son obligatorios" });
    }

    try {
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);

        // Verificar si la tarea existe
        const taskDoc = await taskRef.get();
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        // Actualizar el estado de la tarea y el usuario que la actualizó
        await taskRef.update({ 
            status, 
            updatedBy  // Agregamos el campo `updatedBy` al documento de la tarea
        });

        res.status(200).json({ message: "Estado de la tarea actualizado correctamente" });
    } catch (error) {
        console.error("❌ Error al actualizar estado de tarea:", error);
        res.status(500).json({ error: "Hubo un problema al actualizar el estado de la tarea. Intenta de nuevo más tarde." });
    }
});


// 📌 **Eliminar un grupo (solo administradores)**
app.delete("/groups/:groupId", authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const userId = req.user.uid;
    console.log("Intentando eliminar el grupo con ID:", groupId);
    console.log("Usuario autenticado con ID:", userId);

    try {
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.log("El usuario no existe en la base de datos.");
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        console.log("Rol del usuario:", userDoc.data().rol);
        if (userDoc.data().rol !== 1) {
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();

        if (!groupDoc.exists) {
            console.log("El grupo no existe en la base de datos.");
            return res.status(404).json({ error: "Grupo no encontrado" });
        }

        console.log("Grupo encontrado, procediendo a eliminar...");
        await groupRef.delete();
        console.log("Grupo eliminado correctamente.");
        res.json({ message: "Grupo eliminado correctamente" });

    } catch (error) {
        console.error("Error al eliminar grupo:", error);
        res.status(500).json({ error: error.message });
    }
});


// 📌 **Eliminar un usuario (solo el Master puede eliminar usuarios)**
app.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Referencia al documento en Firestore
        const userRef = admin.firestore().collection('users').doc(id);

        // Verificar si el usuario existe antes de eliminarlo
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Eliminar el usuario
        await userRef.delete();
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar el usuario:', error);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

// 📌 **Agregar un usuario a un grupo existente**
// Add this endpoint to your backend app.js file

// 📌 **Obtener miembros de un grupo**
app.get('/groups/:groupId/users', authenticateUser, async (req, res) => {
  const { groupId } = req.params;
  
  try {
    // Verificar que el grupo exista
    const groupRef = db.collection("groups").doc(groupId);
    const groupDoc = await groupRef.get();
    
    if (!groupDoc.exists) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    // Obtener los miembros del grupo
    const groupData = groupDoc.data();
    const memberIds = groupData.members || [];
    
    if (memberIds.length === 0) {
      return res.json([]);
    }
    
    // Obtener los datos de cada miembro
    const members = [];
    for (const memberId of memberIds) {
      const userRef = db.collection("users").doc(memberId);
      const userDoc = await userRef.get();
      
      if (userDoc.exists) {
        const userData = userDoc.data();
        // Excluir la contraseña y otros datos sensibles
        const { password, ...userInfo } = userData;
        members.push({
          id: userDoc.id,
          ...userInfo
        });
      }
    }
    
    res.json(members);
    
  } catch (error) {
    console.error('Error al obtener miembros del grupo:', error);
    res.status(500).json({ error: error.message });
  }
});

// 📌 Asignar una tarea a un grupo (Solo administradores)
// Ruta para asignar una tarea a un grupo
app.post("/groups/:groupId/tasks", async (req, res) => {
    try {
        const { title, description, dueDate, assignedTo } = req.body;
        const { groupId } = req.params;

        if (!title || !description || !dueDate || !assignedTo) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc();
        await taskRef.set({
            title,
            description,
            dueDate: admin.firestore.Timestamp.fromDate(new Date(dueDate)),
            assignedTo,
            status: "pendiente",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        res.status(201).json({ message: "Tarea asignada correctamente", taskId: taskRef.id });
    } catch (error) {
        console.error("Error al asignar tarea:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});


// 📌 Obtener tareas de un grupo
app.get("/groups/:groupId/tasks", authenticateUser, async (req, res) => {
    const { groupId } = req.params;

    try {
        const tasksSnapshot = await db.collection("groups").doc(groupId).collection("tasks").get();

        if (tasksSnapshot.empty) {
            return res.status(200).json([]);
        }

        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(tasks);
    } catch (error) {
        console.error("❌ Error al obtener tareas:", error);
        res.status(500).json({ error: "Hubo un problema al obtener las tareas. Intenta de nuevo más tarde." });
    }
});

// 📌 Actualizar estado de la tarea
app.patch("/groups/:groupId/tasks/:taskId", async (req, res) => {
    const { groupId, taskId } = req.params;
    const { status, updatedBy } = req.body;  // Extraemos `updatedBy` del cuerpo de la solicitud

    if (!status || !updatedBy) {
        return res.status(400).json({ error: "El estado de la tarea y el usuario que actualiza son obligatorios" });
    }

    try {
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);

        // Verificar si la tarea existe
        const taskDoc = await taskRef.get();
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        // Actualizar el estado de la tarea y el usuario que la actualizó
        await taskRef.update({ 
            status, 
            updatedBy  // Agregamos el campo `updatedBy` al documento de la tarea
        });

        res.status(200).json({ message: "Estado de la tarea actualizado correctamente" });
    } catch (error) {
        console.error("❌ Error al actualizar estado de tarea:", error);
        res.status(500).json({ error: "Hubo un problema al actualizar el estado de la tarea. Intenta de nuevo más tarde." });
    }
});


// 📌 **Eliminar un grupo (solo administradores)**
app.delete("/groups/:groupId", authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const userId = req.user.uid;
    console.log("Intentando eliminar el grupo con ID:", groupId);
    console.log("Usuario autenticado con ID:", userId);

    try {
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.log("El usuario no existe en la base de datos.");
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        console.log("Rol del usuario:", userDoc.data().rol);
        if (userDoc.data().rol !== 1) {
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();

        if (!groupDoc.exists) {
            console.log("El grupo no existe en la base de datos.");
            return res.status(404).json({ error: "Grupo no encontrado" });
        }

        console.log("Grupo encontrado, procediendo a eliminar...");
        await groupRef.delete();
        console.log("Grupo eliminado correctamente.");
        res.json({ message: "Grupo eliminado correctamente" });

    } catch (error) {
        console.error("Error al eliminar grupo:", error);
        res.status(500).json({ error: error.message });
    }
});


// 📌 **Eliminar un usuario (solo el Master puede eliminar usuarios)**
app.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Referencia al documento en Firestore
        const userRef = admin.firestore().collection('users').doc(id);

        // Verificar si el usuario existe antes de eliminarlo
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Eliminar el usuario
        await userRef.delete();
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar el usuario:', error);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

// 📌 **Agregar un usuario a un grupo existente**
// Add this endpoint to your backend app.js file

// 📌 **Eliminar un usuario de un grupo**
app.delete('/groups/:groupId/users/:userId', authenticateUser, async (req, res) => {
  const { groupId, userId } = req.params;
  const currentUserId = req.user.uid;
  
  try {
    // Verificar que el usuario actual sea administrador
    const userRef = db.collection("users").doc(currentUserId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || userDoc.data().rol !== 1) {
      return res.status(403).json({ error: 'No tienes permiso para eliminar usuarios de grupos' });
    }
    
    // Verificar que el grupo exista
    const groupRef = db.collection("groups").doc(groupId);
    const groupDoc = await groupRef.get();
    
    if (!groupDoc.exists) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    // Obtener los miembros actuales del grupo
    const groupData = groupDoc.data();
    const currentMembers = groupData.members || [];
    
    // Verificar si el usuario es miembro del grupo
    if (!currentMembers.includes(userId)) {
      return res.status(400).json({ error: 'El usuario no es miembro de este grupo' });
    }
    
    // Eliminar el usuario del grupo
    const updatedMembers = currentMembers.filter(id => id !== userId);
    await groupRef.update({ 
      members: updatedMembers,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Usuario ${userId} eliminado del grupo ${groupId}`);
    res.status(200).json({ 
      message: 'Usuario eliminado del grupo exitosamente',
      groupId,
      userId
    });
    
  } catch (error) {
    console.error('Error al eliminar usuario del grupo:', error);
    res.status(500).json({ error: error.message });
  }
});

// 📌 Asignar una tarea a un grupo (Solo administradores)
// Ruta para asignar una tarea a un grupo
app.post("/groups/:groupId/tasks", async (req, res) => {
    try {
        const { title, description, dueDate, assignedTo } = req.body;
        const { groupId } = req.params;

        if (!title || !description || !dueDate || !assignedTo) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc();
        await taskRef.set({
            title,
            description,
            dueDate: admin.firestore.Timestamp.fromDate(new Date(dueDate)),
            assignedTo,
            status: "pendiente",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        res.status(201).json({ message: "Tarea asignada correctamente", taskId: taskRef.id });
    } catch (error) {
        console.error("Error al asignar tarea:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});


// 📌 Obtener tareas de un grupo
app.get("/groups/:groupId/tasks", authenticateUser, async (req, res) => {
    const { groupId } = req.params;

    try {
        const tasksSnapshot = await db.collection("groups").doc(groupId).collection("tasks").get();

        if (tasksSnapshot.empty) {
            return res.status(200).json([]);
        }

        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(tasks);
    } catch (error) {
        console.error("❌ Error al obtener tareas:", error);
        res.status(500).json({ error: "Hubo un problema al obtener las tareas. Intenta de nuevo más tarde." });
    }
});

// 📌 Actualizar estado de la tarea
app.patch("/groups/:groupId/tasks/:taskId", async (req, res) => {
    const { groupId, taskId } = req.params;
    const { status, updatedBy } = req.body;  // Extraemos `updatedBy` del cuerpo de la solicitud

    if (!status || !updatedBy) {
        return res.status(400).json({ error: "El estado de la tarea y el usuario que actualiza son obligatorios" });
    }

    try {
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);

        // Verificar si la tarea existe
        const taskDoc = await taskRef.get();
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        // Actualizar el estado de la tarea y el usuario que la actualizó
        await taskRef.update({ 
            status, 
            updatedBy  // Agregamos el campo `updatedBy` al documento de la tarea
        });

        res.status(200).json({ message: "Estado de la tarea actualizado correctamente" });
    } catch (error) {
        console.error("❌ Error al actualizar estado de tarea:", error);
        res.status(500).json({ error: "Hubo un problema al actualizar el estado de la tarea. Intenta de nuevo más tarde." });
    }
});


// 📌 **Eliminar un grupo (solo administradores)**
app.delete("/groups/:groupId", authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const userId = req.user.uid;
    console.log("Intentando eliminar el grupo con ID:", groupId);
    console.log("Usuario autenticado con ID:", userId);

    try {
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.log("El usuario no existe en la base de datos.");
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        console.log("Rol del usuario:", userDoc.data().rol);
        if (userDoc.data().rol !== 1) {
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();

        if (!groupDoc.exists) {
            console.log("El grupo no existe en la base de datos.");
            return res.status(404).json({ error: "Grupo no encontrado" });
        }

        console.log("Grupo encontrado, procediendo a eliminar...");
        await groupRef.delete();
        console.log("Grupo eliminado correctamente.");
        res.json({ message: "Grupo eliminado correctamente" });

    } catch (error) {
        console.error("Error al eliminar grupo:", error);
        res.status(500).json({ error: error.message });
    }
});


// 📌 **Eliminar un usuario (solo el Master puede eliminar usuarios)**
app.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Referencia al documento en Firestore
        const userRef = admin.firestore().collection('users').doc(id);

        // Verificar si el usuario existe antes de eliminarlo
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Eliminar el usuario
        await userRef.delete();
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar el usuario:', error);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

// 📌 **Agregar un usuario a un grupo existente**
// Add this endpoint to your backend app.js file

// 📌 **Eliminar un usuario de un grupo**
app.delete('/groups/:groupId/users/:userId', authenticateUser, async (req, res) => {
  const { groupId, userId } = req.params;
  const currentUserId = req.user.uid;
  
  try {
    // Verificar que el usuario actual sea administrador
    const userRef = db.collection("users").doc(currentUserId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || userDoc.data().rol !== 1) {
      return res.status(403).json({ error: 'No tienes permiso para eliminar usuarios de grupos' });
    }
    
    // Verificar que el grupo exista
    const groupRef = db.collection("groups").doc(groupId);
    const groupDoc = await groupRef.get();
    
    if (!groupDoc.exists) {
      return res.status(404).json({ error: 'Grupo no encontrado' });
    }
    
    // Obtener los miembros actuales del grupo
    const groupData = groupDoc.data();
    const currentMembers = groupData.members || [];
    
    // Verificar si el usuario es miembro del grupo
    if (!currentMembers.includes(userId)) {
      return res.status(400).json({ error: 'El usuario no es miembro de este grupo' });
    }
    
    // Eliminar el usuario del grupo
    const updatedMembers = currentMembers.filter(id => id !== userId);
    await groupRef.update({ 
      members: updatedMembers,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(`✅ Usuario ${userId} eliminado del grupo ${groupId}`);
    res.status(200).json({ 
      message: 'Usuario eliminado del grupo exitosamente',
      groupId,
      userId
    });
    
  } catch (error) {
    console.error('Error al eliminar usuario del grupo:', error);
    res.status(500).json({ error: error.message });
  }
});

// 📌 Asignar una tarea a un grupo (Solo administradores)
// Ruta para asignar una tarea a un grupo
app.post("/groups/:groupId/tasks", async (req, res) => {
    try {
        const { title, description, dueDate, assignedTo } = req.body;
        const { groupId } = req.params;

        if (!title || !description || !dueDate || !assignedTo) {
            return res.status(400).json({ error: "Todos los campos son obligatorios" });
        }

        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc();
        await taskRef.set({
            title,
            description,
            dueDate: admin.firestore.Timestamp.fromDate(new Date(dueDate)),
            assignedTo,
            status: "pendiente",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        res.status(201).json({ message: "Tarea asignada correctamente", taskId: taskRef.id });
    } catch (error) {
        console.error("Error al asignar tarea:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});


// 📌 Obtener tareas de un grupo
app.get("/groups/:groupId/tasks", authenticateUser, async (req, res) => {
    const { groupId } = req.params;

    try {
        const tasksSnapshot = await db.collection("groups").doc(groupId).collection("tasks").get();

        if (tasksSnapshot.empty) {
            return res.status(200).json([]);
        }

        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(tasks);
    } catch (error) {
        console.error("❌ Error al obtener tareas:", error);
        res.status(500).json({ error: "Hubo un problema al obtener las tareas. Intenta de nuevo más tarde." });
    }
});

// 📌 Actualizar estado de la tarea
app.patch("/groups/:groupId/tasks/:taskId", async (req, res) => {
    const { groupId, taskId } = req.params;
    const { status, updatedBy } = req.body;  // Extraemos `updatedBy` del cuerpo de la solicitud

    if (!status || !updatedBy) {
        return res.status(400).json({ error: "El estado de la tarea y el usuario que actualiza son obligatorios" });
    }

    try {
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);

        // Verificar si la tarea existe
        const taskDoc = await taskRef.get();
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        // Actualizar el estado de la tarea y el usuario que la actualizó
        await taskRef.update({ 
            status, 
            updatedBy  // Agregamos el campo `updatedBy` al documento de la tarea
        });

        res.status(200).json({ message: "Estado de la tarea actualizado correctamente" });
    } catch (error) {
        console.error("❌ Error al actualizar estado de tarea:", error);
        res.status(500).json({ error: "Hubo un problema al actualizar el estado de la tarea. Intenta de nuevo más tarde." });
    }
});


// 📌 **Eliminar un grupo (solo administradores)**
app.delete("/groups/:groupId", authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const userId = req.user.uid;
    console.log("Intentando eliminar el grupo con ID:", groupId);
    console.log("Usuario autenticado con ID:", userId);

    try {
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.log("El usuario no existe en la base de datos.");
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        console.log("Rol del usuario:", userDoc.data().rol);
        if (userDoc.data().rol !== 1) {
            return res.status(403).json({ error: "No tienes permiso para eliminar grupos" });
        }

        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();

        if (!groupDoc.exists) {
            console.log("El grupo no existe en la base de datos.");
            return res.status(404).json({ error: "Grupo no encontrado" });
        }

        console.log("Grupo encontrado, procediendo a eliminar...");
        await groupRef.delete();
        console.log("Grupo eliminado correctamente.");
        res.json({ message: "Grupo eliminado correctamente" });

    } catch (error) {
        console.error("Error al eliminar grupo:", error);
        res.status(500).json({ error: error.message });
    }
});


// 📌 **Eliminar un usuario (solo el Master puede eliminar usuarios)**
app.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Referencia al documento en Firestore
        const userRef = admin.firestore().collection('users').doc(id);

        // Verificar si el usuario existe antes de eliminarlo
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Eliminar el usuario
        await userRef.delete();
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar el usuario:', error);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

// 📌 **Agregar un usuario a un grupo existente**
app.post('/groups/:groupId/users', authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const { userId } = req.body;
    const currentUserId = req.user.uid;
    
    if (!userId) {
        return res.status(400).json({ error: 'Se requiere el ID del usuario' });
    }
    
    try {
        // Verificar que el usuario actual sea administrador
        const userRef = db.collection("users").doc(currentUserId);
        const userDoc = await userRef.get();
        
        if (!userDoc.exists || userDoc.data().rol !== 1) {
            return res.status(403).json({ error: 'No tienes permiso para agregar usuarios a grupos' });
        }
        
        // Verificar que el grupo exista
        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();
        
        if (!groupDoc.exists) {
            return res.status(404).json({ error: 'Grupo no encontrado' });
        }
        
        // Verificar que el usuario a agregar exista
        const targetUserRef = db.collection("users").doc(userId);
        const targetUserDoc = await targetUserRef.get();
        
        if (!targetUserDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        
        // Obtener los miembros actuales del grupo
        const groupData = groupDoc.data();
        const currentMembers = groupData.members || [];
        
        // Verificar si el usuario ya es miembro del grupo
        if (currentMembers.includes(userId)) {
            return res.status(400).json({ error: 'El usuario ya es miembro de este grupo' });
        }
        
        // Agregar el usuario al grupo
        const updatedMembers = [...currentMembers, userId];
        await groupRef.update({ 
            members: updatedMembers,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        console.log(`✅ Usuario ${userId} agregado al grupo ${groupId}`);
        res.status(200).json({ 
            message: 'Usuario agregado al grupo exitosamente',
            groupId,
            userId
        });
        
    } catch (error) {
        console.error('Error al agregar usuario al grupo:', error);
        res.status(500).json({ error: error.message });
    }
});

// 📌 Actualizar estado de la tarea
app.put("/groups/:groupId/tasks/:taskId", async (req, res) => {
    const { groupId, taskId } = req.params;
    const { status, updatedBy } = req.body;  // Extraemos `updatedBy` del cuerpo de la solicitud

    if (!status || !updatedBy) {
        return res.status(400).json({ error: "El estado de la tarea y el usuario que actualiza son obligatorios" });
    }

    try {
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);

        // Verificar si la tarea existe
        const taskDoc = await taskRef.get();
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }

        // Actualizar el estado de la tarea y el usuario que la actualizó
        await taskRef.update({ 
            status, 
            updatedBy  // Agregamos el campo `updatedBy` al documento de la tarea
        });

        res.status(200).json({ message: "Estado de la tarea actualizado correctamente" });
    } catch (error) {
        console.error("❌ Error al actualizar estado de tarea:", error);
        res.status(500).json({ error: "Hubo un problema al actualizar el estado de la tarea. Intenta de nuevo más tarde." });
    }
});
// 📌 **Actualizar un usuario por UID**
app.put('/users/:uid', async (req, res) => {
    try {
        const { uid } = req.params;
        const { username, email, rol } = req.body;

        // Referencia al documento en Firestore
        const userRef = admin.firestore().collection('users').doc(uid);

        // Verificar si el usuario existe antes de actualizarlo
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Actualizar los datos del usuario
        await userRef.update({ username, email, rol });

        res.json({ message: 'Usuario actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar el usuario:', error);
        res.status(500).json({ error: 'Error al actualizar el usuario' });
    }
});
 
// 📌 **Eliminar una tarea de un grupo**
app.delete("/groups/:groupId/tasks/:taskId", authenticateUser, async (req, res) => {
    const { groupId, taskId } = req.params;
    const userId = req.user.uid;
    
    try {
        // Verificar que el grupo exista
        const groupRef = db.collection("groups").doc(groupId);
        const groupDoc = await groupRef.get();
        
        if (!groupDoc.exists) {
            return res.status(404).json({ error: "Grupo no encontrado" });
        }
        
        // Verificar que la tarea exista
        const taskRef = db.collection("groups").doc(groupId).collection("tasks").doc(taskId);
        const taskDoc = await taskRef.get();
        
        if (!taskDoc.exists) {
            return res.status(404).json({ error: "Tarea no encontrada" });
        }
        
        // Verificar permisos (solo administradores o el creador de la tarea pueden eliminarla)
        const userRef = db.collection("users").doc(userId);
        const userDoc = await userRef.get();
        
        if (!userDoc.exists) {
            return res.status(403).json({ error: "Usuario no encontrado" });
        }
        
        const isAdmin = userDoc.data().rol === 1;
        const groupData = groupDoc.data();
        
        if (!isAdmin && groupData.createdBy !== userId) {
            return res.status(403).json({ error: "No tienes permiso para eliminar esta tarea" });
        }
        
        // Eliminar la tarea
        await taskRef.delete();
        
        console.log(`✅ Tarea ${taskId} eliminada del grupo ${groupId}`);
        res.status(200).json({ 
            message: "Tarea eliminada correctamente",
            groupId,
            taskId
        });
        
    } catch (error) {
        console.error("Error al eliminar tarea:", error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
