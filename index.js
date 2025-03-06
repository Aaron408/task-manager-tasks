const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

require("dotenv").config();

const serviceAccount = {
  type: process.env.TYPE,
  project_id: process.env.PROJECT_ID,
  private_key_id: process.env.PRIVATE_KEY_ID,
  private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL,
  client_id: process.env.CLIENT_ID,
  auth_uri: process.env.AUTH_URI,
  token_uri: process.env.TOKEN_URI,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.CLIENT_CERT_URL,
  universe_domain: process.env.UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

const verifyToken = (allowedRoles) => async (req, res, next) => {
  console.log("Iniciando verificación de token");
  const token = req.headers["authorization"]?.split(" ")[1];
  console.log("Headers", req.headers);

  if (!token) {
    console.log("Token no proporcionado");
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  console.log("Token recibido:", token);

  try {
    const db = admin.firestore();
    const tokensRef = db.collection("tokensVerification");
    const tokenSnapshot = await tokensRef.where("token", "==", token).get();

    if (tokenSnapshot.empty) {
      console.log("Token inválido o no encontrado");
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    const tokenData = tokenSnapshot.docs[0].data();
    console.log("Datos del token:", tokenData);

    const now = new Date();
    if (new Date(tokenData.expiresAt) < now) {
      console.log("Token expirado");
      return res.status(401).json({ message: "Token ha expirado." });
    }

    //Obtener el usuario desde la colección users
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef.doc(tokenData.userId).get();

    if (!userSnapshot.exists) {
      console.log("Usuario no encontrado");
      return res.status(401).json({ message: "Usuario no encontrado." });
    }

    const userData = userSnapshot.data();
    console.log("Datos del usuario:", userData);

    if (!allowedRoles.includes(userData.role)) {
      console.log("Permisos insuficientes. Rol del usuario:", userData.role);
      return res
        .status(403)
        .json({ message: "Acceso denegado. Permisos insuficientes." });
    }

    console.log("Token verificado exitosamente");
    req.user = { id: tokenData.userId, role: userData.role };
    next();
  } catch (error) {
    console.error("Error en la verificación del token:", error);
    res
      .status(500)
      .json({ message: "Error al verificar el token.", error: error.message });
  }
};

app.get("/", (req, res) => {
  res.send("Tasks service running!");
});

//Obtener todas las tareas del usuario autenticado
app.get("/tasks", verifyToken(["admin", "mortal"]), async (req, res) => {
  try {
    const tasksRef = db.collection("tasks");
    const tasksSnapshot = await tasksRef
      .where("userId", "==", req.user.id)
      .get();

    if (tasksSnapshot.empty) {
      return res.status(404).json({ message: "No se encontraron tareas" });
    }

    const tasks = tasksSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
    return res.status(200).json({ tasks });
  } catch (error) {
    console.error("Error al obtener las tareas:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

app.post("/add-tasks", verifyToken(["admin", "mortal"]), async (req, res) => {
  const { name, description, dueDate, status, category } = req.body;

  try {
    const newTask = {
      name,
      description,
      dueDate,
      status,
      category,
      userId: req.user.id,
      createdAt: new Date(),
    };

    const tasksRef = db.collection("tasks");
    await tasksRef.add(newTask);

    return res
      .status(201)
      .json({ message: "Tarea añadida exitosamente", task: newTask });
  } catch (error) {
    console.error("Error al añadir la tarea:", error);
    return res
      .status(500)
      .json({ message: "Error en el servidor", error: error.message });
  }
});

app.patch(
  "/tasks/:taskId",
  verifyToken(["admin", "mortal"]),
  async (req, res) => {
    try {
      const { taskId } = req.params;
      const { status } = req.body;
      const userId = req.user.id;

      // Verificar si la tarea existe y pertenece al usuario
      const taskRef = db.collection("tasks").doc(taskId);
      const task = await taskRef.get();

      if (!task.exists) {
        return res.status(404).json({ message: "Tarea no encontrada" });
      }

      const taskData = task.data();

      if (taskData.userId !== userId && req.user.role !== "admin") {
        return res
          .status(403)
          .json({ message: "No tienes permiso para actualizar esta tarea" });
      }

      // Actualizar el estado de la tarea
      await taskRef.update({ status });

      res
        .status(200)
        .json({ message: "Estado de la tarea actualizado con éxito" });
    } catch (error) {
      console.error("Error al actualizar el estado de la tarea:", error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  }
);

app.post("/createGroupTasks", verifyToken(["admin"]), async (req, res) => {
  try {
    const { name, description, category, status, assignedTo, groupId } =
      req.body;
    const createdBy = req.user.id;

    const taskRef = db.collection("tasks");
    const newTask = {
      name,
      description,
      category,
      status,
      assignedTo,
      groupId,
      createdBy,
      createdAt: new Date(),
    };

    const docRef = await taskRef.add(newTask);
    res.status(201).json({ task: { id: docRef.id, ...newTask } });
  } catch (error) {
    console.error("Error al crear la tarea:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

app.get(
  "/groups/:groupId/tasks",
  verifyToken(["admin", "mortal"]),
  async (req, res) => {
    try {
      const { groupId } = req.params;
      const tasksRef = db.collection("tasks");
      const snapshot = await tasksRef.where("groupId", "==", groupId).get();

      if (snapshot.empty) {
        return res
          .status(200)
          .json({ tasks: [], userRole: req.user.role, userId: req.user.id });
      }

      const tasks = [];
      snapshot.forEach((doc) => {
        tasks.push({ id: doc.id, ...doc.data() });
      });

      res
        .status(200)
        .json({ tasks, userRole: req.user.role, userId: req.user.id });
    } catch (error) {
      console.error("Error al obtener tareas:", error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  }
);

app.patch(
  "/dropTasks/:taskId",
  verifyToken(["admin", "mortal"]),
  async (req, res) => {
    try {
      const { taskId } = req.params;
      const { status } = req.body;
      const userId = req.user.id;
      const userRole = req.user.role;

      const taskRef = db.collection("tasks").doc(taskId);
      const taskDoc = await taskRef.get();

      if (!taskDoc.exists) {
        return res.status(404).json({ message: "Tarea no encontrada" });
      }

      const taskData = taskDoc.data();

      //Verificamos que el usuario que hace la petición tenga permitido actualizar la tarea
      if (userRole !== "admin" && taskData.assignedTo !== userId) {
        return res
          .status(403)
          .json({ message: "No tienes permiso para actualizar esta tarea" });
      }

      await taskRef.update({ status });

      res.status(200).json({ message: "Tarea actualizada con éxito" });
    } catch (error) {
      console.error("Error al actualizar la tarea:", error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  }
);

const PORT = process.env.TASKS_SERVICE_PORT || 5003;
app.listen(PORT, () => {
  console.log(`Tasks service running on http://localhost:${PORT}`);
});
