const express = require("express");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error conectando a BD:', err);
    } else {
        console.log(' Base de datos SQLite conectada/creada');
        crearTablas();
    }
});

function crearTablas() {

    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nombre TEXT,
            fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tareas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            texto TEXT NOT NULL,
            completada BOOLEAN DEFAULT 0,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creando tablas:', err);
        } else {
            console.log(' Tablas creadas/verificadas');
        }
    });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        secret: "supersecreto",
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 1000 * 60 * 60 }
    })
);

app.use(express.static(path.join(__dirname)));

function requireLogin(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: "No autenticado" });
    next();
}

app.post("/register", async (req, res) => {
    const { email, password, nombre } = req.body;
    if (!email || !password) return res.status(400).send("Faltan datos");

    try {
        const hash = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO usuarios (email, password, nombre) VALUES (?, ?, ?)',
            [email, hash, nombre || email],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).send("Usuario ya existe");
                    }
                    return res.status(500).send("Error en BD");
                }
                
                req.session.userId = this.lastID;
                req.session.userEmail = email;
                res.redirect("/index.html");
            }
        );
    } catch (error) {
        res.status(500).send("Error del servidor");
    }
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send("Faltan datos");

    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).send("Error en BD");
        if (!user) return res.status(401).send("Usuario/contraseña inválido");

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).send("Usuario/contraseña inválido");

        req.session.userId = user.id;
        req.session.userEmail = user.email;
        res.redirect("/index.html");
    });
});

app.get("/tasks", requireLogin, (req, res) => {
    db.all(
        'SELECT * FROM tareas WHERE usuario_id = ? ORDER BY fecha_creacion DESC',
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.post("/tasks", requireLogin, (req, res) => {
    const texto = (req.body.texto || "").trim();
    if (!texto) return res.status(400).json({ error: "Texto vacío" });

    db.run(
        'INSERT INTO tareas (usuario_id, texto) VALUES (?, ?)',
        [req.session.userId, texto],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            res.status(201).json({
                id: this.lastID,
                texto: texto,
                completada: 0,
                usuario_id: req.session.userId
            });
        }
    );
});

app.put("/tasks/:id", requireLogin, (req, res) => {
    const id = req.params.id;
    const updates = [];
    const values = [];

    if (typeof req.body.completada !== "undefined") {
        updates.push("completada = ?");
        values.push(req.body.completada ? 1 : 0);
    }
    if (typeof req.body.texto === "string" && req.body.texto.trim()) {
        updates.push("texto = ?");
        values.push(req.body.texto.trim());
    }

    if (updates.length === 0) {
        return res.status(400).json({ error: "No hay datos para actualizar" });
    }

    values.push(id, req.session.userId);
    
    db.run(
        `UPDATE tareas SET ${updates.join(', ')} WHERE id = ? AND usuario_id = ?`,
        values,
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: "Tarea no encontrada" });
            
            db.get('SELECT * FROM tareas WHERE id = ?', [id], (err, tarea) => {
                res.json(tarea);
            });
        }
    );
});

app.delete("/tasks/:id", requireLogin, (req, res) => {
    const id = req.params.id;
    
    db.run(
        'DELETE FROM tareas WHERE id = ? AND usuario_id = ?',
        [id, req.session.userId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: "Tarea no encontrada" });
            res.status(204).end();
        }
    );
});

app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});
app.get("/", (req, res) => {
    if (req.session.userId) return res.redirect("/index.html");
    res.redirect("/login.html");
});

app.listen(PORT, () => {
    console.log(`\n🚀 Servidor iniciado en http://localhost:${PORT}`);
    console.log(`📁 Archivos estáticos servidos desde: ${__dirname}`);
    console.log(`💾 Base de datos: database.db (se creará automáticamente)\n`);
});