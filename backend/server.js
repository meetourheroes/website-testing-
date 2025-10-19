import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import multer from "multer";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const uploadsDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${unique}${ext}`);
  }
});
const upload = multer({ storage });

function signToken(user) {
  return jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: "8h" });
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing authorization" });
  const token = header.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/api/auth/register", async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email & password required" });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name) VALUES ($1,$2,$3) RETURNING id,email,name`,
      [email, hashed, name || null]
    );
    const user = result.rows[0];
    res.json({ user, token: signToken(user) });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") return res.status(400).json({ error: "Email already exists" });
    res.status(500).json({ error: "db error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const q = await pool.query("SELECT id,email,password_hash,name FROM users WHERE email=$1", [email]);
  if (q.rowCount === 0) return res.status(401).json({ error: "Invalid credentials" });
  const u = q.rows[0];
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  const token = signToken(u);
  res.json({ user: { id: u.id, email: u.email, name: u.name }, token });
});

app.post("/api/files/upload", authMiddleware, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "no file" });
  try {
    const q = await pool.query(
      `INSERT INTO files (owner_id, filename_original, filename_stored, mime, size_bytes) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.userId, req.file.originalname, req.file.filename, req.file.mimetype, req.file.size]
    );
    res.json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "db error" });
  }
});

app.get("/api/files", authMiddleware, async (req, res) => {
  const q = await pool.query("SELECT id, filename_original, mime, size_bytes, uploaded_at FROM files WHERE owner_id=$1 ORDER BY uploaded_at DESC", [req.user.userId]);
  res.json(q.rows);
});

app.get("/api/files/:id/download", authMiddleware, async (req, res) => {
  const id = req.params.id;
  const q = await pool.query("SELECT * FROM files WHERE id=$1", [id]);
  if (q.rowCount === 0) return res.status(404).json({ error: "not found" });
  const f = q.rows[0];
  if (f.owner_id !== req.user.userId) return res.status(403).json({ error: "access denied" });
  const filepath = path.join(uploadsDir, f.filename_stored);
  if (!fs.existsSync(filepath)) return res.status(410).json({ error: "file missing" });
  res.download(filepath, f.filename_original);
});

app.delete("/api/files/:id", authMiddleware, async (req, res) => {
  const id = req.params.id;
  const q = await pool.query("SELECT * FROM files WHERE id=$1", [id]);
  if (q.rowCount === 0) return res.status(404).json({ error: "not found" });
  const f = q.rows[0];
  if (f.owner_id !== req.user.userId) return res.status(403).json({ error: "access denied" });
  await pool.query("DELETE FROM files WHERE id=$1", [id]);
  const filepath = path.join(uploadsDir, f.filename_stored);
  try { if (fs.existsSync(filepath)) fs.unlinkSync(filepath); } catch(e){ console.warn("delete file error",e) }
  res.json({ deleted: true });
});

app.post("/api/forms", authMiddleware, async (req, res) => {
  const { name, slug, schema } = req.body;
  if (!name || !slug || !schema) return res.status(400).json({ error: "name slug schema required" });
  try {
    const q = await pool.query(
      `INSERT INTO forms (owner_id,name,slug,schema) VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.userId, name, slug, JSON.stringify(schema)]
    );
    res.json(q.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "db error" });
  }
});

app.get("/api/forms", authMiddleware, async (req, res) => {
  const q = await pool.query("SELECT id,name,slug,schema,created_at FROM forms WHERE owner_id=$1 ORDER BY created_at DESC", [req.user.userId]);
  res.json(q.rows);
});

app.post("/api/forms/:slug/submit", upload.any(), async (req, res) => {
  const slug = req.params.slug;
  const qf = await pool.query("SELECT * FROM forms WHERE slug=$1", [slug]);
  if (qf.rowCount === 0) return res.status(404).json({ error: "form not found" });
  const form = qf.rows[0];
  const data = req.body.data ? JSON.parse(req.body.data) : req.body;
  const savedFiles = [];
  for (const f of req.files || []) {
    const ins = await pool.query(
      `INSERT INTO files (owner_id, filename_original, filename_stored, mime, size_bytes) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [null, f.originalname, f.filename, f.mimetype, f.size]
    );
    savedFiles.push({ file_id: ins.rows[0].id, fieldname: f.fieldname });
  }
  const insert = await pool.query(
    `INSERT INTO form_submissions (form_id, submitter_email, data, files) VALUES ($1,$2,$3,$4) RETURNING *`,
    [form.id, data.email || null, JSON.stringify(data), JSON.stringify(savedFiles)]
  );
  res.json({ success: true, submission: insert.rows[0] });
});

app.get("/api/forms/:id/submissions", authMiddleware, async (req, res) => {
  const formId = req.params.id;
  const f = await pool.query("SELECT owner_id FROM forms WHERE id=$1", [formId]);
  if (f.rowCount === 0) return res.status(404).json({ error: "form not found" });
  if (f.rows[0].owner_id !== req.user.userId) return res.status(403).json({ error: "access denied" });
  const subs = await pool.query("SELECT id, submitter_email, data, files, submitted_at FROM form_submissions WHERE form_id=$1 ORDER BY submitted_at DESC", [formId]);
  res.json(subs.rows);
});

app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
