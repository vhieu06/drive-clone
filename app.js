const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
const db = new sqlite3.Database("database.db");

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));
app.use(session({ secret: "secret", resave: false, saveUninitialized: false }));
app.set("view engine", "ejs");

// Multer setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// DB setup
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT UNIQUE,
    otp TEXT,
    otp_expires_at INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    originalname TEXT,
    user_id INTEGER,
    deleted INTEGER DEFAULT 0
  )`);
});

// Routes
app.get("/", (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  db.all("SELECT * FROM files WHERE user_id = ? AND deleted = 0", [req.session.userId], (err, files) => {
    res.render("dashboard", { files });
  });
});

app.get("/register", (req, res) => res.render("register"));
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hash], err => {
    if (err) return res.send("Tài khoản hoặc email đã tồn tại.");
    res.redirect("/login");
  });
});

app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
  const { identifier, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ? OR email = ?", [identifier, identifier], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send("Thông tin đăng nhập không đúng.");
    }
    req.session.userId = user.id;
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.post("/upload", upload.array("files"), (req, res) => {
  const stmt = db.prepare("INSERT INTO files (filename, originalname, user_id) VALUES (?, ?, ?)");
  req.files.forEach(file => {
    stmt.run(file.filename, file.originalname, req.session.userId);
  });
  stmt.finalize();
  res.redirect("/");
});

app.get("/download/:id", (req, res) => {
  db.get("SELECT * FROM files WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], (err, file) => {
    if (!file) return res.sendStatus(404);
    res.download(path.join(__dirname, "uploads", file.filename), file.originalname);
  });
});

app.post("/delete/:id", (req, res) => {
  db.run("UPDATE files SET deleted = 1 WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId]);
  res.redirect("/");
});

app.get("/trash", (req, res) => {
  db.all("SELECT * FROM files WHERE user_id = ? AND deleted = 1", [req.session.userId], (err, files) => {
    res.render("trash", { files });
  });
});

app.post("/restore/:id", (req, res) => {
  db.run("UPDATE files SET deleted = 0 WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId]);
  res.redirect("/trash");
});

app.post("/permanent-delete/:id", (req, res) => {
  db.get("SELECT * FROM files WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], (err, file) => {
    if (file) {
      fs.unlinkSync(path.join(__dirname, "uploads", file.filename));
      db.run("DELETE FROM files WHERE id = ?", [file.id]);
    }
    res.redirect("/trash");
  });
});
// Hiển thị danh sách file có thể xoá
app.get("/files", (req, res) => {
  const folderPath = path.join(__dirname, "uploads");
  fs.readdir(folderPath, (err, files) => {
    if (err) return res.send("Lỗi khi đọc thư mục.");
    res.render("files", { files });
  });
});

// Xử lý xoá nhiều file
app.post("/delete", (req, res) => {
  const filesToDelete = req.body.files;
  if (!filesToDelete) return res.send("Không có file nào được chọn.");

  const files = Array.isArray(filesToDelete) ? filesToDelete : [filesToDelete];
  const folderPath = path.join(__dirname, "uploads");

  files.forEach(file => {
    const filePath = path.join(folderPath, file);
    fs.unlink(filePath, err => {
      if (err) console.error(`Lỗi khi xoá ${file}:`, err);
    });
  });

  res.redirect("/files");
});
// Forgot password - Gửi OTP
app.get("/forgot", (req, res) => {
  res.render("forgot");
});

app.post("/forgot", (req, res) => {
  const email = req.body.email;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  db.run("UPDATE users SET otp = ?, otp_expires_at = ? WHERE email = ?", [otp, expiresAt, email], function (err) {
    if (err) return res.send("Lỗi khi cập nhật OTP.");
    if (this.changes === 0) return res.send("Email không tồn tại.");
    if (err || this.changes === 0) return res.send("Email không tồn tại.");

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: "your-email@gmail.com",
        pass: "your-app-password",
      },
    });

    const mailOptions = {
      from: "Drive Clone",
      to: email,
      subject: "Mã OTP khôi phục mật khẩu",
      html: `<p>Mã OTP của bạn là: <b>${otp}</b></p><p>Mã này sẽ hết hạn sau 10 phút.</p>`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) return res.send("Lỗi gửi email.");
      req.session.resetEmail = email;
      res.redirect("/verify-otp");
    });
  });
});

app.get("/verify-otp", (req, res) => {
  res.render("verify-otp");
});

app.post("/verify-otp", async (req, res) => {
  const { otp, password } = req.body;
  const email = req.session.resetEmail;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user || user.otp !== otp) return res.send("Mã OTP không đúng.");
    if (Date.now() > user.otp_expires_at) return res.send("Mã OTP đã hết hạn.");

    const hash = await bcrypt.hash(password, 10);
    db.run("UPDATE users SET password = ?, otp = NULL, otp_expires_at = NULL WHERE email = ?", [hash, email], err => {
      if (err) return res.send("Lỗi khi đặt lại mật khẩu.");
      req.session.resetEmail = null;
      res.send("Mật khẩu đã được đặt lại thành công.");
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on http://localhost:${PORT}`));
