// server.js
// server.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

dotenv.config();

// --- App setup ---
const app = express();
app.use(express.json());

// --- CORS setup ---
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
app.use(cors({
  origin: FRONTEND_URL,       // allow frontend URL
  methods: ["GET", "POST"],   // allowed methods
  credentials: true           // allow cookies / auth headers
}));

// --- MongoDB connection ---
mongoose.connect(process.env.MONGO_URI, {
  autoIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ Mongo connection error:", err);
    process.exit(1);
  });

// --- Models ---
const { Schema } = mongoose;

const UserSchema = new Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  avatarUrl: String,
  lastSeen: Date
}, { timestamps: true });
const User = mongoose.model("User", UserSchema);

const MessageSchema = new Schema({
  sender: { type: Schema.Types.ObjectId, ref: "User" },
  receiver: { type: Schema.Types.ObjectId, ref: "User" },
  text: String,
  roomId: String,
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", MessageSchema);

// --- Auth helpers ---
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

function generateToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing token" });
  const token = auth.split(" ")[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.userId = data.id;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Auth Routes ---
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, lastSeen: new Date() });
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = generateToken(user);
    user.lastSeen = new Date();
    await user.save();

    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Users and Rooms ---
app.post("/api/create-room", authMiddleware, (req, res) => {
  const roomId = uuidv4();
  const link = `${FRONTEND_URL}/chat/${roomId}`;
  res.json({ roomId, link });
});

app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const users = await User.find({}, "name email lastSeen");
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Chat API ---
app.get("/api/messages/:receiverId", authMiddleware, async (req, res) => {
  try {
    const { receiverId } = req.params;
    const messages = await Message.find({
      $or: [
        { sender: req.userId, receiver: receiverId },
        { sender: receiverId, receiver: req.userId }
      ]
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Socket.IO setup ---
const PORT = process.env.PORT || 5000;
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: FRONTEND_URL, methods: ["GET", "POST"], credentials: true }
});

io.on("connection", (socket) => {
  console.log("⚡ User connected:", socket.id);

  socket.on("join_room", ({ roomId, userId }) => {
    socket.join(roomId);
    console.log(`User ${userId} joined room ${roomId}`);
    socket.to(roomId).emit("user_joined", { userId });
  });

  socket.on("send_message_room", async ({ roomId, sender, text }) => {
    const message = await Message.create({ sender, text, roomId });
    io.to(roomId).emit("receive_message_room", message);
  });

  socket.on("disconnect", () => console.log("❌ User disconnected:", socket.id));
});

// --- Health check ---
app.get("/", (req, res) => res.send("✅ Chat backend is live!"));

// --- Start server ---
server.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
