const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./models/User");

const app = express();
app.use(express.json());

// Подключаемся к базе данных
mongoose.connect("mongodb://localhost/mydatabase", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Генерация JWT-токена
function generateToken(user) {
  return jwt.sign({ _id: user._id, email: user.email }, "secret-key", {
    expiresIn: "1h",
  });
}

// Проверка валидности JWT-токена
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ message: "JWT token is missing" });
  }

  jwt.verify(token, "secret-key", (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid JWT token" });
    }
    req.user = decoded;
    next();
  });
}

// Регистрация пользователя
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ email, password: hashedPassword });
    await user.save();

    const token = generateToken(user);

    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Аутентификация пользователя
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = generateToken(user);

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Защищенный маршрут
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ userId: req.user._id, email: req.user.email });
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
