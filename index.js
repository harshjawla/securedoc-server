require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.static("public"));


app.use(
  cors({
    origin: "https://securedoc-client.vercel.app",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Origin",
      "X-Requested-With",
      "Content-Type",
      "Accept",
      "Authorization",
    ],
    credentials: true,
  })
);
app.use(cookieParser());

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

const MONGO_URL = process.env.MONGODB_URL;

mongoose.connect(MONGO_URL);

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
  },
  password: String,
});

const contentSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
  },
  name: String,
  content: {
    type: String,
    default: "<p>This is your document</p>",
  },
});

const shareSchema = new mongoose.Schema({
  owner: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
  },
  name: String,
  shareWith: {
    type: [String],
    lowercase: true, // This ensures that all strings are converted to lowercase
  },
});

const Share = new mongoose.model("Share", shareSchema);

const Content = new mongoose.model("Content", contentSchema);

const User = new mongoose.model("User", userSchema);
const PORT = 4000;
const saltRounds = 10;

app.get("/", (req, res) => {
  res.send("This is server side");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const alreadyExist = await User.findOne({ username });
    if (alreadyExist) {
      return res.status(400).send("User already exists, please login");
    }

    bcrypt.hash(password, saltRounds, async function (err, hash) {
      if (err) {
        console.log(err);
        return res.status(500).send("Internal Server Error");
      }

      const newUser = await User.create({
        username: username,
        password: hash,
      });

      if (newUser) {
        return res.status(200).send("Successfully Registered");
      } else {
        return res.status(500).send("Failed to create account, please retry");
      }
    });
  } catch (error) {
    console.error("Error registering user:", error);
    return res.status(500).send("Internal Server Error");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("Received login request for username:", username); // Add logging statement
  const user = await User.findOne({ username });
  if (user) {
    bcrypt.compare(password, user.password, function (err, result) {
      if (err) {
        console.error("Error occurred during password comparison:", err); // Add logging statement
        return res.status(500).json({error: err});
      }
      if (result) {
        // Generate JWT token with user ID
        const token = jwt.sign(
          { userId: user.username },
          process.env.JWT_SECRET,
          { expiresIn: "1d" }
        );
        console.log("JWT token generated successfully for user:", user.username); // Add logging statement
        // Set the JWT token as an HTTP-only cookie
        res.cookie("jwt", token, { httpOnly: true, sameSite: "None", secure: true, domain: "securedoc-server.vercel.app" });
        res.status(200).json({ message: "Login successful", token: token });
      } else {
        console.log("Invalid password for user:", user.username); // Add logging statement
        res.status(401).json({ message: "Invalid username or password" });
      }
    });
  } else {
    console.log("User not found:", username); // Add logging statement
    return res.status(400).send("User not registered");
  }
});


app.post("/logout", async (req, res) => {
  try {
    res.cookie("jwt", " ", { httpOnly: true, sameSite: "None", secure: true, domain: "securedoc-server.vercel.app" });
    return res.status(200).send("Logged Out Successfully");
  } catch (error) {
    console.error("Error Logging out", error);
    return res.status(500).send("Internal Server Error");
  }
});

app.get("/authenticate", (req, res) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("Error verifying token:", err);
        return res.status(401).json({ message: "Unauthorized" });
      } else {
        // Token is valid, allow access to protected resource
        return res.status(200).json(decoded);
      }
    });
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
});

app.post("/content", async (req, res) => {
  const { username, content } = req.body;
  const uploadedContent = await Content.create({
    username: username,
    content: content,
  });
  if (uploadedContent) {
    res.status(200).send("Uploaded");
  } else {
    res.status(400).send("Error");
  }
});

app.post("/userfiles", async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ error: "Unauthorized: JWT token missing" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const username = decoded.userId;

    const files = await Content.find({ username });
    res.status(200).json(files);
  } catch (error) {
    console.error("Error fetching user files:", error);
    res.status(500).json({ error: error });
  }
});

app.post("/create", async (req, res) => {
  const { name } = req.body;
  const token = req.cookies.jwt;
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if(err){
      return res.status(500).json({error: err});
    }
    const username = decoded.userId;
    const files = await Content.find({ username, name });
    if (files.length > 0) {
      res.status(401).send("Filename must be unique");
    } else {
      const result = await Content.create({ username, name });
      if (result) {
        res.status(200).json(result);
      }
    }
  });
});

app.post("/update", async (req, res) => {
  try {
    const { name, username, content } = req.body;
    const result = await Content.updateOne(
      { username: username, name: name },
      { $set: { content: content } }
    );
    res.status(200).send("Updated");
  } catch (error) {
    res.status(500).send("Update Failed");
  }
});

app.post("/delete", async (req, res) => {
  const { name } = req.body;
  const token = req.cookies.jwt;
  jwt.verify(token, process.env.JWT_SECRET,  async (err, decoded) => {
    const username = decoded.userId;
    const result = await Content.deleteOne({ username, name });
    if (result) {
      res.status(200).send("Deleted");
    } else {
      res.status(400).send("failed to delete");
    }
  });
});

app.post("/share", async (req, res) => {
  const { name, emails } = req.body;
  const token = req.cookies.jwt;
  jwt.verify(token, process.env.JWT_SECRET,  async (err, decoded) => {
    const username = decoded.userId;
    const alreadyExist = await Share.findOne({ owner: username, name: name });
    if (alreadyExist) {
      const result = await Share.updateOne(
        { owner: username, name: name },
        { $set: { shareWith: emails } }
      );
      if (result) {
        res.status(200).json(decoded);
      } else {
        res.status(400).send("Server Error");
      }
    } else {
      const result = await Share.create({
        owner: username,
        name: name,
        shareWith: emails,
      });

      if (result) {
        res.status(200).json(decoded);
      } else {
        res.status(400).send("Server Error");
      }
    }
  });
});

app.post("/all", async (req, res) => {
  const { username, docName } = req.body;
  const shared = await Share.findOne({ owner: username, name: docName });
  if (shared) {
    const fileExist = await Content.findOne({
      username: username,
      name: docName,
    });
    if (fileExist) {
      res.status(200).json(fileExist);
    } else {
      res.status(404).send("File deleted by user");
    }
  } else {
    res.status(404).send("File not shared or deleted by owner");
  }
});

app.post("/sharing", async (req, res) => {
  const { username, docName } = req.body;
  const token = req.cookies.jwt;
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(500).send("please login");
    }
    const myUserName = decoded.userId;
    const shared = await Share.findOne({ owner: username, name: docName });
    if (shared) {
      const fileExist = await Content.findOne({
        username: username,
        name: docName,
      });
      if (fileExist) {
        const emailExist = shared.shareWith.includes(myUserName);
        if (emailExist) {
          res.status(200).json(fileExist);
        } else {
          res.status(400).send("File is not shared with you");
        }
      } else {
        res.status(404).send("File deleted by user");
      }
    } else {
      res.status(404).send("File not shared or deleted by owner");
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on PORT: ${PORT}`);
});

module.exports = app;
