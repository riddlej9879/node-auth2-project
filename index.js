// If the .env variables dont load this statement will be needed
// require("dotenv/config")

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const usersRouter = require("./users/users-router");
const cookieParser = require("cookie-parser");

const server = express();
const port = process.env.PORT || 5000;

server.use(helmet());
server.use(cors());
server.use(express.json());
server.use(cookieParser());

server.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: process.env.JWT_SECRET,
  })
);

server.use("/api", usersRouter);

server.use((err, req, res, next) => {
  console.log(err);

  res.status(500).json({ message: "Something went wrong" });
});

server.listen(port, () => {
  console.log(`Running at http://localhost:${port}`);
});
