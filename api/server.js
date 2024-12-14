const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex");
const db = require("../data/db-config"); // Make sure the knex instance is correctly set up
const authRouter = require("./auth/auth-router");
const usersRouter = require("./users/users-router");
const { restricted } = require("./auth/auth-middleware");

const server = express();

// Middleware
server.use(helmet()); // Helps secure your app by setting various HTTP headers
server.use(express.json()); // Middleware to parse JSON request bodies
server.use(cors()); // CORS middleware to handle cross-origin requests

// Create the session store instance
const store = KnexSessionStore(session);

// Set up session middleware
server.use(
  session({
    name: "chocolatechip", // Name of the cookie
    secret: "your-secret-key", // A secret to sign the session ID cookie
    resave: false, // Don't save session if it wasn't modified
    saveUninitialized: false, // Don't create a session until something is stored in it
    cookie: {
      httpOnly: true, // Ensures the cookie is not accessible via JavaScript
      secure: process.env.NODE_ENV === 'production', // Use secure cookies only in production (i.e., when using HTTPS)
      maxAge: 1000 * 60 * 60, // Session expires in 1 hour (adjust as needed)
    },
    store: new store({
      knex: db, // Your Knex instance from db-config.js
      tablename: "sessions", // Optional: Specify a table name for storing session data
    }),
  })
);

// Routes
server.use("/api/auth", authRouter); // Authentication routes
server.use("/api/users", usersRouter); // Users routes

// Apply the restricted middleware to the users route
server.use("/api/users", restricted, usersRouter);

// Basic API route for checking server status
server.get("/", (req, res) => {
  res.json({ api: "up" });
});

// Error handling middleware
server.use((err, req, res, next) => { // eslint-disable-line
  console.error(err); // Log error details for debugging
  if (!err.status) {
    err.status = 500; // Default to 500 if no status is set
  }
  res.status(err.status).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;