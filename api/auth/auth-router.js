// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express");
const bcrypt = require("bcryptjs"); // For password hashing
const db = require("../../data/db-config");
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require("../auth/auth-middleware");

const router = express.Router();

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
/**
  1. [POST] /api/auth/register
  { "username": "sue", "password": "1234" }

  
*/
router.post("/register", checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const [id] = await db("users").insert({ username, password: hashedPassword });
    const user = await db("users").where("user_id", id).first();

    res.status(200).json({
      user_id: user.user_id,
      username: user.username,
    });
  } catch (err) {
    console.error("Registration error:", err);
    next(err);
  }
});
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
/**
  2. [POST] /api/auth/login
  { "username": "sue", "password": "1234" }
*/
router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const [user] = await db("users").where({ username });

    if (!user) {
      console.log("User not found:", username);  // Debugging step
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password valid:", isPasswordValid);  // Debugging step

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    req.session.user = { user_id: user.user_id, username: user.username };
    res.status(200).json({ message: `Welcome ${user.username}!` });
  } catch (err) {
    next(err);
  }
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
/**
  3. [GET] /api/auth/logout
*/

router.get("/logout", (req, res) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "Failed to log out" });
      }
      res.status(200).json({ message: "logged out" });
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});


module.exports = router;
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
