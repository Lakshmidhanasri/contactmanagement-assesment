const jwt = require("jsonwebtoken");
const User = require("../models/User");

const authMiddleware = async (req, res, next) => {
  // Extract token from the Authorization header
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).send("Access denied"); // No token provided

  try {
    // Verify the token using the secret stored in environment variables
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Find the user based on the ID extracted from the verified token
    req.user = await User.findById(verified.userId);
    if (!req.user) return res.status(404).send("User not found"); // Ensure user exists

    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    res.status(400).send("Invalid token"); // Invalid token
  }
};

module.exports = authMiddleware;
