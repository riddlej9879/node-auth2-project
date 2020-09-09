const jwt = require("jsonwebtoken");
const usersModel = require("../users/users-model");

module.exports = async function (req, res, next) {
  try {
    const decoded = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
    console.log(decoded);
    const user = await usersModel.findById(decoded.userID);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch (err) {
    console.log(err);
    res.status(401).json({ message: "Authentication error" });
  }
};
