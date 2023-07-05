const express = require("express");
const { registerUser, loginUser, logout, getUser, loggedInStat, updateUser, changePassword, forgotPassword, resetPassword } = require("../controllers/userController");
const protect = require("../middleware/authMiddleware");
const router = express.Router();


router.post("/register",registerUser)
router.post("/login",loginUser);
router.get("/logout",logout);
router.get("/getuser",protect,getUser);
router.get("/loggedIn",loggedInStat);
router.patch("/updateuser",protect,updateUser);
router.patch("/changepassword",protect,changePassword);
router.post("/forgotpassword",forgotPassword);
router.put("/resetpassword/:resetToken",resetPassword)


module.exports = router; 