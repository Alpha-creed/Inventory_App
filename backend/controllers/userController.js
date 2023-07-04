const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");


//generate Token
const generateToken = (id)=>{
    return jwt.sign({id},process.env.JWT_SECRET,{expiresIn:"1d"})
}


//Register User
const registerUser = asyncHandler( async (req,res) => {
    const {name,email,password} = req.body


    //Validation
    if(!name || !email || !password){
        res.status(400)
        throw new Error("Please fill in all required fields")
    }
    if(password.length <6){
        res.status(400)
        throw new Error("Password must be up to 6 characters")
    }

    //check if user already exist
    const userExists = await User.findOne({email})

    if(userExists){
        res.status(400)
        throw new Error("Email has already been registered")
    }


    //create new User
    const user = await User.create({
        name,
        email,
        password,
    });

    //Generate Token
    const token = generateToken(user._id)


    //send HTTP-only cookie
    res.cookie("token",token,{
        path:"/",
        httpOnly:true,
        expires:new Date(Date.now() + 1000 * 86400), //1 day
        sameSite:"none",
        secure:true
    })

    if(user){
        const {_id,name,email,photo,phone,bio} = user
        res.status(201).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token
        })
    }else{
        res.status(400)
        throw new Error("Invalid user data")
    }  
});


//login User
const loginUser = asyncHandler(async(req,res)=>{
    const {email,password} = req.body

    //validate Request
    if(!email || !password){
        res.status(400);
        throw new Error("Please add email and password")
    }
    //Check if user exists
    const user = await User.findOne({email})

    if(!user){
        res.status(400);
        throw new Error("User not found,Please signup");
    }

    //User exists ,check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password,user.password)

    //Generate Token
    const token = generateToken(user._id);

    //send HTTP-only cookie
    res.cookie("token",token,{
        path:"/",
        httpOnly:true,
        expires:new Date(Date.now() + 1000 * 86400),//1day
        sameSite:"none",
        secure:true,
    })

    if(user && passwordIsCorrect){
        const {_id,name,email,photo,phone,bio} = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token,
        });
    }else{
        res.status(400);
        throw new Error("Invalid email or password");
    }
});

const logout = asyncHandler(async(req,res)=>{
    res.cookie("token","",{
        path:"/",
        httpOnly:true,
        expires:new Date(0),
        sameSite:"none",
        secure:true,
    });
    return res.status(200).json({message:"Successfully Logged Out"});
});

//Get User Data
const getUser = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id)

    if(user){
        const {_id,name,email,photo,phone,bio} = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
        });
    }else{
        res.status(400)
        throw new Error("User not found") ;
    }
});

//Get Login Status
const loggedInStat = asyncHandler(async(req,res)=>{
    
    const token = req.cookies.token;
    if(!token){
        return res.json(false)
    }

    //Verify token
    const verified = jwt.verify(token,process.env.JWT_SECRET);
    if(verified){
        return res.json(true)
    }
    return res.json(false)
})

//Update user
const updateUser = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id)

    if(user){
        const {_id,name,email,photo,phone,bio} =user;
        user.email = email;
        user.name = req.body.name||name;
        user.photo = req.body.photo||photo;
        user.phone = req.body.phone||phone;
        user.bio = req.body.bio||bio;

        const updateUser = await user.save()
        res.status(200).json({
            _id:updateUser._id,
            name:updateUser.name,
            email:updateUser.email,
            photo:updateUser.photo,
            bio:updateUser.bio,
        })
    }
})

const changePassword = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id);
    const {oldPassword,password} = req.body

    //Validate
    if(!user){
        res.status(400)
        throw new Error("User not found ,please signup");
    }

    if(!oldPassword || !password){
        res.status(400);
        throw new Error("Please add old and new password");
    }

    //check if oldpassword matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldPassword,
        user.password)
    
    //Save new password
    if(user && passwordIsCorrect){
        user.password = password
        await user.save()
        res.status(200).send("Password change successful");
    }else{
        res.status(400)
        throw new Error("Old password is incorrect");
    }

})

module.exports = {
    registerUser,
    loginUser,
    logout,
    getUser,
    loggedInStat,
    updateUser,
    changePassword,
}