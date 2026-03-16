const User= require("../models/User")
const bcrypt= require("bcryptjs")
const jwt = require("jsonwebtoken");

const{
    generateAccessToken,
    generateRefreshToken

}= require("../utils/generateToken");

exports.register = async(req,res)=>{

  try{
    const{email,password} =req.body;
    console.log(email)
    const userExist = await User.findOne({email});

    if(userExist){
        return res.status(400).json({message: "User already exists"});//unauthorised
    }

    const hashedPassword = await bcrypt.hash(password,10);
    // res.send(req.body)
    const user = await User.create({
        email,
        password: hashedPassword,
    });

    res.status(201).json({
        message: "User registered",//Success
        userId: user._id,
    });



  }
  catch(error){
    res.status(500).json({error: error.message});//internal server error
  }


};

//Login

exports.login= async(req,res)=>{

    try{
        const{email,password}=req.body;
        const user = await User.findOne({email});

        if(!user){
            return res.status(400).json({message: "Invaid credentials"})
        }

        const isMatch= await bcrypt.compare(password,user.password);

        if(!isMatch){
            return res.status(400).json({message: "Invalid credentials"});
        }
        const accessToken=generateAccessToken(user._id);
        const refreshToken=generateRefreshToken(user._id);

        user.refreshToken=refreshToken;
        await user.save();
        res.json({
            accessToken,
            refreshToken,
        });
    }
    catch(error){
        res.status(500).json({error: error.message});

    }
}

//Refresh Token

exports.refreshToken = async(req,res)=>{

    try{
        const{refreshToken} =req.body;
        if(!refreshToken){

            return res.status(401).json({message: "No refresh Token"});
        }
        const user =await User.findOne({refreshToken});

        if(!user){
            return res.status(403).json({message: "Invalid refrehs token"});
        }

        jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET,
            (err, decoded)=>{
                if(err){
                    return res.status(403).json({message: "Token expired"});
                }
            

            const newAccessToken = generateAccessToken(user._id);
            res.json({
                accessToken: newAccessToken,
            });
        }
        )

    }
    catch(error){

        res.status(500).json({error: error.message})

    }
}