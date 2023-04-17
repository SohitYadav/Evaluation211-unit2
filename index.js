const express=require('express');
const {userModel}=require('./models/userModel');
const {blogModel}=require('./models/blogmodel');
const {blacklistModel}=require('./models/blackListmodel')
const app=express();
const bcrypt=require('bcrypt');
const bodyParser=require('body-parser');
const jwt=require('jsonwebtoken');
const {connection}=require('./db')
require('dotenv').config();
app.use(bodyParser.json());


app.post('/auth/register',async (req,res)=>{
    try{
        const {name,email,password}=req.body;
        const hashPass=await bcrypt.hash(password,10);
        const newUser=new userModel({name,email,password:hashPass});
        await newUser.save();
        res.send("User Registered");
    }
    catch(err){
        res.send(err)
    }
    
})

app.post('/auth/login',async (req,res)=>{
   try{
    const {email,password}=req.body;
    const user=await userModel.findOne({email});
    if(!user){
        res.send("User not Found");
    }

    const match=await bcrypt.compare(password,user.password);
    if(!user){
        res.send("Invalid password");
    }
    const token=jwt.sign({userId:user._id},process.env.Secret,{expiresIn:'1m'});

    const refreshToken=jwt.sign({userId:user._id},process.env.refreshKey,{expiresIn:'3m'});

    res.send({
        token,refreshToken
    })
   }
   catch(err){
    res.send(err)
   }
    
})

// middleware

const verifyToken=(req,res,next)=>{
const token=req.headers.authorization;
const tokenPre=blacklistModel.findOne(token);

if(tokenPre){
    res.send("Unauthorized");
}
if(!token){
    res.send("No token")
}

jwt.verify(token,process.env.Secret,(err,decoded)=>{
    if(err){
        res.send("Authentication fail");
    }
    next();
})
}


// middleware for refresh token

const verifyRefreshToken=(req,res,next)=>{
    const refreshToken=req.body.refreshToken;

    if(!refreshToken){
        res.send("No token")
    }
    
    jwt.verify(token,process.env.refreshKey,(err,decoded)=>{
        if(err){
            res.send("Authentication failed for Refresh Token");
        }
        next();
    })
}


// new blog

app.post('/blogs',verifyToken,async (req,res)=>{
    try{
        const {title,content}=req.body;
        const authorId=req.userId;
    
        const newBlog=new blogModel({title,content,author:authorId});
        await newBlog.save();
        res.send("Blog Created");
    }
    catch(err){
        res.send(err);
    }
    
})

app.get('/getBlogs',verifyToken,async (req,res)=>{

    try{
        const blog=await blogModel.find();
        res.send(blog);
    }
    catch(err){
        res.send(err.message);
    }
})


//update blog

app.put('/blogs/:id',verifyToken,async (req,res)=>{
    try{
        const {title,content}=req.body;
        const authorId=req.userId;
        const blogId=req.params.id;
    
        const blog=await blogModel.findById(blogId);
    
        if(!blog){
            res.send("Blog not Found");
        }
    
        blog.title=title,
        blog.content=content;
        await blogModel.save();
    
        res.send("Blog Updated");
    }
    catch(err){
        res.send(err)
    }
    
})


//delete blog

app.delete('/blogs/:id',verifyToken,async (req,res)=>{
    try{
        const {title,content}=req.body;
        const authorId=req.userId;
        const blogId=req.params.id;
    
        const blog=await blogModel.findById(blogId);
    
        if(!blog){
            res.send("Blog not Found");
        }
    
        blog.title=title,
        blog.content=content;
        await blogModel.remove();
    
        res.send("Blog Deleted");
    }
    catch(err){
        res.send(err);
    }
    
})


//moderator endpoint

app.delete('/blogs/:id/moderator',verifyToken,async (req,res)=>{

    try{
        const blogId=req.params.id;

        const blog=await blogModel.findById(blogId);
        if(!blog){
            res.send("Blog not Found");
        }
    
        if(req.userRole!=='Moderator'){
            res.send("Not Authorized")
        }
    
        await blogModel.remove();
        res.send("Blog Deleted by Moderator");
    }
    catch(err){
        res.send(err)
    }
   
})


//blaclist 

app.post('/logout',verifyToken,async (req,res)=>{
    try{
        const token=req.headers.authorization.split(' ')[1];

        const Blacklisted=new blacklistModel({token});
        await Blacklisted.save();
        
        req.send("Logout Success");
    }
    catch(err){
        res.send(err)
    }

})


app.listen(6200,async()=>{
    try{
        await connection
        console.log("Connected");
    }
    catch(err){
        console.log(err);
    }
})