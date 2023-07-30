import express from "express";
import path from 'path';
import cookieParser from "cookie-parser";
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();

//mongo database
mongoose.connect('mongodb://127.0.0.1:27017',{
    dbName:'backend',
}).then(()=>console.log('mongodb is connected')).catch(err=>console.log("something went wrong in connection of mongo",err));
const userSchema = new mongoose.Schema({
    name:String,
    email: String,
    password:String
});

const User = mongoose.model('user',userSchema);

//middleware
app.use(express.static(path.join(path.resolve(),'public')));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

app.set('view engine','ejs');


const isAuthenticated = async(req,res,next) => {
    const {token} = req.cookies;
    console.log('token value',token)
    if(token){
        const decoded = jwt.verify(token,"lkdjkghfdfsfghjk");
        console.log('decoded',decoded)
        req.user = await User.findById(decoded._id)
        next();
    }else{
        res.render('login');
    }
}

app.get('/',isAuthenticated, (req,res)=>{
    console.log(req.user);
    res.render('logout',{name:req.user.name});
})

app.get('/register', (req,res)=>{
    res.render('register');
})

app.post('/register',async(req,res)=>{
    const {name,email,password} = req.body;
    let user = await User.findOne({email});
    if(user)return res.redirect('/');

    const passGen = await bcrypt.hash(password,10);
    user = await User.create({name,email,password:passGen});
    const token = jwt.sign({_id:user._id},'lkdjkghfdfsfghjk');
    res.cookie('token',token,{
        httpOnly:true,
        expires:new Date(Date.now() + 10*60*1000)
    })
    res.redirect("/");
});

app.post('/login',async(req,res)=>{
    const {email,password} = req.body;
    let user = await User.findOne({email});
    if(!user){
        return res.redirect('/register')
    };

    const isMatched = await bcrypt.compare(password,user.password)
    if(!isMatched) return res.render('login',{message:'incorrect password',email:email})
    const token = jwt.sign({_id:user._id},"lkdjkghfdfsfghjk");
    res.cookie('token',token,{
        httpOnly:true,
        expires:new Date(Date.now()+ 10*60*1000)
    })
    res.redirect('/')
});

app.post('/logout',(req,res)=>{
    res.cookie('token',null,{
        httpOnly:true,
        expires:new Date(Date.now())
    })
    res.redirect('/');
})



app.listen(5000,()=>{
    console.log("server is running on 5000")
})