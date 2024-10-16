("use strict");
const express = require('express');
const { Pool } = require('pg'); 
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

//const SECRET_KEY = process.env.SECRET_KEY;
//const secretKey = crypto.randomBytes(32).toString('hex');
//console.log(`Your generated SECRET_KEY is: ${secretKey}`);

const app = express();
app.set('trust proxy', 1); // λέει στο Express ότι βρίσκεται πίσω από έναν proxy και ότι μπορεί να εμπιστεύεται την κεφαλίδα X-Forwarded-For για να αναγνωρίζει τη διεύθυνση IP του χρήστη.
app.use(express.json());
app.use(cookieParser());
dotenv.config();

app.use(
    helmet({
        contentSecurityPolicy: {
            useDefaults: true,
            directives: {
                "default-src": ["'self'"],
                "img-src": ["'self'", "data:", "https:"],
                "script-src": ["'self'", "'unsafe-inline'"],
                "style-src": ["'self'", "'unsafe-inline'"],
            },
        },
        dnsPrefetchControl: { allow: false },
        expectCt: { maxAge: 86400 },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        ieNoOpen: true,
        noSniff: true,
        permittedCrossDomainPolicies: { policy: 'none' },
        referrerPolicy: { policy: 'no-referrer' },
        xssFilter: true,
    })
);

const tokenBlackList = [];

// Συνάρτηση για κρυπτογράφηση
function encryptToken(token) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(process.env.SECRET_KEY, 'salt', 32);
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Συνδυάζουμε το IV με το κρυπτογραφημένο token
}

// Συνάρτηση για αποκρυπτογράφηση
function decryptToken(encryptedToken) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(process.env.SECRET_KEY, 'salt', 32);
    const parts = encryptedToken.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Ρύθμιση του rate limiter για το login endpoint
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Χρονικό παράθυρο 15 λεπτών
    max: 5, // Μέγιστο 5 αιτήματα ανά IP για το χρονικό παράθυρο
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
    standardHeaders: true, // Επιστρέφει πληροφορίες rate limit στα headers `RateLimit-*`
    legacyHeaders: false, // Απενεργοποιεί τα παλιά headers `X-RateLimit-*`
});

const pool = new Pool({
    user: process.env.DATABASE_USER,
    host: process.env.DATABASE_HOST,
    database: process.env.DATABASE_NAME,
    password: process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
});

function authenticateToken(req,res,next){
    const encrypted = req.cookies['auth_token'];
    if(!encrypted) return res.status(401).json({message:'No cookies stored'});

    try{
        const token = decryptToken(encrypted);

        if(tokenBlackList.includes(token)){
            return res.status(403).json({message:'Token is in blacklist'});
        }

        jwt.verify(token,process.env.SECRET_KEY,(err,user)=>{
            if(err)return res.status(403).json({message:'Cant verify token'});
            req.user = user;
            next();
        })
    }catch(err){
        console.log(`Error with encrypted token: ${err}`);
        return res.sendStatus(403);
    }
};

app.get('/data',authenticateToken ,async (req,res)=>{
    if(req.user.role != 'admin')return res.status(403).json({message: 'No authenticate user'});
    try{
        const result = await pool.query('SELECT * FROM users');
        res.json(result.rows);
    }catch (err){
        console.log(err);
        res.status(500).json({message: 'Server Error'})
    }
})

app.post('/login', loginLimiter, async (req,res)=>{
    const {email,password} = req.body;
    try{
        const result = await pool.query('SELECT * FROM users WHERE email = $1',[email]);
        const user = result.rows[0];
        
        if(user && (await bcrypt.compare(password, user.password))){
            const token = jwt.sign({id:user.id, email:user.email, role:user.role},process.env.SECRET_KEY,{expiresIn:'1h'});
            const encrypted = encryptToken(token);

            res.cookie('auth_token',encrypted,{
                httpOnly:true,
                secure: true,
                sameSite: 'None',
                maxAge: 60 * 60 * 1000,
            })

            res.json( {message:'Connected'});
        }else{
            res.status(401).json({ message: 'Invalid username or password'});
        }
    }catch(err){
        console.log(err);
        res.status(500).json({message:'SERVER ERROR'});

    }
})

app.post('/register', async (req,res)=>{
    const {email , password, role} = req.body;
    try{
        const hashedPassword = await bcrypt.hash(password,10);
        const result = await pool.query('INSERT INTO users (email,password,role) VALUES ($1,$2,$3) RETURNING *',[email,hashedPassword,role || 'user']);
        const user = result.rows[0];
        res.status(201).json({message:'User registered succesfully', user: user.id}) 
    }catch(err){
        console.log(err);
        res.status(500).json({message: 'Server Error from register', message2:role})
    }
})

app.post('/logout',(req,res)=>{
    let token = req.cookies['auth_token'];
    if(!token) return res.status(401).json({message:'No token'});
    token = decryptToken(token);
    tokenBlackList.push(token);

    res.clearCookie('auth_token',{
        httpOnly: true,
        secure: true,
    })
    res.json({message:'Logout succesfully'});
})

app.listen(process.env.PORT, () => {
    console.log(`Server is running on https://api2.ubser04.gr`);
});