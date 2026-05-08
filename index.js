const express = require("express")
const bcrypt = require("bcryptjs")
const app = express()
const env = require("dotenv").config()
const mongoose = require("mongoose")
const jwt = require("jsonwebtoken") 
const MONGO_URL = process.env.MONGO_URL
const passport = require(`passport`) 
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const session = require(`express-session`)
app.use(express.json())
app.use(session({secret:"cats"}))
app.use(passport.initialize());
app.use(passport.session())

mongoose.connect(MONGO_URL).then(() => {
    console.log(`Database is connected successfully`)
    app.listen(3000, () => {
        console.log(`Server listening on port 3000`)
    })
}).catch((err) => {
    console.log(`Server Error`, err)
})

function generateAccesToken(existingUser) {
    return jwt.sign(
        { userName: existingUser.userName },
        process.env.ACCES_TOKEN_SECRET,
        { expiresIn: "15m" }
    )
}

//!This should be in database in production
let refreshTokens = []

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]
    if (token == null) return res.sendStatus(401)
    jwt.verify(token, process.env.ACCES_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/protected-route",
    passReqToCallback   : true
  },
  async function(request, accessToken, refreshToken, profile, done) {
    try {
        let user = await User.findOne({ 
            $or: [
                { googleId: profile.id }, 
                { userName: profile.email }
            ] 
        });

        if (!user) {
            user = new User({
                googleId: profile.id,
                userName: profile.email,
                password: "google-auth-user" 
            });
            await user.save();
        } else {
            if (!user.googleId) {
                user.googleId = profile.id;
                await user.save();
            }
        }

        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}
));
passport.serializeUser(function(user,done){
    done(null,user)
})
passport.deserializeUser(function(user,done){
    done(null,user)
})

const userSchema = new mongoose.Schema({
    userName: { type: String, required: true, unique: true },
    password: { type: String, required: function() { return !this.googleId; } },
    googleId: { type: String, unique: true, sparse: true }
});
const User = mongoose.model("User", userSchema)

app.post("/token", (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accesToken = generateAccesToken({ userName: user.userName })
        res.json({ accesToken })
    })
})

app.post("/register", async (req, res) => {
    try {
        const { userName, password } = req.body
        const existingUser = await User.findOne({ userName })
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" })
        }
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)
        const newUser = new User({ userName, password: hashedPassword })
        await newUser.save()
        return res.send("User registered successfully.")
    } catch (err) {
        console.log(err)
        return res.status(500).send("Server error")
    }
})
app.get("/auth/google", passport.authenticate("google", { 
    scope: ["email", "profile"] 
}));
app.get("/",(req,res)=>{
    res.send(`<a href="http://localhost:3000/auth/google">Login with google</a>`)
})
app.post("/login", async (req, res) => {
    try {
        const { userName, password } = req.body
        const existingUser = await User.findOne({ userName })
        if (!existingUser) {
            return res.status(401).send("Username or password is incorrect")
        }
        const isMatch = await bcrypt.compare(password, existingUser.password)
        if (!isMatch) {
            return res.status(401).send("Username or password is incorrect")
        }
        const accesToken = generateAccesToken(existingUser)
        const refreshToken = jwt.sign(
            { userName: existingUser.userName },
            process.env.REFRESH_TOKEN_SECRET
        )
        refreshTokens.push(refreshToken)
        return res.status(200).json({ message: "Login Successfully", accesToken, refreshToken })
    } catch (err) {
        console.log(err)
        return res.status(500).send("Server error")
    }
})

app.delete("/logout", (req, res) => {
    const { token } = req.body
    refreshTokens = refreshTokens.filter(t => t !== token)
    res.sendStatus(204)
})

app.get("/protected-route", 
    passport.authenticate("google", { session: false }), 
    (req, res) => {
        const accesToken = generateAccesToken(req.user);
        const refreshToken = jwt.sign(
            { userName: req.user.userName },
            process.env.REFRESH_TOKEN_SECRET
        );
        refreshTokens.push(refreshToken);
        res.json({ 
            message: "Google Login Successful", 
            accesToken, 
            refreshToken,
            user: req.user 
        });
    }
);
app.get("/jwt" , authenticateToken,(req,res)=>{
    res.send(`Acces granted`)
})