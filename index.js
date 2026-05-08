require("dotenv").config()
const express = require("express")
const bcrypt = require("bcryptjs")
const mongoose = require("mongoose")
const jwt = require("jsonwebtoken")
const passport = require("passport")
const GoogleStrategy = require("passport-google-oauth2").Strategy
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const joi = require("joi")
const sanitize = require("mongo-sanitize")
const hpp = require("hpp")
const https = require('https');
const fs = require(`fs`)
const app = express()
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

app.disable("x-powered-by")
app.use(express.json({ limit: "10kb" }))     
app.use((req, res, next) => {                  
    if (req.body) req.body = sanitize(req.body)
    next()
})
app.use(hpp())                                 
app.use(passport.initialize())                 
app.use(helmet({                               
    xPoweredBy: false,
    contentSecurityPolicy: false,
    xDownloadOptions: false,
}))

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 15,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    ipv6Subnet: 56,
})

const userSchema = new mongoose.Schema({
    userName: { type: String, required: true, unique: true },
    password: { type: String, required: function () { return !this.googleId } },
    googleId: { type: String, unique: true, sparse: true }
})

const User = mongoose.model("User", userSchema)

const registerSchema = joi.object({
    userName: joi.string().alphanum().min(3).max(30).required(),
    password: joi.string().alphanum().min(8).max(20).required()
})

const loginSchema = joi.object({
    userName: joi.string().required(),
    password: joi.string().required()
})

function validate(schema) {
    return (req, res, next) => {
        if (!req.body) return res.status(400).json({ message: "Request body is missing" })
        const { error } = schema.validate(req.body)
        if (error) return res.status(400).json({ message: error.details[0].message })
        next()
    }
}

// ── Passport Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://localhost:3000/auth/google/callback",
    passReqToCallback: true
},
    async function (request, accessToken, refreshToken, profile, done) {
        try {
            let user = await User.findOne({
                $or: [
                    { googleId: profile.id },
                    { userName: profile.email }
                ]
            })
            if (!user) {
                user = new User({
                    googleId: profile.id,
                    userName: profile.email,
                    password: "google-auth-user"
                })
                await user.save()
            } else {
                if (!user.googleId) {
                    user.googleId = profile.id
                    await user.save()
                }
            }
            return done(null, user)
        } catch (err) {
            return done(err, null)
        }
    }
))

passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((user, done) => done(null, user))

// JWT 
let refreshTokens = []

function generateAccessToken(user) {
    return jwt.sign(
        { userName: user.userName },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    )
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]
    if (!token) return res.sendStatus(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

// Routes
app.get("/", (req, res) => {
    res.send(`<a href="https://localhost:3000/auth/google">Login with Google</a>`)
})

app.post("/register", limiter, validate(registerSchema), async (req, res) => {
    try {
        const { userName, password } = req.body
        const existingUser = await User.findOne({ userName })
        if (existingUser) return res.status(400).json({ message: "User already exists" })
        const hashedPassword = await bcrypt.hash(password, 10)
        const newUser = new User({ userName, password: hashedPassword })
        await newUser.save()
        return res.send("User registered successfully.")
    } catch (err) {
        console.log(err)
        return res.status(500).send("Server error")
    }
})

const DUMMY_HASH = "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

app.post("/login", limiter, validate(loginSchema), async (req, res) => {
    try {
        const { userName, password } = req.body
        const existingUser = await User.findOne({ userName })

        const hashToCompare = existingUser ? existingUser.password : DUMMY_HASH
        const isMatch = await bcrypt.compare(password, hashToCompare)

        if (!existingUser || !isMatch) {
            return res.status(401).send("Username or password is incorrect")
        }
        if (existingUser.password === "google-auth-user") {
            return res.status(400).json({ message: "Please log in with Google" })
        }

        const accessToken = generateAccessToken(existingUser)
        const refreshToken = jwt.sign(
            { userName: existingUser.userName },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "7d" }
        )
        refreshTokens.push(refreshToken)
        return res.status(200).json({ message: "Login Successfully", accessToken, refreshToken })
    } catch (err) {
        console.log(err)
        return res.status(500).send("Server error")
    }
})

app.post("/token", (req, res) => {
    const refreshToken = req.body.token
    if (!refreshToken) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ userName: user.userName })
        res.json({ accessToken })
    })
})

app.delete("/logout", (req, res) => {
    const { token } = req.body
    refreshTokens = refreshTokens.filter(t => t !== token)
    res.sendStatus(204)
})

app.get("/auth/google",
    passport.authenticate("google", { scope: ["email", "profile"] })
)

app.get("/auth/google/callback",
    passport.authenticate("google", { session: false, failureRedirect: "/" }),
    (req, res) => {
        const accessToken = generateAccessToken(req.user)
        const refreshToken = jwt.sign(
            { userName: req.user.userName },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "7d" }
        )
        refreshTokens.push(refreshToken)
        res.json({ message: "Google Login Successful", accessToken, refreshToken })
    }
)

app.get("/jwt", authenticateToken, (req, res) => {
    res.send("Access granted")
})

mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log("Database connected successfully")
        https.createServer(options, app).listen(3000, () => {
        console.log('HTTPS Server running on https://localhost:3000');
})
}).catch(err => console.log("Server Error", err))