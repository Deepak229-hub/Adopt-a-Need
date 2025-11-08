import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"
import pg from "pg"
import bcrypt from "bcrypt"
import env from "dotenv"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local"

const app = express()
const port = 3000
const saltRounds = 10
env.config()

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static("public"))

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}))

app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: 5432
})

db.connect()

app.get("/", (req, res) => {
    res.render("index.ejs")
})

app.get("/login", (req, res) => {
    res.render("login.ejs")
})

app.get("/register", (req, res) => {
    res.render("login.ejs")
})

app.get("/adoption", (req, res) => {
    (req.isAuthenticated()) ? res.render("adoption.ejs") : res.render("login.ejs")
})

app.get("/profile", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("profile.ejs", {user: req.user})
    } else {
        res.render("login.ejs")
    }
})

app.post("/profileupdate", async (req, res) => {
    let updates = {
        name: req.body.updatedName,
        email: req.body.updatedEmail,
        contact: req.body.updatedContact,
        role: req.body.updatedRole,
        address: req.body.updatedAddress
    }
    try {
        let result = await db.query("SELECT * FROM users WHERE id=$1", [req.user.id])
        const updatedUser = await db.query(`UPDATE users SET name=$1, email=$2, phone=$3, role=$4, address=$5 WHERE id=$6 RETURNING *`, [
            updates.name ? updates.name : result.rows[0].name,
            updates.email ? updates.email : result.rows[0].email,
            updates.contact ? updates.contact : result.rows[0].phone,
            updates.role ? updates.role : result.rows[0].role,
            updates.address ? updates.address : result.rows[0].address,
            result.rows[0].id
        ])
        req.user = updatedUser.rows[0]
        res.redirect("/profile")
    } catch (err) {
        console.log(err)
    }
    
    console.log(updates)
})

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}))

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if(err) {
            return err
        }
        res.redirect("/")
    })
})

app.post("/register", async (req, res) => {
    const name = req.body.name
    const email = req.body.username
    const password = req.body.password
    const confirmPassword = req.body.confirm_password
    if (password.length < 8) {
        return res.render("login.ejs", { errorMessage: "Password must be 8 characters long!" })
    }
    if (password !== confirmPassword) {
        return res.render("login.ejs", { errorMessage: "Confirm Password must be same to the entered password!" })
    }
    try {
        let result = await db.query("SELECT * FROM users WHERE email=$1", [email])
        if (result.rows.length > 0) {
            return res.render("login.ejs", { errorMessage: "User already exists!" })
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    return res.status(500).send("Failed to register right now. Pleasr try again!")
                }
                const result = await db.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *", [name, email, hash])
                const user = result.rows[0]
                req.login(user, (err) => {
                    if (err) {
                        return res.status(500).send("Login failed after registration!")
                    }
                    res.redirect("/")
                })
            })
        }
    } catch (error) {
        res.status(500).send("An error occured during register!")
    }
})

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        let result = await db.query("SELECT * FROM users WHERE email=$1", [username])
        if (result.rows.length > 0) {
            const user = result.rows[0]
            const userPassword = user.password
            bcrypt.compare(password, userPassword, (err, result) => {
                if (err) {
                    console.log("error comparing password")
                    return cb(err)
                } else if (result) {
                    return cb(null, user)
                } else {
                    return cb(null, false)
                }
            })
        } else {
            return cb(null, false, {message: "Incorrect Username or Password!"})
        }
    } catch (error) {
        console.log(error.message)
        return cb(error)
    }
}))

passport.serializeUser((user, cb) => {
    cb(null, user)
})

passport.deserializeUser((user, cb) => {
    cb(null, user)
})

app.listen(port, () => {
    console.log(`Server is listening to port ${port}`)
})