import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"
import pg from "pg"
import bcrypt from "bcrypt"


const app = express()
const port = 3000
const saltRounds = 10
let isLoggedIn = false

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "adopt-a-need",
    password: "45516111",
    port: 5432
})

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static("public"))

db.connect()

app.get("/", (req, res) => {
    res.render("index.ejs")
})

app.get("/login", (req, res) => {
    res.render("partials/login.ejs")
})

app.get("/register", (req, res) => {
    res.render("partials/register.ejs")
})

app.post("/register", async (req, res) => {
    const user = req.body.email
    const password = req.body.password
    const name = req.body.name
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [user])
        if(result.rows.length > 0) {
            res.send("User already exists!")
        }else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if(err) {
                    console.log("Error hashing password: ", err)
                }else {
                    await db.query("INSERT INTO users (email, password, name) VALUES ($1, $2, $3)", [user, hash, name])
                    isLoggedIn = true
                    res.render("index.ejs", {userName: result.rows[0].name, isLoggedIn: isLoggedIn})
                }
            })
        }
    } catch (error) {
        console.log("An error occured!")
    }
})

app.post("/login", async (req,res) => {
    const email = req.body.email
    const password = req.body.password
    try {
        const user = await db.query("SELECT * FROM users WHERE email = $1", [email])
        if(user.rows.length > 0) {
            const userPassword = await db.query("SELECT password FROM users WHERE email = $1", [email])
            bcrypt.compare(password, userPassword.rows[0].password, (err, result) => {
                if(err) {
                    console.log("Error logging user: ", err)
                }else if(result) {
                    isLoggedIn = true
                    res.render("index.ejs", {userName: user.rows[0].name, isLoggedIn: isLoggedIn})
                } else {
                    res.send("Incorrect Password!")
                }
            } )
        } else {
            res.send("User doesn't exist!")
        }
    } catch (error) {
        console.log("An error occured1")
    }
})

app.listen(port, () => {
    console.log(`Server is listening to port ${port}`)
})