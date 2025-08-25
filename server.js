import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"
import pg from "pg"
import bcrypt from "bcrypt"
import env from "dotenv"


const app = express()
const port = 3000
const saltRounds = 10
env.config()

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: 5432
})

app.use(bodyParser.urlencoded({ extended: true }))
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
    const name = req.body.name
    const email = req.body.email
    const phone = req.body.phone
    let password = null
    if (req.body.password == req.body.confirm_password) {
        password = req.body.password
    }

    try {
        let user = await db.query("SELECT * FROM users WHERE email = $1", [email])
        if (user.rows.length > 0) {
            res.send("User already exists!");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error hashing password: ", err)
                } else {
                    const result = await db.query("INSERT INTO users (name, email, phone, password) VALUES ($1, $2, $3, $4)", [name, email, phone, hash])
                    res.send("User Registered Successfully!")
                }
            })
        }
    } catch (error) {
        console.log("An Error occured!")
    }
})

app.post("/login", async (req, res) => {
    const user = req.body.email || req.body.phone
    const password = req.body.password

    try {
        let result = await db.query("SELECT * FROM users WHERE email = $1 OR phone = $1", [user])
        if(result.rows.length > 0) {
            const userPassword = result.rows[0].password
            bcrypt.compare(password, userPassword, (err, result) => {
                if(err) {
                    console.log(err)
                } else if (result) {
                    res.send("User Logged in!")
                } else {
                    res.send("Wrong password!")
                }
            })
        } else {
            res.send("User doesn't exists!")
        }
    } catch (error) {
        console.log(error)
    }
})

app.listen(port, () => {
    console.log(`Server is listening to port ${port}`)
})