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
const port = 4000
const saltRounds = 10
env.config()

app.use(bodyParser.urlencoded({extended: true}))
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

app.get("/", async (req, res) => {
    if (!req.isAuthenticated())
        return res.redirect("/login")
    try {
        const result = await db.query("SELECT * FROM ORPHANAGES WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const orphanage = result.rows[0]
        const donationAmount = await db.query("SELECT SUM(AMOUNT) FROM DONATIONS WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const volunteers = await db.query("SELECT COUNT(VOLUNTEER_ID) FROM VOLUNTEERS WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const recentDonations = await db.query("SELECT * FROM DONATIONS WHERE ORPHANAGE_ID=$1 ORDER BY DONATION_DATE DESC LIMIT 10", [req.user.orphanage_id])
        res.render("admin_dashboard.ejs", {orphanage, donation: donationAmount.rows[0].sum, volunteers: volunteers.rows[0].count, recentDonations:recentDonations.rows})
    } catch (error) {
        console.log(error)
        res.status(500)
    }
})

app.get("/login", (req, res) => {
    res.render("Admin_Login.ejs")
})

app.get("/register", (req, res) => {
    res.render("orphanageRegistration.ejs")
})

app.post("/update", async (req, res) => {
    if(!req.isAuthenticated())
        return res.redirect("/login")
    try {
        const name = req.body.name
        const email = req.body.email
        const result = await db.query("UPDATE ORPHANAGES SET NAME=$1, EMAIL=$2 WHERE ORPHANAGE_ID=$3", [name, email, req.user.orphanage_id])
        console.log(result)
        res.redirect("/")
    } catch (error) {
        console.log(error.message)
    }
})

app.post("/addVolunteer", async (req, res) => {
    if(!req.isAuthenticated())
        return res.render("/login")
    try {
        const name = req.body.name
        const mobile = req.body.mobile
        const availability = req.body.available.toLowerCase()
        const result = await db.query("INSERT INTO VOLUNTEERS (ORPHANAGE_ID, MOBILE_NUMBER, AVAILABLE_ON, NAME) VALUES ($1, $2, $3, $4) RETURNING *", [req.user.orphanage_id, mobile, availability, name])
        res.redirect("/")
    } catch (error) {
        console.log(error.message)
    }
})

app.post("/saveDonation", async (req, res) => {
    if(!req.isAuthenticated())
        return res.render("/login")
    try {
        const name = req.body.name
        const amount = req.body.amount
        const result = await db.query("INSERT INTO DONATIONS (ORPHANAGE_ID, AMOUNT, DONOR_NAME) VALUES ($1, $2, $3) RETURNING *", [req.user.orphanage_id, amount, name])
        res.redirect("/")
    } catch (error) {
        console.log(error)
    }
})

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}))

app.post("/register", async (req, res) => {
    const orphanageName = req.body.name
    const orphanageEmail = req.body.email
    const orphanagePhone = req.body.phone
    const password = req.body.password
    const orphanageType = req.body.type
    const address = req.body.address
    const regNumber = req.body.reg_number
    const childrenCapacity = req.body.capacity
    const childrenCount = req.body.children_count
    const orphanageBankAcc = req.body.bank_account
    const orphanageUPI = req.body.upi
    try {
        const result = await db.query("SELECT * FROM ORPHANAGES WHERE NAME=$1", [orphanageName])
        if(result.rows.length > 0)
            return res.redirect("/register", {msg: "Orphanage already exists!"})
        bcrypt.hash(password, saltRounds, async (err, hash) => {
            if (err)
                return res.status(500).send("Failed to register!")
            const date = new Date()
            const result = await db.query("INSERT INTO ORPHANAGES (NAME, EMAIL, PHONE, PASSWORD, TYPE, ADDRESS, REGISTRATION_NUMBER, CAPACITY, CHILDREN_COUNT, BANK_ACCOUNT, UPI_ID) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *", [orphanageName, orphanageEmail, orphanagePhone, hash, orphanageType, address, regNumber, childrenCapacity, childrenCount, orphanageBankAcc, orphanageUPI])
            const user = result.rows[0]
            req.login(user, (err) => {
                if (err) 
                    return res.status(500).send("Login failed!")
                res.redirect("/")
            })
        })
    } catch (error) {
        res.status(500).send("An error occured during register!")
        console.log(error)
    }
})

passport.use(new Strategy({usernameField: 'adminEmail', passwordField: 'adminPassword'},async function verify(adminEmail, adminPassword, cb) {
    try {
        let query = await db.query("SELECT * FROM orphanages WHERE email=$1", [adminEmail])
        if (query.rows.length > 0) {
            const user = query.rows[0]
            const password = user.password
            bcrypt.compare(adminPassword, password, (err, result) => {
                if (err) {
                    console.log("error comparing password!")
                    return cb(err)
                } else if (result) {
                    return cb(null, user)
                } else {
                    return cb(null, false)
                }
            })
        } else {
            return cb(null, false)
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
    console.log(`Server is listening at port ${port}`)
})