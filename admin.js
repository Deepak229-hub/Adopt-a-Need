import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"
import pg from "pg"
import bcrypt from "bcrypt"
import env from "dotenv"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local"
import { types } from "pg"

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

types.setTypeParser(1082, (val) => val)

app.get("/", async (req, res) => {
    if (!req.isAuthenticated())
        return res.redirect("/login")
    try {
        const result = await db.query("SELECT * FROM ORPHANAGES WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const orphanage = result.rows[0]
        const donationAmount = await db.query("SELECT SUM(AMOUNT) FROM DONATIONS WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const volunteersCount = await db.query("SELECT COUNT(VOLUNTEER_ID) FROM VOLUNTEERS WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const recentDonations = await db.query("SELECT * FROM DONATIONS WHERE ORPHANAGE_ID=$1 ORDER BY DONATION_DATE DESC LIMIT 10", [req.user.orphanage_id])
        const volunteers = await db.query("SELECT * FROM VOLUNTEERS WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        const children = await db.query("SELECT * FROM CHILDREN WHERE ORPHANAGE_ID=$1", [req.user.orphanage_id])
        res.render("admin_dashboard.ejs", {orphanage, donation: donationAmount.rows[0].sum, volunteersCount: volunteersCount.rows[0].count, recentDonations:recentDonations.rows, volunteers: volunteers.rows, children: children.rows})
    } catch (error) {
        console.log(error)
        res.status(500)
    }
})

app.get("/editchildinfo/:id", async (req, res) => {
    if(!req.isAuthenticated()) 
        return res.redirect("/login")
    const childId = req.params.id
    try {
        const result = await db.query("SELECT * FROM CHILDREN WHERE ID=$1 AND ORPHANAGE_ID=$2", [childId, req.user.orphanage_id])
        const child = result.rows[0]
        console.log(child)
        res.render("editChildInfo.ejs", {id: child.id, name: child.name, gender: child.gender, dob: child.date_of_birth, doa: child.date_of_admission, status: child.status})
    } catch (error) {
        console.log(error)
    }
})

app.post("/editChild/:id", async (req, res) => {
    try {
        const result = await db.query("UPDATE CHILDREN SET NAME=$1, GENDER=$2, DATE_OF_BIRTH=$3, DATE_OF_ADMISSION=$4, STATUS=$5 WHERE ID=$6", [req.body.name, req.body.gender.toUpperCase(), req.body.dob, req.body.doa, req.body.status.toUpperCase(), req.params.id])
        res.redirect("/")
    } catch (error) {
        console.log(error)
    }
})

app.post("/deleteVolunteer/:id", async (req, res) => {
    if(!req.isAuthenticated())
        return res.redirect("login.ejs")
    const id = req.params.id
    try {
        await db.query("DELETE FROM VOLUNTEERS WHERE VOLUNTEER_ID=$1 AND ORPHANAGE_ID=$2", [id, req.user.orphanage_id])
        res.redirect("/")
    } catch (error) {
        console.log(error);
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
        return res.redirect("/login")
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

app.post("/addChild" , async (req, res) => {
    if(!req.isAuthenticated())
        return res.redirect("/login")
    try {
        const name = req.body.name
        const gender = req.body.gender
        const dob = req.body.dob
        const doa = req.body.doa
        const status = req.body.status
        await db.query("INSERT INTO CHILDREN (NAME, GENDER, DATE_OF_BIRTH, DATE_OF_ADMISSION, STATUS, ORPHANAGE_ID) VALUES ($1, $2, $3, $4, $5, $6)", [name, gender.toUpperCase(), dob, doa, status.toUpperCase(), req.user.orphanage_id])
        res.redirect("/")
    } catch (error) {
        console.log(error);
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