import express from "express"
import bodyParser from "body-parser"
import ejs from "ejs"

const app = express()
const port = 3000

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static("public"))

app.get("/", (req, res) => {
    res.render("index.ejs")
})

app.listen(port, () => {
    console.log(`Server is listening to port ${port}`)
})