//Express app
const express = require("express");
const {join} = require('path')
const app = express();

//Import dan buat instance untuk arg parse
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;

//Variabel index server
const svIndex = argv.svIndex;
const PORT = 80;

console.log(svIndex);
app.set("views", join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.static("public"));

app.listen(PORT, ()=>{
    console.log(`Web server ${svIndex} is up!`);
})

app.get("/", (req,res)=>{
    res.render("index",{"svIndex":svIndex})
})