//Express app
const express = require("express");
const app = express();
const PORT = 80;

app.use(express.static("public"));

app.listen(PORT, ()=>{
    console.log(`Web server is up!`);
})

app.get("/", (req,res)=>{
    res.sendFile("public/pic.jpg", { root: __dirname });
})