/*imports*/
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Config JSON response because express do not understand JSON by default

app.use(express.json())

// Models
const User = require('./model/User')

//Open route - public route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'bem vindo a nossa API'})
})

// Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    //validation
    if(!name){
        return res.status(422).json({msg: 'o nome é obrigatorio'})
    }
    if(!email){
        return res.status(422).json({msg: 'o email é obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg: 'a senha é obrigatorio'})
    }
    
    if(password != confirmpassword){
        return res.status(422).json({msg: 'a senha não confere'})
    }

    //check if user exists
    const userExists = await User.findOne({ email: email})

    if(userExists){
        return res.status(422).json({ msg:'Por favor, use outro email'})
    } 

    //create password
    const salt = await bcrypt.genSalt(12) // caracteres a mais na senha pra aumentar a dificuldade
    const passwordHash = await bcrypt.hash(password, salt)// passando caracteres a mais junto com a senha pra dificultar

    // create user

    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg: 'Usuário criado com sucesso'})

    } catch (error){
        console.log(error)

        res.status(500).json({msg: 'aconteceu um erro no server, try it mais tarde',})
    }
})

//Login user
app.post("/auth/login", async (req, res) => {

    const {email, password} = req.body

    //validation
    if(!email){
        return res.status(422).json({msg: 'o email é obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg: 'a senha é obrigatorio'})
    }

    //check if user exists
    const user = await User.findOne({ email: email})

    if(!user){
        return res.status(404).json({ msg:'Usuário não encontrado'})
    } 

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({msg: 'Senha inválida'})
    }
})

//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.zkn6fqg.mongodb.net/?retryWrites=true&w=majority`,)
    .then(() => {
        app.listen(3000)
        console.log('Conectou ao banco!')
    })
    .catch((err) => console.log(err))




