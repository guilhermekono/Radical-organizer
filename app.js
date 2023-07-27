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

//Private Route

app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id

    // check if user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next){//função que verifica o token, isso é um middlware com acesso à requisição, à resposta e ao parametro next, que indica que ta tudo certo e é pra continuar, ou indica que tem um erro e cai fora

    const authHeader = req.headers['authorization'] //acesso ao token em si. É necessário extrair a parte útil do token, pois ele vem como 'Bearer &*uashduhasd', sendo que só a parte depois do bearer é o token em si
    const token = authHeader && authHeader.split(" ")[1]
    console.log(token)

    if(!token){
        return res.status(401).json({msg: "Acesso negado pois usuário não tem token"})
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret) //verifica se token existe?

        next()

    } catch(error){
        res.status(400).json({msg:"Token inválido"})
    }

}

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

    try {

        const secret = process.env.secret

        const token = jwt.sign({

            id: user._id,

            },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token})

    } catch(err){
        console.log(error)

        res.status(500).json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!',
        })
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




