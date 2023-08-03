/*imports*/
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors'); 

const app = express()


app.use(express.urlencoded());

// Adiciona o middleware cors
app.use(cors());

app.use(express.static('public'));


// Models
const User = require('./model/User')


// ** Modificação: Register User **
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  

  try {
    //check if user exists
    const userExists = await User.findOne({ email: email });

    if (userExists) {
      return res.status(422).json({ msg: 'Por favor, use outro e-mail.' });
    }

    // create password
    const saltRounds = 12;
    console.log(name, email, password, confirmpassword);


    const passwordHash = await bcrypt.hash(password, saltRounds);

    // create user
    const user = new User({
      name,
      email,
      password: passwordHash, 
    });

    await user.save();

    res.status(201).json({ msg: 'Usuário registrado com sucesso.' });

  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde.' });
  }
});

// ** Modificação: Login user **
app.post('/auth/login', async (req, res) => {
  
  const {email, password} = req.body

  try {
    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado.' });
    }

    // check if password match
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(422).json({ msg: 'Senha inválida.' });
    }

    const secret = process.env.secret;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret,
    );

    res.status(200).json({ msg: 'Autenticação realizada com sucesso.'});

  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde.' });
  }
});

//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.zkn6fqg.mongodb.net/?retryWrites=true&w=majority`,)
  .then(() => {
    app.listen(3000)
    console.log('Conectou ao banco!')
  })
  .catch((err) => console.log(err))
