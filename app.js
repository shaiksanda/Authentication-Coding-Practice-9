const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const app = express()
const dbPath = path.join(__dirname, 'userData.db')
app.use(express.json())
let db = null
const port = 3000

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(port, () => {
      console.log(`Server Running at http://localhost:${port}/`)
    })
  } catch (error) {
    console.log(error)
    process.exit(1)
  }
}

initializeDbAndServer()

app.post('/register', async (request, response) => {
  const userDetails = request.body
  const {username, name, password, gender, location} = userDetails
  const getUserQuery = `select * from user where username=?`
  const dbUser = await db.get(getUserQuery, [username])
  console.log(dbUser)
  if (dbUser === undefined) {
    const addUser = `insert into user(username,name,password,gender,location) values(?,?,?,?,?)`
    if (password.length < 5) {
      response.status(400).send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)
      await db.run(addUser, [username, name, hashedPassword, gender, location])
      response.send('User created successfully').status(200)
    }
  } else {
    response.status(400).send('User already exists')
  }
})

app.post('/login', async (request, response) => {
  const userDetails = request.body
  const {username, password} = userDetails
  const getUserQuery = `select * from user where username=?`
  const dbUser = await db.get(getUserQuery, [username])
  if (dbUser === undefined) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched) {
      response.send('Login success!').status(200)
    } else {
      response.status(400).send('Invalid password')
    }
  }
})

app.put('/change-password', async (request, response) => {
  const userDetails = request.body
  const {username, oldPassword, newPassword} = userDetails
  const getUserQuery = `select * from user where username=?`
  const dbUser = await db.get(getUserQuery, [username])
  if (dbUser !== undefined) {
    const isPasswordMatched = await bcrypt.compare(oldPassword, dbUser.password)
    if (!isPasswordMatched) {
      response.status(400).send('Invalid current password')
    } else {
      if (newPassword.length < 5) {
        response.status(400).send('Password is too short')
      } else {
        const updatePasswordQuery = `update user set password=? where username=?`
        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await db.run(updatePasswordQuery, [hashedPassword, username])
        response.status(200).send('Password updated')
      }
    }
  }
})

module.exports = app
