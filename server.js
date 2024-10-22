import express from 'express';
import { Sequelize, DataTypes } from 'sequelize';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import basicAuth from 'basic-auth';
import moment from 'moment-timezone';
import bcrypt from 'bcrypt';  

dotenv.config();

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
app.disable('x-powered-by');






const sequelize = new Sequelize(process.env.DB_name, process.env.DB_username, process.env.DB_password, {
  host: process.env.DB_host,
  dialect: 'mysql',
});


const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    allowNull: false,
    unique: true,
    primaryKey: true,
  },
  
  email: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  account_created: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
  account_updated: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
}, {
  timestamps: false,
});

app.all('/healthz', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }
  next();
});

app.get('/healthz', async (req, res) => {
  try {
    if (Object.keys(req.query).length > 0) {
      return res.status(400).end();
    }
    if (req.get('Content-Length') && parseInt(req.get('Content-Length')) > 0) {
      return res.status(400).end();
    }
    await sequelize.authenticate();
    return res.status(200).end();
  } catch (error) {
    return res.status(503).end();
  }
});


const authenticate = async (req, res, next) => {
  try {
    const AuthorizationHeader = req.get('Authorization');
    if (!AuthorizationHeader) {
      return res.status(401).end();
    }

    const [email, password] = AuthorizationHeader.split(':');
    if (!email || !password) {
      return res.status(401).json({ message: 'Invalid credentials format. Use email:password' });
    }

    const credsBase64 = Buffer.from(`${email}:${password}`).toString('base64');
    req.headers['authorization'] = `Basic ${credsBase64}`;
    const creds = basicAuth(req);

    if (!creds || !creds.name || !creds.pass) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = await User.findOne({ where: { email: creds.name } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(creds.pass, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Error in authentication middleware:', error);
    return res.status(500).end();
  }
};



app.all('/v1/user/self', (req, res, next)=> {
 // console.log("inside all self" + " " + req.method);
  if(req.method === 'HEAD' || req.method == 'OPTIONS' || req.method === 'PATCH') {
    //console.log('inside if')
    return res.status(405).end();
  }
  next();
})
app.post('/v2/user', async (req, res) => {
  try {
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(422).send('Request body is empty');
    }
    const { email, password, firstName, lastName } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if(!req.body.firstName || firstName ==="" || firstName === " ") {
      return res.status(422).json({ message: 'Firstname cannot be empty' });
    }
    // if(firstName.includes(" ")) {
    //   return res.status(400).json({ message: 'Firstname cannot have space' });
    // }
    if(lastName.includes(" ")) {
      return res.status(422).json({ message: 'Lastname cannot have space' });
    }
    if(!req.body.lastName || lastName === " " || lastName === "") {
      return res.status(422).json({ message: 'Lastname cannot be empty' });
    }
    if(password === "") {
      return res.status(422).json({ message: 'Password cannot be empty' });
    }
    if(password.includes(" ")) {
      return res.status(422).json({ message: 'Password cannot have space' });
    }
    if(password.length < 8) {
      return res.status(422).json({ message: 'password should be atleast 8 characters' });
    }
    if (!emailRegex.test(email)) {
      return res.status(422).json({ message: 'Invalid email format' });
    }
    
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const encrypted_password = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, password:encrypted_password, firstName, lastName });
    const createtime = moment(newUser.account_created).tz('America/New_York').format();
    const updatetime = moment(newUser.account_updated).tz('America/New_York').format();
    return res.status(201).json({
        description:"User created successfully",
        id: newUser.id,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        account_created: createtime,
        account_updated: updatetime
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ 
      message: 'Error creating user' 
    });
  }
});


app.put('/v1/user/self', authenticate, async (req, res) => {
  try {
    const user = req.user;
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(422).send('Request body is empty');
    }

    if(req.body.email || req.body.account_created || req.body.account_updated || req.body.id) {
      return res.status(400).end();
    }
  
    if (req.body.firstName) {
      console.log(req.body.firstName);
      if(req.body.firstName.length === 0 || req.body.firstName === " ") {
        return res.status(422).json({ message: 'Firstname cannot be empty' });
      }
      user.firstName = req.body.firstName;
    }
    if (req.body.lastName) {
      if(req.body.lastName.includes(" ")) {
        return res.status(422).json({ message: 'Lastname cannot have space' });
      }
      if(req.body.lastName === " " || req.body.lastName === "") {
        return res.status(422).json({ message: 'Lastname cannot be empty' });
      }
      user.lastName = req.body.lastName;
    }
    if (req.body.password) {
      if(req.body.password === "") {
        return res.status(422).json({ message: 'Password cannot be empty' });
      }
      if(req.body.password.includes(" ")) {
        return res.status(422).json({ message: 'Password cannot have space' });
      }
      if(req.body.password.length < 8) {
        return res.status(422).json({ message: 'password should be atleast 8 characters' });
      }
      const encrypted_password = await bcrypt.hash(req.body.password, 10);
      user.password = encrypted_password;
    }
    user.account_updated = moment().tz('America/New_York').toDate();
    await user.save();
    return res.status(204).end();
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'Error updating user' });
  }
});

app.delete('/v1/user/self', (req, res)=>{
  return res.status(405).end();
})

app.get('/v1/user/self', authenticate, async (req, res) => {
  try {
    if (Object.keys(req.query).length > 0) {
      return res.status(400).end();
    }
    if (req.get('Content-Length') && parseInt(req.get('Content-Length')) > 0) {
      return res.status(400).end();
    }
    const user = req.user;
    const createtime = moment(user.account_created).tz('America/New_York').format();
    const updatetime = moment(user.account_updated).tz('America/New_York').format();
    return res.status(200).json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      account_created: createtime,
      account_updated: updatetime,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'Error fetching user information' });
  }
});


(async () => {
  try {
    await sequelize.sync({ alter: true });
    const port = app.listen(process.env.PORT, () => {
      console.log('Server running on port: ' + process.env.PORT);
    });

    port.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        app.listen(process.env.DEFAULT_PORT,  '0.0.0.0',() => {
          console.log("Server running on port: " + process.env.DEFAULT_PORT);
        });
      } else {
        console.error('Server Error:', e);
      }
    });
  } catch (error) {
    console.error('Error synchronizing the database:', error);
  }
})();



export  {app, sequelize, User};