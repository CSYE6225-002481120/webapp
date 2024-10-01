import express from 'express';
import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
import { DataTypes } from 'sequelize';
import { v4 as uuidv4 } from 'uuid';
import basicAuth from 'basic-auth';

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
app.disable('x-powered-by');

dotenv.config();

const sequelize = new Sequelize(process.env.DB_name, process.env.DB_username, process.env.DB_password, {
  host: process.env.DB_host,
  dialect: 'mysql'
});

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    allowNull: false,
    unique: true,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  account_created: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
  account_updated: {
    type: DataTypes.DATE,
    allowNull: true,
  },
}, {
  timestamps: false,
});

User.beforeUpdate((user) => {
  user.account_updated = new Date();
});

if (process.argv[2]) {
  process.env.PORT = process.argv[2];
}

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
    return res.status(400).end();
  }
  let id = AuthorizationHeader.trim();
  const id_base_64 = Buffer.from(id + ':').toString('base64');
  req.headers['authorization'] = `Basic ${id_base_64}`;
  const creds = basicAuth(req);
  if (!creds || !creds.name) {
    return res.status(400).end();
  }
  const user = await User.findOne({ where: { id: creds.name } });
  if (!user) {
    return res.status(403).end();
  }
  req.user = user;
  next();
} catch(error) {
  console.log(error);
}
};

// User creation for POST
app.post('/v1/user', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).end();
    }
    const newUser = await User.create({ email, password, firstName, lastName });
    res.status(201).json({
      message: 'User created',
      user: newUser,
    });
  } catch (error) {
    console.log(error);
    res.status(400).end();
  }
});

app.put('/v1/user/self', authenticate, async (req, res) => {
  try {
    const user = req.user;
    if (req.body.firstName) {
      user.firstName = req.body.firstName;
    }
    if (req.body.lastName) {
      user.lastName = req.body.lastName;
    }
    if (req.body.password) {
      user.password = req.body.password;
    }
    await user.save();
    return res.status(204).end();
  } catch (error) {
    console.log(error);
    res.status(400).end();
  }
});
app.get('/v1/user/self', authenticate, async(req, res)=>{
  
})

(async () => {
  try {
    await sequelize.sync({ alter: true });
    const port = app.listen(process.env.PORT, () => {
      console.log('Server running on port: ' + process.env.PORT);
    });

    port.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        app.listen(process.env.DEFAULT_PORT, () => {
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
