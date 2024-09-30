import express from 'express';
import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
import { DataTypes } from 'sequelize';
import crypto from 'crypto';

const app = express();
app.use(express.json());
app.use((req, resp, next) => {
  resp.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  resp.set('Pragma', 'no-cache'); 
  resp.set('X-Content-Type-Options', 'nosniff');
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
    type: DataTypes.STRING,
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

if(process.argv[2]) {
  process.env.PORT = process.argv[2];
} 

app.all('/healthz', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).end(); 
  }
  next();
});

app.get('/healthz', async (req, resp) => {
  try {
    if (Object.keys(req.query).length > 0) {
      return resp.status(400).end();
    }
    
    if (req.get('Content-Length') && parseInt(req.get('Content-Length')) > 0) { 
      return resp.status(400).end();
    }
    await sequelize.authenticate();
    return resp.status(200).end();
  } catch(error) {
    return resp.status(503).end();
  }
});

// User creation for POST
app.post('/v1/user', async(req, resp) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const existingUser = await User.findOne({ where: { email } });
    if(existingUser) {
      return resp.status(400).end();
    }
    const token = crypto.randomBytes(16).toString('hex');
    const newUser = await User.create({ id: token, email, password, firstName, lastName });
    resp.status(201).json({
      message: 'User created',
    });
  } catch(error) {
    console.log(error);
    resp.status(400).end();
  }
});

app.put('/v1/user/self', async(req, resp)=> {
  try {
    
  } catch(error) {
    console.log(error);
    resp.status(400).end();
  }
})

// Correct placement of sequelize.sync
(async () => {
  try {
    await sequelize.sync({ force: true }); 
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
