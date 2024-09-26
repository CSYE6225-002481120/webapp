import express from 'express';
import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';

const app = express();
app.use(express.json());
app.use((req, resp, next) => {
    resp.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    resp.set('Pragma', 'no-cache'); 
    resp.set('X-Content-Type-Options', 'nosniff');
    next();
  });
app.disable('x-powered-by');
 
// if (req.body && Object.keys(req.body).length > 0) {
//     return res.status(400).end();
//   } else {
//     return res.status(405).end();
  

dotenv.config();



const sequelize = new Sequelize(process.env.DB_name, process.env.DB_username, process.env.DB_password, {
    host: process.env.DB_host,
    dialect: process.env.DB_dialect
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
  })
  
  const port = app.listen(process.env.PORT, ()=> {
    console.log('server running on port: ' + process.env.PORT);
  })

  port.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        app.listen(process.env.DEFAULT_PORT, () => {
           console.log("server running on " + process.env.DEFAULT_PORT);
        });
    } else {
        console.error('Error', err);
    }
});



  
