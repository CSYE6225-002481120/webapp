import { expect } from 'chai';
import sinon from 'sinon';
import { describe, it, beforeEach } from 'mocha';
import request from 'supertest';
import bcrypt from 'bcrypt';
import { app, sequelize, User } from '../server.js';
import dotenv from 'dotenv';

dotenv.config();
 

describe('User Routes - POST /v1/user', () => {
  beforeEach(async () => {
   
    await sequelize.sync({ force: true });
  });

  // Integration Test -  User Creation
  it('should create a new user with valid data', async () => {
    const response = await request(app)
      .post('/v1/user')
      .send({
        email: 'test@example.com',
        password: 'Password123',
        firstName: 'John',
        lastName: 'Doe',
      });

    expect(response.status).to.equal(201);
    expect(response.body).to.have.property('id');
    expect(response.body).to.have.property('firstName', 'John');
    expect(response.body).to.have.property('lastName', 'Doe');
    expect(response.body).to.have.property('email', 'test@example.com');
    expect(response.body).to.have.property('account_created');
    expect(response.body).to.have.property('account_updated');
  });

  // Unit Test - Email  Exists
  it('should return 400 if user with email already exists', async () => {
    const existingUser = {
      email: 'existing@example.com',
      password: await bcrypt.hash('Password123', 10),
      firstName: 'Jane',
      lastName: 'Doe',
    };

    await User.create(existingUser);

    const response = await request(app)
      .post('/v1/user')
      .send({
        email: 'existing@example.com',
        password: 'Password123',
        firstName: 'John',
        lastName: 'Doe',
      });

    expect(response.status).to.equal(400);
    expect(response.body).to.have.property('message', 'User already exists');
  });

  // Unit Test - Empty Request Body
  it('should return 400 if request body is empty', async () => {
    const response = await request(app).post('/v1/user').send({});
    expect(response.status).to.equal(400);
    expect(response.text).to.equal('Request body is empty');
  });

  // Unit Test - Invalid Email Format
  it('should return 400 for invalid email format', async () => {
    const response = await request(app)
      .post('/v1/user')
      .send({
        email: 'invalid-email-format',
        password: 'Password123',
        firstName: 'John',
        lastName: 'Doe',
      });
    expect(response.status).to.equal(400);
    expect(response.body).to.have.property('message', 'Invalid email format');
  });

  // Unit Test - Password Less Than 8 Characters
  it('should return 400 for password less than 8 characters', async () => {
    const response = await request(app)
      .post('/v1/user')
      .send({
        email: 'test@example.com',
        password: 'Pass12',
        firstName: 'John',
        lastName: 'Doe',
      });

    expect(response.status).to.equal(400);
    expect(response.body).to.have.property('message', 'password should be atleast 8 characters');
  });
});

describe('User Routes - /v1/user/self GET', () => {
    let createdUser;
  
    beforeEach(async () => {
     
      await sequelize.sync({ force: true });
  
     
      const passwordHash = await bcrypt.hash('Password123', 10);
      createdUser = await User.create({
        email: 'user@example.com',
        password: passwordHash,
        firstName: 'John',
        lastName: 'Doe',
      });
    });
  

 // Test Case 1: Check if email and password in Authorization header are correct
it('should return 200 and the user details if email and password are correct', async () => {
    const response = await request(app)
      .get('/v1/user/self')
      .set('Authorization', 'user@example.com:Password123'); // Send as plain text
    
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property('id', createdUser.id);
    expect(response.body).to.have.property('firstName', 'John');
    expect(response.body).to.have.property('lastName', 'Doe');
    expect(response.body).to.have.property('email', 'user@example.com');
    expect(response.body).to.have.property('account_created');
    expect(response.body).to.have.property('account_updated');
  });
  
  
    // Test Case 2: Check that password is not returned in the response
    it('should not return the password field in the response', async () => {
      const response = await request(app)
        .get('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123'); 
  
      expect(response.status).to.equal(200);
      expect(response.body).to.not.have.property('password');
    });
  
    // Test Case 3: Check for invalid credentials (wrong password)
    it('should return 401 if the password is incorrect', async () => {
        const response = await request(app)
          .get('/v1/user/self')
          .set('Authorization', 'user@example.com:WrongPassword');  // Use plain text
    
        expect(response.status).to.equal(401);
        expect(response.body).to.have.property('message', 'Invalid credentials');
      });
  
    // Test Case 4: Check for missing Authorization header
    it('should return 401 if the Authorization header is missing', async () => {
      const response = await request(app).get('/v1/user/self');
      expect(response.status).to.equal(401);
    });
  
    // Test Case 5: Check for invalid email (user not found)
    it('should return 403 if the email is not found in the database', async () => {
      const response = await request(app)
        .get('/v1/user/self')
        .set('Authorization', 'WrongEmail:Password123'); 
  
      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('message', 'User not found');
    });
  });

  describe('User Routes - PUT /v1/user/self', () => {
    let createdUser;
  
    beforeEach(async () => {
    
      await sequelize.sync({ force: true });
  
     
      const passwordHash = await bcrypt.hash('Password123', 10);
      createdUser = await User.create({
        email: 'user@example.com',
        password: passwordHash,
        firstName: 'John',
        lastName: 'Doe',
      });
    });
  
    // Test Case 1: Check for empty request body
    it('should return 400 if the request body is empty', async () => {
      const response = await request(app)
        .put('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123') 
        .send({});  
  
      expect(response.status).to.equal(400);
      expect(response.text).to.equal('Request body is empty');
    });
  
  
  
    // Test Case 3: Lastname cannot have spaces
    it('should return 400 if lastName has spaces', async () => {
      const response = await request(app)
        .put('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123')
        .send({ lastName: 'Doe Smith' });
  
      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('message', 'Lastname cannot have space');
    });
  
   
  
  
    // Test Case 6: Password cannot contain spaces
    it('should return 400 if password contains spaces', async () => {
      const response = await request(app)
        .put('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123')
        .send({ password: 'Pass word123' });
  
      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('message', 'Password cannot have space');
    });
  
   
    it('should return 400 if password is less than 8 characters', async () => {
      const response = await request(app)
        .put('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123')
        .send({ password: 'Pass12' });
  
      expect(response.status).to.equal(400);
      expect(response.body).to.have.property('message', 'password should be atleast 8 characters');
    });
  
   
    it('should return 204 and update firstName and lastName successfully', async () => {
      const response = await request(app)
        .put('/v1/user/self')
        .set('Authorization', 'user@example.com:Password123')
        .send({
          firstName: 'Jane',
          lastName: 'Smith',
        });
  
      expect(response.status).to.equal(204);
  
     
      const updatedUser = await User.findOne({ where: { email: 'user@example.com' } });
      expect(updatedUser.firstName).to.equal('Jane');
      expect(updatedUser.lastName).to.equal('Smith');
    });
  });
  
  describe('Health Check Route - /healthz', () => {

    // Test Case 1: Check if non-GET requests return 405
    it('should return 405 for POST requests to /healthz', async () => {
      const response = await request(app)
        .post('/healthz')
        .send(); 
  
      expect(response.status).to.equal(405);
    });
  
    it('should return 405 for PUT requests to /healthz', async () => {
      const response = await request(app)
        .put('/healthz')
        .send(); 
  
      expect(response.status).to.equal(405);
    });
  
    it('should return 405 for DELETE requests to /healthz', async () => {
      const response = await request(app)
        .delete('/healthz')
        .send(); 
  
      expect(response.status).to.equal(405);
    });
  
    // Test Case 2: Check for GET /healthz with successful database connection
    it('should return 200 for GET requests if the database is connected', async () => {
     
      const authenticateStub = sinon.stub(sequelize, 'authenticate').resolves();
  
      const response = await request(app).get('/healthz');
  
      expect(response.status).to.equal(200);
      authenticateStub.restore(); 
    });
  
    // Test Case 3: Check for GET /healthz with failed database connection
    it('should return 503 if the database connection fails', async () => {
      
      const authenticateStub = sinon.stub(sequelize, 'authenticate').rejects(new Error('Database Connection Failed'));
  
      const response = await request(app).get('/healthz');
  
      expect(response.status).to.equal(503);
      authenticateStub.restore(); 
    });
  
    // Test Case 4: Check for GET /healthz with query parameters
    it('should return 400 for GET requests with query parameters', async () => {
      const response = await request(app)
        .get('/healthz')
        .query({ name: 'test' }); 
  
      expect(response.status).to.equal(400);
    });
  
    // Test Case 5: Check for GET /healthz with a request body
    it('should return 400 for GET requests with a request body', async () => {
      const response = await request(app)
        .get('/healthz')
        .send({ key: 'value' });
  
      expect(response.status).to.equal(400);
    });
  });
  
  
