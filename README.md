

the assignment is to build a health check api that pre checks if everything is connected before starting the app for this we are trying to connect to a database and if it is connected successfully and a GET request is sent then 200 status code should be given

If the database is not connected then 503 service unavilable should be given

If any other method instead of GET is sent as a request then 405 should be given

If any payload is sent then 400 should be given

for this webapp to run first install the following dependencies and environment 

*install node 
*open the repo and install these dependencies 
run the command in the folder path
-> npm i express
-> npm i sequelize
-> npm i dotenv

run the command node server.js (port number if wanted to run on any specific port) to start the server

install curl using homebrew on mac the command is brew install curl (install brew first from browser) (for windows there will be another method but curl can be installed)

run the following commands in another terminal to check the output 
curl -vvvv http://localhost:portnumber/healthz to send a GET request with no payload
curl -vvvv -XPOST http://localhost:port/healthz to send another method request(POST is only an example for this)
curl -vvvv -X GET -H "Content-Type: application/json" -d '{"key":"value"}' http://localhost:port/healthz to send payload using GET
curl -vvvv -X PUT http://localhost:5002/healthz -H "Content-Type: application/json" -d '{"key":"value"}' to send payload using another request method 
curl -vvvv "http://localhost:3000/healthz?param=value" GET method with query parameters 





