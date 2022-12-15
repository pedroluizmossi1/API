#!/bin/bash
# Change to the fastapi directory
cd ./fastapi

# Start fastapi
uvicorn main:app --reload &

# Change to the flask directory
cd ..
cd ./flask
# start flask
flask --app main_flask --debug run &

# Wait for both processes to finish
wait