#!/bin/bash
# Change to the fastapi directory

kill -9 $(lsof -t -i:5000) $(lsof -t -i:8000)

cd /home/api/API/fastapi

# Start fastapi
uvicorn main:app --reload &

# Change to the flask directory
cd /
cd /home/api/API/flask
# start flask
flask --app main_flask --debug run --host=0.0.0.0 &

# Wait for both processes to finish
wait

trap "kill $(lsof -t -i:5000) $(lsof -t -i:8000)" SIGINT SIGTERM