#!/bin/bash
# 
# MSI DDSS 2021/2022 - Assignment 2
# The code and resources available in this repository are to be used in the scope of the DDSS course.
#
# Authors: Nuno Antunes <nmsa@dei.uc.pt>, João Antunes <jcfa@dei.uc.pt>
#



#
# ATTENTION: This will stop and delete all the running containers
# Comment out if you are using docker for other ativities
#
docker rm $(docker stop $(docker ps -a -q)) 


# # # Please comment back this command after your python setup works.
# This command should be uncommented only when you changed any of the Dockerfiles. In alternative, use it directly in the console.
docker-compose  -f docker-compose-python-psql.yml   build  --no-cache 


mkdir -p python/app/logs

# add  -d  to the command below if you want the containers running in background without logs
docker-compose  -f docker-compose-python-psql.yml up --build