# MSI DDSS - Assignment 2

The code and resources available in this repository are to be used in the scope of the _DDSS_ course.

**Important:** these sources are merely suggestions of implementations.
You should modify everything you deem as necessary and be responsible for all the content that is delivered.

The main purpose of this repository is to provide help with the initial setup of the applications that must be developed for the assignment. In particular, all the projects available are totally automated to be easily deployed in third-party setups with the help of a tool (in this case docker or maven, depending on the project).

_The contents of this repository do not replace the proper reading of the assignment description._

## Overview of the Contents

In this repository you will find the supporting resources for Assignment 2 of MSI-DDSS 2021/2022.

- [**`PostgreSQL`**](postgresql) - Database ready to run in a docker container with or without the help of the docker-compose tool;
- [**`Python`**](python) - Source code of web application template in python with Docker container configured. Ready to run in docker-compose with PostgreSQL
  - [`app/`](python/app) folder is mounted to allow developing with container running
- [**`Java`**](java) - Source code of web application template in java/spark with Docker container configured. Ready to run in docker-compose with PostgreSQL or in your favorite IDE.
- [**`NodeJS`**](nodejs) - Source code of web application template in nodejs with Docker container configured. Ready to run in docker-compose with PostgreSQL
  - [`src/`](nodejs/src) folder is mounted for developing with container running
- [**`php`**](php) - Source code of web application template in php with Docker container configured. Ready to run in docker-compose with PostgreSQL
  - [`htdocs/`](php/htdocs) folder is mounted for developing with container running
- [**`interfaces`**](interfaces) - the html interfaces mentioned in the assignment description. Necessary html interfaces in case other language/framework is adopted.
- [**`docker-compose`**](.) - Files that start the demo Python, Java, NodeJS and php applications together with a PostgreSQL database;

## Requirements

To execute this project it is required to have installed:

- `docker`
- `docker-compose`
- `maven` only if you opt for the [java](java) option

## Development

You should select one of the options or add your own.
Then you just need to developing inside the folder and run the script (e.g. [`./docker-compose-php-psql.sh`](docker-compose-php-psql.sh)) to have both the server and the database running.

[`Python`](python), [`php`](php) and [`NodeJS`](nodejs) allow you to be developing while the containers are running, and the sources are continuously being integrated.

In the case of [`Java`](java) we suggest that you have the container of the database running and you develop from your favourite IDE. 
Only for delivery you need the code to be working inside the `docker` image.
All IDEs support `maven`, and if your program works with `maven` it should be OK. Ask for the help of the Profs. if you face difficulties. 


**Delete everything you are not planing to you in your assignment.**

In `Linux` deployments you must confirm that you have `docker` installed and running, use the command `ps ax | grep dockerd` to check if `dockerd` is running, which is the process that manages containers.
You should run your commands as superuser, and therefore you should prefix your `docker`/`docker-compose` commands with `sudo` (e.g. `sudo ./docker-compose-php-psql.sh`).

## Web browser access

After the required commands and having started the web application, they will available on your browser at:

- NodeJs version: http://localhost:8080;
- Python version: http://localhost:8080;
- PHP version: http://localhost:8080;
- Java version: http://localhost:4567;

# Authors

- Nuno Antunes <nmsa@dei.uc.pt>
- Marco Vieira <mvieira@dei.uc.pt>
