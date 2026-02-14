# Running `sample_app`

At the root folder of the library, start with the following command:

    docker compose run --rm integration-tests bash

Then:

    poetry build --output /app/samples

Get the version of the package you just built with:

    poetry version -s

Access the folder `samples`. Replace the version number in the following command with the one you got above:

    poetry add --editable ./auth0_oauth_client-0.3.0.tar.gz

Exit the container. Access the folder `samples`, update `.env` accordingly, and run the sample app with:

    docker compose build app && docker compose up --remove-orphans app

Access the page at `http://localhost:8080/`