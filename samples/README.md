# Running `sample_app`

At the root folder of the library, start with the following command:

    docker compose run --rm integration-tests bash

Then:

    poetry build --output /app/samples

Access the folder `samples`, use the following command to install the package:

    poetry add --editable ./auth0_oauth_client-0.1.0.tar.gz

Exit the container. Access the folder `samples`, update `.env` accordingly, and run the sample app with:

    docker compose build app && docker compose up --remove-orphans app

Access the page at `http://localhost:8080/`