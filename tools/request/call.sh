#!/bin/bash

#chmod +x call.sh grant execute permissions

#./call.sh register
#./call.sh login

# Check if an argument was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {login|register}"
    exit 1
fi

# The API endpoint
API_ENDPOINT="http://127.0.0.1:8080"

# The user name and password
USERNAME="jon"
PASSWORD="12345098764363749966845241634859694732"

# Function to perform login
login() {
    curl --location "$API_ENDPOINT/login" \
    --header 'Content-Type: application/json' \
    --data '{
        "userName": "'$USERNAME'"
    }'
}

# Function to perform registration
register() {
    curl --location "$API_ENDPOINT/register" \
    --header 'Content-Type: application/json' \
    --data '{
        "userName": "'$USERNAME'",
        "password": "'$PASSWORD'"
    }'
}

# Check the argument and call the corresponding function
case "$1" in
    login)
        login
        ;;
    register)
        register
        ;;
    *)
        echo "Invalid argument: $1"
        echo "Usage: $0 {login|register}"
        exit 1
        ;;
esac
