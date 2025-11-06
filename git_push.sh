#!/bin/bash

read -p "Enter commit message: " COMMIT_MESSAGE

# Check if empty
if [[ -z "$COMMIT_MESSAGE" ]]; then
    echo "Commit message cannot be empty."
    exit 1
fi

git add .
git commit -m "$COMMIT_MESSAGE"
git push origin main
