#!/bin/bash
if [[ "$VIRTUAL_ENV" != "" ]]
then
  echo "virtual env already active"
else
  echo "activating virtual env"
  source env/bin/activate
fi
python3 ../dpd-uvicorn-runner/dpd-uvicorn-runner.py &