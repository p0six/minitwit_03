#!/bin/bash
FLASK_APP=minitwit && export FLASK_APP
flask initdb && flask populatedb && sleep 3
for i in `echo 1 2 3`
do
  let "j = $i - 1"
  MINITWIT_SETTINGS="`pwd`/sessions/session_store0${i}.cfg" && export MINITWIT_SETTINGS
  flask run -p 500${j} &
done
