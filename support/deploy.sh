#!/bin/bash
set -e

echo "Deploying project Watch-Translations"
cd ~/www/python

echo "Stopping webservice.."
webservice stop

branch="master"
if test -f "~/branch"; then
    branch=`cat ~/branch`
fi

echo "Using branch $branch for deployment."
git pull --ff-only

echo "Now running database migrations.."
toolforge-jobs run db-upgrade-$$ --command 'cd ~/src && ~/venv/bin/flask db upgrade' --image tf-python39 --wait

echo "...all done! Starting webservice!"
webservice --backend=kubernetes python3.9 start
