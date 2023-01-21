#!/bin/bash
set -e

echo "Deploying project Watch-Translations"
cd ~/www/python
webservice stop

branch="master"
if test -f "~/branch"; then
    branch=`cat ~/branch`
fi

echo "Using branch $branch for deployment."
git pull --ff-only

toolforge-jobs run db-upgrade-$$ --command 'cd ~/src && ~/venv/bin/flask db upgrade' --image tf-python39 --wait

webservice --backend=kubernetes python3.9 start
echo "...all done!"
