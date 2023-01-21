#!/bin/bash
set -e
echo "Deploying project Watch-Translations"
echo "Stopping webservice.."
webservice stop
branch="master"
if test -f "~/branch"; then
    branch=`cat ~/branch`
fi
echo "Using branch $branch for deployment."
cd `dirname "$0"`/..
git fetch --all
git merge --ff-only
echo "Now running database migrations.."
cd src
flask db upgrade
echo "...all done! Starting webservice!"
webservice --backend=kubernetes python3.9 start
