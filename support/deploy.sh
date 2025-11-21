#!/bin/bash
set -e

export IMAGE="python3.13"

echo "Deploying project Watch-Translations"
cd ~/www/python
toolforge webservice stop

branch="master"
if test -f "~/branch"; then
    branch=`cat ~/branch`
fi

echo "Using branch $branch for deployment."
git pull --ff-only

toolforge jobs run venv-upgrade-$$ --command 'cd ~/watch-translations && venv/bin/pip install -Ur support/requirements.txt' --image "$IMAGE" --wait
toolforge jobs run db-upgrade-$$ --command 'cd ~/src && ~/venv/bin/flask db upgrade' --image "$IMAGE" --wait

toolforge webservice "$IMAGE" start
echo "...all done!"
