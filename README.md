# watch-translations

**WatchTranslations** is a tool that allows contributors to monitor translations at [TranslateWiki](https://translatewiki.net/), and receive notifications if there's anything untranslated.
The production version of the tool is hosted [here](https://tools.wmflabs.org/watch-translations/) on Wikimedia [Toolforge](https://wikitech.wikimedia.org/wiki/Help:Toolforge).

## Requirements

- Python 3
  - Modules from [`requirements.txt`](./support/requirements.txt)
- MySQL

## Local development environment

1. Clone the repository (`labs/tools/watch-translations`) from Wikimedia Gerrit
1. Create a Python virtualenv with `virtualenv -p python3 venv`
1. Activate the new virtaulenv with `source venv/bin/activate`
1. Install requirements with `pip install support/requirements.txt`
1. In `src`, copy `config.example.yaml` to `config.yaml`
1. Setup a development database with `flask db upgrade`
1. Start the server with `python app.py`
1. Navigate to `http://localhost:5000`

## Localization

All localizable fields are populated through `messages/LANG.json`.
Translations can be submitted through the [group](https://translatewiki.net/w/i.php?title=Special:Translate&group=wikimedia-tools-watch-translations) on TranslateWiki.
