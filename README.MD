# PyScraper

## Prerequisite

Python 3.10

Developer identity (and optionally nickname/pass) for <https://screenscraper.fr>

## Usage

```bash
python3 scraper.py [options] <rom file or directory>
```

It'll create a `pyscraper.ini` file on the first time. Set your developer credentials there.

Depending on whether <screenscraper.fr> allows API access for non-registered users, you may also need the forum nickname and password. You're very likely to have them if you already have a developer identity.

Supported options:

```text
-c send checksum of the rom for more accurate info
-n rename the rom file to match the scraped name
-o output folder if different than rom's folder
-d dry-run, does not actually rename or download anything
-r scrape the roms recursively,effective only when input is a folder
-u force update the image file even they already exist
```

The script will download a game's title screenshot and save it using the rom's name under the same directory by default. Should the rom be renamed, the image file will always be the same name.

Depending on the maximum number of threads you have, this script will utilize that and make concurrent requests while scraping.

## TODO

Right now only `.nes` rom type is supported.

There may be some options in the command prompt but not working yet.

* Specify what kind of media to download(`-m`)

* Cache the registered user only flag and maximum threads flag in the config so to skip it next time

* Support for other roms

* Better logging for analysis
