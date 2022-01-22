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
-m Specify a media type to download. Defaults to rom's title screenshot. Or use `all` to download both title and game screenshots.
```

The script will download a game's title screenshot and save it using the rom's name to a subfolder of the rom's folder by default. Should the rom be renamed, the image file will always be the same name.

Using a subfolder because screenshot and title pictures will be the same name.

Depending on the maximum number of threads you have, this script will utilize that and make concurrent requests while scraping. These settings are cached in the .ini file. Should those values change(thanks for your contribution!), just remove them from the config file and they'll be fetched again.

## TODO

Right now only FC, SFC and GBA rom types are supported.

* Add support for other roms

* Better logging for analysis
