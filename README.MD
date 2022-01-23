# PyScraper

## Prerequisite

Python 3.10

Developer identity (and optionally nickname/pass) for [screenscraper.fr](https://screenscraper.fr)

## Usage

```bash
python3 scraper.py [options] <rom files or directory>
```

First time launch will fail and generate a `.ini` file for you to fill in the credentials.

Depending on whether [screenscraper.fr](https://screenscraper.fr) allows API access for non-registered users, you may also need the forum nickname and password. You're very likely to have them if you already have a developer identity.

Depending on the maximum number of threads you have, this script will make concurrent requests while scraping. These settings are also cached in the `.ini` file. Should those values change(thanks for your contribution!), just remove them from the config file and they'll be fetched again.

### Example 1

```bash
python3 scraper.py -n ~/sample.nes
```

This will scrape only the game name for `sample.nes` and rename it accordingly.

### Example 2

```bash
python3 scraper.py -cn ~/*.nes -m screenshot
```

This will scrape game info for all the nes roms under `~/` by sending the exact checksum of the rom (md5, sha1, crc32). It allows more accurate scraping but is less fail proof.

This also downloads the game play screenshot to the `~/screenshot/` folder as specified by `-m` option. If a screenshot with the same name already exists, it won't be overwritten.

### Example 3

```bash
python3 scraper.py -cnd ~/*.nes -m all
```

This command intends to send checksum info and rename the all `.nes` files under home folder, as well as downloading both game title and game play screenshots to `~/title` and `~/screenshot` respectively. But since `-d` is turned on, this will be a dry run, no name is changed, no file is downloaded.

### Example 4

```bash
python3 scraper.py -cnu ~/*.nes -m all
```

Similar to example 3, but this will be an actual run. And with `-u` options, existing media files will be overwritten if already exist.

### Example 5

```bash
python3 scraper.py -h
```

See help information and usage.

## TODO

Right now only FC, SFC and GBA rom types are supported.

* Add support for other roms

* Better logging for analysis
