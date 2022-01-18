import argparse
from concurrent import futures
from concurrent.futures import ThreadPoolExecutor
import configparser
import os
import sys
from pathlib import Path
from typing import List
import urllib.request
import urllib.parse
import hashlib
import zlib
import json
import logging

SS_API2_BASE_URL = "https://www.screenscraper.fr/api2/"
INFRA_INFO_PATH = "ssinfraInfos.php"
USER_INFO_PATH = "ssuserInfos.php"
ROM_INFO_PATH = "jeuInfos.php"
DEVID_PARAM = "devid"
DEVPASSWORD_PARAM = "devpassword"
SOFTNAME_PARAM = "softname"
SOFTNAME = "PyScraper"
OUTPUT_PARAM = "output"
DEFAULT_OUTPUT = "json"
SSID_PARAM = "ssid"
SSPASSWORD_PARAM = "sspassword"
CRC_PARAM = "crc"
MD5_PARAM = "md5"
ROMSHA1_PARAM = "romsha1"
SYSTEMEID_PARAM = "systemeid"
ROMTYPE_PARAM = "romtype"
ROMNAME_PARAM = "romnom"

INI_FILE = "pyscraper.ini"
DEFAULT = "screenscraper.fr"
SS_NAME = "nickname"
SS_PASS = "password"

SUPPORTED_FILE_TYPE_ID = {".nes": "3"}

devid: str = None
devpassword: str = None
ssid: str = None
sspassword: str = None
dry_run: bool


class ChecksumInfo:

    def __init__(self, file):
        self.file = file
        crc = 0
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        with open(file, "rb") as f:
            for buffer in iter(lambda: f.read(4096), b""):
                crc = zlib.crc32(buffer, crc)
                md5.update(buffer)
                sha1.update(buffer)
        self.crc = format(crc & 0xFFFFFFFF, '08x').upper()
        self.md5 = md5.hexdigest().upper()
        self.sha1 = sha1.hexdigest().upper()


class DownloadFile:

    def __init__(self, url, dest):
        self.url = url
        self.dest = dest


def main() -> int:
    init_logger()

    parser = argparse.ArgumentParser(
        description="Scrape rom information from screenscraper.fr")
    parser.add_argument("input",
                        type=Path,
                        help="Rom file or directory of the roms")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Location to store scraped files, must be a valid directory")
    parser.add_argument("-r",
                        "--recursive",
                        action="store_true",
                        help="Scrape recursively in a directory")
    parser.add_argument("-c",
                        "--checksum",
                        action="store_true",
                        help="Whether or not to send checksum")
    parser.add_argument("-n",
                        "--rename",
                        action="store_true",
                        help="Rename the rom file to the name from SS")
    parser.add_argument("-u",
                        "--update-cache",
                        action="store_true",
                        help="Force update the media and update the cache")
    parser.add_argument("-m",
                        "--media-type",
                        nargs='+',
                        choices=["title", "screenshot"],
                        default="title",
                        help="Media type to scrape. Default to title.")
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help="Only writes to log, does not rename roms or download media files"
    )
    args = parser.parse_args()

    if not args.input:
        parser.print_usage()
        return 0

    global dry_run
    dry_run = args.dry_run

    input: Path = args.input
    if not input.exists():
        logger.warning("Input does not exist")
        return -1

    output_dir: Path
    if args.output:
        if args.output.exists() and args.output.is_dir():
            output_dir = args.output
        else:
            logger.warning("Invalid output directory")
    else:
        output_dir = input if input.is_dir() else input.parent

    read_credentials()
    if not devid or not devpassword:
        logger.info(f"Set dev credentials in sample {INI_FILE} file!")
        save_sample_ini()
        return -1

    registered_user_only = get_registered_user_only()

    if registered_user_only:
        if not (ssid and sspassword):
            logger.error(f"API closed for non-registered users, \
                    set forum nicknamd/password in {INI_FILE} file")
            return -1

    global maximum_threads
    maximum_threads = get_maximum_threads()

    return scrape(input, output_dir, args.recursive, args.rename,
                  args.checksum, args.update_cache)


def get_registered_user_only() -> bool:
    url = SS_API2_BASE_URL + INFRA_INFO_PATH + "?" + common_query(False)

    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                return json_object.get("response",
                                       {}).get("serveurs",
                                               {}).get("closefornomember")
            except ValueError:
                logger.debug(response_data.decode('utf-8'))
    except Exception as e:
        logger.debug(e)
    return False


def get_maximum_threads() -> int:
    if not (ssid and sspassword):
        return 1

    url = SS_API2_BASE_URL + USER_INFO_PATH + "?" + common_query(True)

    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                max_threads = json_object.get("response",
                                              {}).get("ssuser",
                                                      {}).get("maxthreads")
                return int(max_threads or 1)
            except ValueError:
                logger.debug(response_data.decode("utf-8"))
    except Exception as e:
        logger.debug(e)
    return 1


def scrape(input: Path, output_dir: Path, recursive: bool, rename: bool,
           send_checksum: bool, update_cache: bool) -> int:
    rom_files = []
    if input.is_dir():
        for f in input.rglob("*.*") if recursive else input.glob("*.*"):
            rom_files.append(f)
    else:
        rom_files.append(input)

    futures_list = []
    with ThreadPoolExecutor(max_workers=maximum_threads) as executor:
        for f in rom_files:
            future = executor.submit(scrape_single_file, f, output_dir,
                                     send_checksum, rename, update_cache)
            futures_list.append(future)
            if len(futures_list) >= maximum_threads or f == rom_files[-1]:
                done, not_done = futures.wait(
                    futures_list, return_when=futures.ALL_COMPLETED)
                files_to_download = [
                    download for future in done
                    for download in future.result()
                ]
                futures_list = list(not_done)
                for file in files_to_download:
                    futures_list.append(executor.submit(download_file, file))
    return 0


def scrape_single_file(input: Path, output_dir: Path, send_checksum: bool,
                       rename: bool, update_cache: bool) -> List[DownloadFile]:
    if input.suffix.lower() not in SUPPORTED_FILE_TYPE_ID:
        logger.debug(f"Unsupported rom type for scraping: {input}")
        return []
    rom_query_param, checksum = rominfo_query(input, send_checksum)
    params = common_query(True) + '&' + rom_query_param
    url = SS_API2_BASE_URL + ROM_INFO_PATH + "?" + params
    logger.debug(url)
    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                return process_response(input, output_dir, json_object,
                                        checksum, rename, update_cache)
            except ValueError:
                logger.debug(response_data.decode('utf-8'))
    except Exception as e:
        logger.debug(e)
    return []


def process_response(input: Path, output_dir: Path, ss_data: dict,
                     checksum: ChecksumInfo, rename: bool,
                     update_cache: bool) -> List[DownloadFile]:
    game_data = ss_data.get('response', {}).get('jeu')
    if not game_data:
        logger.warning(f"{input.name}: has no game data")
        return []

    rom_data = game_data.get('rom', {})

    if checksum:
        if checksum.crc == rom_data.get(
                'romcrc') and checksum.md5 == rom_data.get(
                    'rommd5') and checksum.sha1 == rom_data.get('romsha1'):
            logger.debug(f"{input.name}: checksum matches")
        else:
            logger.warning(f"{input.name}: has no match by checksum")

    remote_rom_name = rom_data.get('romfilename', '')
    found_rom_with_same_suffix = remote_rom_name.lower().endswith(
        input.suffix.lower())
    if not found_rom_with_same_suffix:
        logger.warning(f"{input.name}: has no match by name")
    elif rename and found_rom_with_same_suffix:
        if input.name == remote_rom_name:
            logger.info(f"{input.name}: already the same name as remote")
        else:
            logger.info(f"{input.name}: renamed {remote_rom_name}")
            if not dry_run:
                input = input.rename(input.parent.joinpath(remote_rom_name))

    files = []
    rom_regions = rom_data.get('romregions')
    media_data = game_data.get('medias', {})

    media_to_download: DownloadFile = None
    available_files = []
    for media in media_data:
        if media.get("type") == "sstitle":
            available_files.append(media)
            if media.get("region") == rom_regions:
                media_to_download = get_download_file_info(
                    input, output_dir, media)

    if not media_to_download and len(available_files) > 0:
        media_to_download = get_download_file_info(input, output_dir,
                                                   available_files[0])

    if media_to_download:
        if not media_to_download.dest.exists() or update_cache:
            files.append(media_to_download)
        else:
            logger.debug(f"Skipping file {media_to_download.dest}")

    return files


def get_download_file_info(input: Path, output_dir: str,
                           media: dict) -> DownloadFile:
    url = media.get("url")
    dest = Path(output_dir).joinpath(input.stem + "." + media["format"])
    return DownloadFile(url, dest)


def download_file(file: DownloadFile) -> List:
    logger.debug(f"fetching: {file.url}")
    logger.info(f"Download to: {file.dest}")
    if file.dest.exists():
        logger.debug(f"File {file.dest} already exists")

    if dry_run:
        return []
    try:
        req = urllib.request.urlopen(file.url)
        with open(file.dest, "wb") as handle:
            while True:
                chunk = req.read(1024)
                if not chunk:
                    break
                handle.write(chunk)
    except Exception as e:
        logger.debug(e)
    return []


def common_query(maybe_include_user_pass: bool) -> str:
    params = {
        DEVID_PARAM: devid,
        DEVPASSWORD_PARAM: devpassword,
        SOFTNAME_PARAM: SOFTNAME,
        OUTPUT_PARAM: DEFAULT_OUTPUT,
    }
    if maybe_include_user_pass and ssid and sspassword:
        params[SSID_PARAM] = ssid
        params[SSPASSWORD_PARAM] = sspassword
    return urllib.parse.urlencode(params)


def rominfo_query(rom_file: Path,
                  include_checksum: bool) -> tuple[str, ChecksumInfo]:
    system_id = SUPPORTED_FILE_TYPE_ID[rom_file.suffix.lower()]
    params = {
        SYSTEMEID_PARAM: system_id,
        ROMTYPE_PARAM: "rom",
        ROMNAME_PARAM: rom_file.name
    }
    checksum: ChecksumInfo = None
    if include_checksum:
        checksum = ChecksumInfo(rom_file)
        params[CRC_PARAM] = checksum.crc
        params[MD5_PARAM] = checksum.md5
        params[ROMSHA1_PARAM] = checksum.sha1
    return urllib.parse.urlencode(params), checksum


def read_credentials():
    config = configparser.ConfigParser()
    config.read(INI_FILE)
    if config.has_option(DEFAULT, DEVID_PARAM) and config.has_option(
            DEFAULT, DEVPASSWORD_PARAM):
        global devid, devpassword, ssid, sspassword
        devid = config[DEFAULT][DEVID_PARAM]
        devpassword = config[DEFAULT][DEVPASSWORD_PARAM]
        ssid = config[DEFAULT][SS_NAME]
        sspassword = config[DEFAULT][SS_PASS]
    return None, None


def save_sample_ini():
    config = configparser.ConfigParser()
    config[DEFAULT] = {
        DEVID_PARAM: "",
        DEVPASSWORD_PARAM: "",
        SS_NAME: "",
        SS_PASS: ""
    }
    with open(INI_FILE, 'w') as configfile:
        config.write(configfile)


def init_logger():
    global logger
    logger = logging.getLogger('pyscraper')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('pyscraper.log')
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)


if __name__ == '__main__':
    sys.exit(main())
