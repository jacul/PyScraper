import argparse
from concurrent import futures
from concurrent.futures import ThreadPoolExecutor
import configparser
import sys
from pathlib import Path
from typing import List
from urllib.error import HTTPError
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

ALL = "all"
TITLE = "title"
SCREENSHOT = "screenshot"
SS = "ss"
SS_TITLE = "sstitle"

PARAM_TO_MEDIA_TYPE = {TITLE: SS_TITLE, SCREENSHOT: SS}
MEDIA_TYPE_TO_PARAM = {SS_TITLE: TITLE, SS: SCREENSHOT}

SUPPORTED_FILE_TYPE_ID = {
    ".nes": "3",
    ".smc": "4",
    ".sfc": "4",
    ".fig": "4",
    ".gba": "12"
}

INI_FILE = "pyscraper.ini"
DEFAULT = 'screenscraper.fr'
SS_NAME = "nickname"
SS_PASS = "password"
MAX_THREADS = "maxthreads"
REGISTERED_ONLY = "registeredonly"

__devid: str = None
__devpassword: str = None
__ssid: str = None
__sspassword: str = None
__dry_run: bool
__registered_user_only: bool = None
__maximum_threads: int = None

__input: Path = None
__output_dir: Path = None
__recursive = False
__rename = False
__send_checksum = False
__update_cache = False
__download_media_types = {}


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

    def __init__(self, file: Path, output_dir: Path, media: dict):
        url = media.get("url")
        parent_folder = file.parent if output_dir is None else output_dir
        media_name = MEDIA_TYPE_TO_PARAM.get(media.get("type"), "media")
        media_folder = parent_folder.joinpath(media_name)
        name = file.stem + "." + media["format"]
        self.url = url
        self.dir = media_folder
        self.dest = media_folder.joinpath(name)


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
                        "--media-types",
                        choices=[ALL, TITLE, SCREENSHOT],
                        default=[TITLE],
                        help="Media type to scrape. Default to title.")
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help="Only writes to log, does not rename roms or download media files"
    )
    args = parser.parse_args()

    if args.input is None:
        parser.print_usage()
        return 0

    global __input
    __input = args.input
    if not __input.exists():
        logger.warning("Input does not exist")
        return -1

    global __output_dir
    if args.output:
        if args.output.exists() and args.output.is_dir():
            __output_dir = args.output
        else:
            logger.warning("Invalid output directory")

    global __dry_run, __recursive, __rename, __send_checksum, __update_cache, __download_media_types
    __dry_run = args.dry_run
    __recursive = args.recursive
    __rename = args.rename
    __send_checksum = args.checksum
    __update_cache = args.update_cache
    __download_media_types = PARAM_TO_MEDIA_TYPE.values(
    ) if ALL in args.media_types else {
        PARAM_TO_MEDIA_TYPE[type]
        for type in args.media_types
    }

    if init_configs() != 0:
        return -1

    return scrape()


def get_registered_user_only() -> bool:
    url = SS_API2_BASE_URL + INFRA_INFO_PATH + "?" + common_query(False)

    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                result = json_object.get("response",
                                         {}).get("serveurs",
                                                 {}).get("closefornomember")
                logger.debug(
                    f"Fetching forum closed for non-registered users: {result}"
                )
                return bool(result)
            except ValueError as e:
                logger.exception(e)
    except HTTPError as error:
        logger.error(error.reason + " " + url)
    except Exception as e:
        logger.exception(e)
    return False


def get_maximum_threads() -> int:
    if __ssid is None or __sspassword is None:
        return 1

    url = SS_API2_BASE_URL + USER_INFO_PATH + "?" + common_query(True)

    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                result = json_object.get("response",
                                         {}).get("ssuser",
                                                 {}).get("maxthreads")
                max_threads = int(result or 1)
                logger.debug(
                    f"Fetching maximum threads to scrape: {max_threads}")
                return max_threads
            except ValueError as e:
                logger.exception(e)
    except HTTPError as error:
        logger.error(error.reason + " " + url)
    except Exception as e:
        logger.exception(e)
    return 1


def scrape() -> int:
    rom_files = []
    if __input.is_dir():
        for f in __input.rglob("*.*") if __recursive else __input.glob("*.*"):
            rom_files.append(f)
    else:
        rom_files.append(__input)

    futures_list = []
    with ThreadPoolExecutor(max_workers=__maximum_threads) as executor:
        for f in rom_files:
            future = executor.submit(
                scrape_single_file,
                f,
            )
            futures_list.append(future)
            if len(futures_list) >= __maximum_threads or f == rom_files[-1]:
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


def scrape_single_file(file: Path) -> List[DownloadFile]:
    if file.suffix.lower() not in SUPPORTED_FILE_TYPE_ID:
        logger.debug(f"Unsupported rom type for scraping: {file}")
        return []
    rom_query_param, checksum = rominfo_query(file)
    params = common_query(True) + '&' + rom_query_param
    url = SS_API2_BASE_URL + ROM_INFO_PATH + "?" + params
    logger.debug(url)
    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                return process_response(file, json_object, checksum)
            except ValueError as e:
                logger.exception(e)
    except HTTPError as error:
        logger.error(error.reason + " " + file.name)
    except Exception as e:
        logger.exception(e)
    return []


def process_response(file: Path, ss_data: dict,
                     checksum: ChecksumInfo) -> List[DownloadFile]:
    game_data = ss_data.get('response', {}).get('jeu')
    if game_data is None:
        logger.warning(f"{file.name}: has no game data")
        return []

    rom_data = game_data.get('rom', {})

    file = maybe_rename_rom(file, rom_data, checksum)

    rom_regions = rom_data.get('romregions')
    media_data = game_data.get('medias', {})

    return download_available_media(file, media_data, rom_regions)


def maybe_rename_rom(file: Path, rom_data: dict,
                     checksum: ChecksumInfo) -> Path:
    if checksum:
        if checksum.crc == rom_data.get(
                'romcrc') and checksum.md5 == rom_data.get(
                    'rommd5') and checksum.sha1 == rom_data.get('romsha1'):
            logger.debug(f"{file.name}: checksum matches")
        else:
            logger.warning(f"{file.name}: has no match by checksum")

    remote_rom_name = rom_data.get('romfilename', '')
    found_rom_with_same_suffix = remote_rom_name.lower().endswith(
        file.suffix.lower())

    if not found_rom_with_same_suffix:
        logger.warning(f"{file.name}: has no match by name")
        return file

    if __rename and found_rom_with_same_suffix:
        if file.name == remote_rom_name:
            logger.info(f"{file.name}: already the same name as remote")
            return file

        logger.info(f"{file.name}: rename to {remote_rom_name}")
        if __dry_run: return file

        rename_to = file.parent.joinpath(remote_rom_name)
        if rename_to.exists():
            logger.warning(f"{remote_rom_name} already exists, skipping")
        else:
            file = file.rename(file.parent.joinpath(remote_rom_name))
    return file


def download_available_media(file: Path, media_data: dict,
                             rom_regions: str) -> List[DownloadFile]:
    files = []
    if len(__download_media_types) == 0:
        return files

    type_to_media = {}
    for media in media_data:
        media_type = media.get("type")
        if media_type in __download_media_types:
            type_media = type_to_media.get(media_type, [])
            if media.get("region") == rom_regions:
                type_media.insert(0, media)
            else:
                type_media.append(media)
            type_to_media[media_type] = type_media

    for media_type in type_to_media:
        media = type_to_media[media_type]
        if len(media) > 0:
            download_file = DownloadFile(file, __output_dir, media[0])
            if not __dry_run and (not download_file.dest.exists()
                                  or __update_cache):
                files.append(download_file)
            else:
                logger.debug(f"Skipping file {download_file.dest}")

    return files


def download_file(file: DownloadFile) -> List:
    logger.debug(f"Fetching: {file.url}")
    logger.info(f"Download to: {file.dest}")
    if not file.dir.exists():
        logger.debug(f"Creating folder {file.dir}")
        file.dir.mkdir()

    if file.dest.exists():
        logger.debug(f"Overwrite existing file {file.dest}")

    if __dry_run:
        return []
    try:
        req = urllib.request.urlopen(file.url)
        with open(file.dest, "wb") as handle:
            while True:
                chunk = req.read(1024)
                if not chunk:
                    break
                handle.write(chunk)
    except HTTPError as error:
        logger.error(error.reason + " " + file.url)
    except Exception as e:
        logger.exception(e)
    return []


def common_query(maybe_include_user_pass: bool) -> str:
    params = {
        DEVID_PARAM: __devid,
        DEVPASSWORD_PARAM: __devpassword,
        SOFTNAME_PARAM: SOFTNAME,
        OUTPUT_PARAM: DEFAULT_OUTPUT,
    }
    if maybe_include_user_pass and __ssid and __sspassword:
        params[SSID_PARAM] = __ssid
        params[SSPASSWORD_PARAM] = __sspassword
    return urllib.parse.urlencode(params)


def rominfo_query(rom_file: Path) -> tuple[str, ChecksumInfo]:
    system_id = SUPPORTED_FILE_TYPE_ID[rom_file.suffix.lower()]
    params = {
        SYSTEMEID_PARAM: system_id,
        ROMTYPE_PARAM: "rom",
        ROMNAME_PARAM: rom_file.name
    }
    checksum: ChecksumInfo = None
    if __send_checksum:
        checksum = ChecksumInfo(rom_file)
        params[CRC_PARAM] = checksum.crc
        params[MD5_PARAM] = checksum.md5
        params[ROMSHA1_PARAM] = checksum.sha1
    return urllib.parse.urlencode(params), checksum


def init_configs() -> int:
    load_config_file()
    if __devid is None or __devpassword is None:
        logger.info(f"Set dev credentials in sample {INI_FILE} file!")
        save_sample_ini()
        return -1

    global __registered_user_only
    if __registered_user_only == None:
        __registered_user_only = get_registered_user_only()
        append_ini(REGISTERED_ONLY, __registered_user_only)

    if __registered_user_only and not (__ssid and __sspassword):
        logger.error(f"API closed for non-registered users, \
                set forum nicknamd/password in {INI_FILE} file")
        return -1

    global __maximum_threads
    if __maximum_threads is None:
        __maximum_threads = get_maximum_threads()
        append_ini(MAX_THREADS, __maximum_threads)
    return 0


def load_config_file():
    config = configparser.ConfigParser()
    config.read(INI_FILE)
    if config.has_option(DEFAULT, DEVID_PARAM) and config.has_option(
            DEFAULT, DEVPASSWORD_PARAM):
        global __devid, __devpassword, __ssid, __sspassword
        __devid = config[DEFAULT][DEVID_PARAM]
        __devpassword = config[DEFAULT][DEVPASSWORD_PARAM]
        __ssid = config[DEFAULT][SS_NAME]
        __sspassword = config[DEFAULT][SS_PASS]

    if config.has_option(DEFAULT, REGISTERED_ONLY):
        global __registered_user_only
        __registered_user_only = config.getboolean(DEFAULT, REGISTERED_ONLY)

    if config.has_option(DEFAULT, MAX_THREADS):
        global __maximum_threads
        __maximum_threads = config.getint(DEFAULT, MAX_THREADS)
    return


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


def append_ini(key: str, value):
    config_update = configparser.RawConfigParser()
    config_update.read(INI_FILE)
    config_update.set(DEFAULT, key, value)

    with open(INI_FILE, 'w') as f:
        config_update.write(f)


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
