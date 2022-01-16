import argparse
import configparser
import sys
from pathlib import Path
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
SOFTNAME = "PyScrapper"
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

INI_FILE = "pyscrapper.ini"
DEFAULT = "screenscraper.fr"
SS_NAME = "nickname"
SS_PASS = "password"

SUPPORTED_FILE_TYPE_ID = {".nes": "3"}

devid: str
devpassword: str
ssid: str
sspassword: str
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


def main() -> int:
    init_logger()

    parser = argparse.ArgumentParser(
        description="Scrap rom information from screenscraper.fr")
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
                        help="Scrap recursively in a directory")
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
                        help="Media type to scrap. Default to title.")
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
        logger.debug("Input does not exist")
        return -1

    output_dir: Path
    if args.output:
        if args.output.exists() and args.output.is_dir():
            output_dir = args.output
        else:
            logger.debug("Invalid output directory")
    else:
        output_dir = input if input.is_dir() else input.parent

    read_credentials()
    if not devid or not devpassword:
        logger.debug(f"Set dev credentials in sample {INI_FILE} file!")
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

    return scrap(input, output_dir, args.recursive, args.rename, args.checksum,
                 args.update_cache)


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
                logger.debug(response_data.decode('utf-8'))
    except Exception as e:
        logger.debug(e)
    return 1


def scrap(input: Path, output_dir: Path, recursive: bool, rename: bool,
          send_checksum: bool, update_cache: bool) -> int:
    if input.is_dir():
        glob = input.rglob("*.*") if recursive else input.glob("*.*")
        count = 0
        for f in glob:
            scrap_single_file(f, output_dir, send_checksum, rename)
            count += 1
            # if count > 20:
            #     break
    else:
        return scrap_single_file(input, output_dir, send_checksum, rename)
    return 0


def scrap_single_file(input: Path, output_dir: Path, send_checksum: bool,
                      rename: bool) -> int:
    if input.suffix.lower() not in SUPPORTED_FILE_TYPE_ID:
        logger.debug(f"Unsupported rom type for scrapping: {input}")
        return -1
    rom_query_param, checksum = rominfo_query(input, send_checksum)
    params = common_query(True) + '&' + rom_query_param
    url = SS_API2_BASE_URL + ROM_INFO_PATH + "?" + params
    logger.debug(url)
    try:
        with urllib.request.urlopen(url) as response:
            response_data = response.read()
            try:
                json_object = json.loads(response_data)
                process_response(input, output_dir, json_object, checksum,
                                 rename)
            except ValueError:
                logger.debug(response_data.decode('utf-8'))
                return -1
    except Exception as e:
        logger.debug(e)
        return -1
    return 0


def process_response(input: Path, output_dir: Path, ss_data: dict,
                     checksum: ChecksumInfo, rename: bool):
    game_data = ss_data.get('response', {}).get('jeu')
    if not game_data:
        logger.warning(f"{input.name}: has no game data")
        return

    rom_data = game_data.get('rom')
    if checksum:
        if checksum.crc == rom_data.get(
                'romcrc') and checksum.md5 == rom_data.get(
                    'rommd5') and checksum.sha1 == rom_data.get('romsha1'):
            logger.debug(f"{input.name}: checksum matches")
        else:
            logger.warning(f"{input.name}: has no match by checksum")
            return
    remote_rom_name = rom_data.get('romfilename')
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
                input.rename(remote_rom_name)

    #TODO: Download title.
    return


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
    logger = logging.getLogger('pyscrapper')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('pyscrapper.log')
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
