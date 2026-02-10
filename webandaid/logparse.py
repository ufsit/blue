import argparse
import collections
import datetime
import json
import pathlib
import sys
import time

def parse_modsec_json(json_dict: dict) -> str:
    output_str: str = ""

    first_line: str = "{request_time} {request_ip}:{remote_port}\n"
    # Add the client IP

    output_str += first_line.format(
        request_time=datetime.datetime.fromtimestamp(
                json_dict["transaction"]["unix_timestamp"] / 1000000000)
                .strftime("%m/%d %H:%M:%S"),
        request_ip=json_dict["transaction"]["client_ip"],
        remote_port=json_dict["transaction"]["client_port"],
    )

    for waf_message in json_dict["messages"]:
        waf_message_line: str = "  {rule_id} | {severity} | {rule_msg} | {rule_data}\n"
        output_str += waf_message_line.format(
            rule_id=waf_message["data"]["id"],
            severity=waf_message["data"]["severity"],
            rule_msg=waf_message["data"]["msg"],
            rule_data=waf_message["data"]["data"],
        )
    return output_str

def parse_caddy_json(json_dict: dict) -> str:
    output_str: str = ""

    log_line_header: str = "{timestamp} {ip}:{port} {method} {host}{uri}\n"
    output_str += log_line_header.format(
        timestamp=datetime.datetime.fromtimestamp(
                json_dict["ts"]).strftime("%m/%d %H:%M:%S"),
        ip=json_dict["request"]["remote_ip"],
        port=json_dict["request"]["remote_port"],
        method=json_dict["request"]["method"],
        host=json_dict["request"]["host"],
        uri=json_dict["request"]["uri"],
    )

    headers_to_log: dict[str, str] = {
        "Accept": "Accept",
        "Accept-Encoding": "Accept-Encoding",
        "Accept-Language": "Accept-Language",
        "Connection": "Connection",
        "User-Agent": "UA", 
        "Upgrade-Insecure-Requests": "Upgrade-Insecure-Requests", 
    }

    for header_to_log, header_abbr in headers_to_log.items():
        header_line: str = "  {header_name}: {header_value}\n"

        if header_to_log in json_dict["request"]["headers"]:
            output_str += header_line.format(
                header_name=header_abbr,
                header_value=json_dict["request"]["headers"][header_to_log][0],
            )
        else:
            output_str += header_line.format(
                header_name=header_abbr,
                header_value="<header missing>",
            )

    return output_str

def parse_json_line(json_line: bytes) -> str:
    """
    Parses an input JSON line into a string
    :param json_line: The line of text containing valid JSON
    :return: A string with the parsed line.
    """
    json_dict: dict = json.loads(json_line)
    if "transaction" in json_dict:
        return parse_modsec_json(json_dict)
    else:
        return parse_caddy_json(json_dict)
    return json_line.decode("utf-8")

def main(argv: list[str]) -> int:
    argparser: argparse.ArgumentParser = argparse.ArgumentParser()
    argparser.add_argument("input_file", type=pathlib.Path,
            help="The input file.")
    parsedargs: dict[str, typing.Any] = vars(argparser.parse_args(argv[1:]))

    buffer_size: int = 16
    current_json_line: bytearray = bytearray()

    with open(parsedargs["input_file"], "rb") as input_file:
        while True:
            input_buffer = input_file.read(buffer_size)
            newline_location: int = input_buffer.find(b"\n")
            if newline_location == -1:
                # No newline in this 
                current_json_line.extend(input_buffer)
            else:
                current_json_line.extend(input_buffer[:newline_location])
                print(parse_json_line(bytes(current_json_line)))
                current_json_line.clear()
                current_json_line.extend(input_buffer[newline_location+1:])
            if input_buffer == b"":
                # We've reached the end of the file for now.
                time.sleep(1)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
