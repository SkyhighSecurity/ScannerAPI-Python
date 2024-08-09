import os
import json
import socket
import requests
import tempfile
import logging
from flask import Flask, request, jsonify
from io import BytesIO
import boto3
from datetime import datetime, timedelta

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Environment variables
ICAP_SERVER = os.getenv("ICAPSERVER", "54.89.242.83")
ICAP_CLIENT = os.getenv("ICAPCLIENT", "192.168.0.1")
ICAP_PORT = int(os.getenv("ICAPPORT", "1344"))
ICAP_SERVICE_NAME = "avscan"
VERSION = "1.0"
USERAGENT = "Rest2ICAP"
ICAP_TERMINATOR = "\r\n\r\n"
HTTP_TERMINATOR = "0\r\n\r\n"
STD_PREVIEW_SIZE = 4096
STD_RECEIVE_LENGTH = 4194304
STD_SEND_LENGTH = 4096

class ICAPException(Exception):
    pass

class ICAPClient:
    def __init__(self, server_host, port, icap_service, client_ip, preview_size=-1):
        self.icap_service = icap_service
        self.port = port
        self.client_ip = client_ip
        self.std_preview_size = preview_size if preview_size != -1 else STD_PREVIEW_SIZE

        iplist = socket.gethostbyname_ex(server_host)
        if not iplist:
            raise ValueError("Unable to get ICAP server address from specified host name.")
        
        ip_address = iplist[2][0]
        self.server_ip = ip_address
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sender.connect((ip_address, port))
        
        if preview_size == -1:
            parse_me = self.get_options()
            response_map = self.parse_header(parse_me)
            status = int(response_map.get("StatusCode", 0))
            if status == 200:
                self.std_preview_size = int(response_map.get("Preview", STD_PREVIEW_SIZE))
            else:
                raise ICAPException("Could not get preview size from server")
    
    def scan_stream(self, byte_stream, filename):
        file_size = len(byte_stream.read())
        byte_stream.seek(0)
        
        request_header = f"GET http://{self.client_ip}/{filename} HTTP/1.1\r\nHost: {self.client_ip}\r\n\r\n".encode('ascii')
        response_header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".encode('ascii')
        res_header = len(request_header)
        res_body = res_header + len(response_header)
        preview_size = min(self.std_preview_size, file_size)
        
        icap_request = (
            f"RESPMOD icap://{self.server_ip}:{self.port}/{self.icap_service} ICAP/{VERSION}\r\n"
            f"Connection: close\r\n"
            f"Encapsulated: req-hdr=0 res-hdr={res_header} res-body={res_body}\r\n"
            f"Host: {self.server_ip}\r\n"
            f"User-Agent: {USERAGENT}\r\n"
            f"X-Client-IP: {self.client_ip}\r\n"
            f"Allow: 204\r\n"
            f"Preview: {preview_size}\r\n\r\n"
        ).encode('ascii')

        preview_size_hex = f"{preview_size:X}\r\n".encode('ascii')
        
        self.sender.settimeout(600)
        self.sender.sendall(icap_request)
        self.sender.sendall(request_header)
        self.sender.sendall(response_header)
        self.sender.sendall(preview_size_hex)
        
        chunk = byte_stream.read(preview_size)
        self.sender.sendall(chunk)
        self.sender.sendall(b"\r\n")
        
        if file_size <= preview_size:
            self.sender.sendall(b"0; ieof\r\n\r\n")
        else:
            self.sender.sendall(b"0\r\n\r\n")

        response_map = self.parse_header(self.get_next_header(ICAP_TERMINATOR))
        status = int(response_map.get("StatusCode", 0))
        result = {
            "Filename": filename,
            "Infected": False,
            "HasError": False,
            "ErrorMessage": ""
        }
        
        if file_size > preview_size and status == 100:
            while (chunk := byte_stream.read(STD_SEND_LENGTH)):
                chunk_hex = f"{len(chunk):X}\r\n".encode('ascii')
                self.sender.sendall(chunk_hex)
                self.sender.sendall(chunk)
                self.sender.sendall(b"\r\n")
            self.sender.sendall(b"0\r\n\r\n")
        
        response_map = self.parse_header(self.get_next_header(ICAP_TERMINATOR))
        status = int(response_map.get("StatusCode", 0))
        
        if status == 204:
            return result
        elif status == 200:
            response = self.get_next_header(HTTP_TERMINATOR)
            if "McAfee Web Gateway - Notification" in response:
                result["Infected"] = True
                result["InfectionName"] = response_map.get("X-Virus-Name", "Unknown")
                return result
        else:
            raise ICAPException("Unrecognized or no status code in response header.")
    
    def get_options(self):
        msg = (
            f"OPTIONS icap://{self.server_ip}/{self.icap_service} ICAP/{VERSION}\r\n"
            f"Host: {self.server_ip}\r\n"
            f"User-Agent: {USERAGENT}\r\n"
            f"Encapsulated: null-body=0\r\n\r\n"
        ).encode('ascii')
        self.sender.sendall(msg)
        return self.get_next_header(ICAP_TERMINATOR)
    
    def get_next_header(self, terminator):
        buffer = b""
        while True:
            chunk = self.sender.recv(1)
            if not chunk:
                raise ICAPException("Error in getNextHeader() method")
            buffer += chunk
            if buffer.endswith(terminator.encode('ascii')):
                break
        return buffer.decode('ascii')
    
    def parse_header(self, response):
        headers = {}
        lines = response.split("\r\n")
        headers["StatusCode"] = lines[0].split(" ")[1]
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value
        return headers
    
    def close(self):
        self.sender.shutdown(socket.SHUT_RDWR)
        self.sender.close()

# Utility functions
def download_file(url):
    response = requests.get(url)
    response.raise_for_status()
    return BytesIO(response.content)

def download_s3_file(s3_uri):
    s3_client = boto3.client('s3')
    s3_uri_parts = s3_uri.replace("s3://", "").split("/", 1)
    bucket_name, object_key = s3_uri_parts[0], s3_uri_parts[1]
    file_obj = tempfile.NamedTemporaryFile(delete=False)
    s3_client.download_file(bucket_name, object_key, file_obj.name)
    file_obj.seek(0)
    return file_obj

class MVCConnection:
    def __init__(self):
        self.iam_token = self.IAMToken()
        self.mvc_authinfo = self.MVCAuthInfo()

    class IAMToken:
        def __init__(self):
            self.token_type = ""
            self.expires_at = None
            self.access_token = ""

    class MVCAuthInfo:
        def __init__(self):
            self.token_type = ""
            self.access_token = ""
            self.refresh_token = ""
            self.tenant_ID = ""
            self.tenant_Name = ""
            self.userID = ""
            self.email = ""
            self.expires_at = None

    def is_authenticated(self):
        if not self.iam_token.access_token or datetime.now() > self.iam_token.expires_at:
            return False
        return True

    async def authenticate_async(self, username, password, bps_tenantid, env, log):
        iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token"
        env = env or "www.myshn.net"

        iam_payload = {
            "client_id": "0oae8q9q2y0IZOYUm0h7",
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "shn.con.r web.adm.x web.rpt.x web.rpt.r web.lst.x web.plc.x web.xprt.x web.cnf.x uam:admin",
            "tenant_id": bps_tenantid,
        }

        try:
            iam_response = requests.post(iam_url, data=iam_payload)
            if iam_response.status_code != 200:
                log.info(f"Unsuccessful authentication of {username} to McAfee IAM. HTTP Status: {iam_response.status_code}")
                return False
            iam_response_data = iam_response.json()
            self.iam_token.access_token = iam_response_data["access_token"]
            self.iam_token.expires_at = datetime.now() + timedelta(seconds=int(iam_response_data["expires_in"]))
            self.iam_token.token_type = iam_response_data["token_type"]
            log.info(f"Successful authentication of {username} to McAfee IAM and fetch of iam_token")
        except Exception as e:
            log.info(f"Exception in IAM authentication: {e}")
            return False

        mvc_url = f"https://{env}/neo/neo-auth-service/oauth/token?grant_type=iam_token"
        try:
            mvc_response = requests.post(mvc_url, headers={"x-iam-token": self.iam_token.access_token})
            if mvc_response.status_code != 200:
                log.info(f"Unsuccessful authentication of {username} to MVISION Cloud. HTTP Status: {mvc_response.status_code}")
                return False
            mvc_response_data = mvc_response.json()
            self.mvc_authinfo.token_type = mvc_response_data["token_type"]
            self.mvc_authinfo.access_token = mvc_response_data["access_token"]
            self.mvc_authinfo.refresh_token = mvc_response_data["refresh_token"]
            self.mvc_authinfo.tenant_ID = mvc_response_data["tenantID"]
            self.mvc_authinfo.tenant_Name = mvc_response_data["tenantName"]
            self.mvc_authinfo.userID = mvc_response_data["userId"]
            self.mvc_authinfo.email = mvc_response_data["email"]
            self.mvc_authinfo.expires_at = datetime.now() + timedelta(seconds=int(mvc_response_data["expires_in"]))
            log.info(f"Successful authentication of {username} to MVISION Cloud, got access token.")
            return True
        except Exception as e:
            log.info(f"Exception in MVISION Cloud authentication: {e}")
            return False

# Flask routes
@app.route('/avscan', methods=['GET', 'POST'])
def av_scan():
    url_to_scan = request.args.get('url')
    s3_uri = request.args.get('s3uri')
    use_file_cache = request.args.get('usefilecache', 'false').lower() == 'true'

    icap_client = ICAPClient(ICAP_SERVER, ICAP_PORT, ICAP_SERVICE_NAME, ICAP_CLIENT)
    
    try:
        if url_to_scan:
            filename = os.path.basename(url_to_scan)
            if use_file_cache:
                file_obj = tempfile.NamedTemporaryFile(delete=False)
                with download_file(url_to_scan) as file_stream:
                    file_obj.write(file_stream.read())
                with open(file_obj.name, 'rb') as file_stream:
                    scan_result = icap_client.scan_stream(file_stream, filename)
                os.unlink(file_obj.name)
            else:
                with download_file(url_to_scan) as file_stream:
                    scan_result = icap_client.scan_stream(file_stream, filename)
        elif s3_uri:
            filename = os.path.basename(s3_uri)
            if use_file_cache:
                file_obj = download_s3_file(s3_uri)
                with open(file_obj.name, 'rb') as file_stream:
                    scan_result = icap_client.scan_stream(file_stream, filename)
                os.unlink(file_obj.name)
            else:
                with download_s3_file(s3_uri) as file_stream:
                    scan_result = icap_client.scan_stream(file_stream, filename)
        else:
            return jsonify({"error": "No object to scan"}), 400

        return jsonify(scan_result)
    except Exception as e:
        logging.error(f"Scan failure, unknown error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        icap_client.close()

@app.route('/dlpscan', methods=['GET', 'POST'])
async def dlp_scan():
    request_body = await request.get_data(as_text=True)
    url_to_scan = request.args.get('url')
    file_name = os.path.basename(url_to_scan)

    env = "www.myshn.net"
    policyid = "520065"

    conn = MVCConnection()

    if conn.is_authenticated():
        logging.info("Already authenticated...")
        return jsonify({"message": "Already authenticated..."})

    is_authenticated = await conn.authenticate_async("nate@mvision-ebc.com", "9hy%QP1hxoX&", "A9DD97B4-FBB7-49F8-80A0-8A2164A1E17C", "", logging)
    logging.info(f"Authenticating, result: {is_authenticated}")

    mvc_url = f"https://{env}/neo/zeus/v1/admin/content-parser/policy/evaluation/silo/{conn.mvc_authinfo.tenant_ID}/1"
    logging.info(f"Calling MVC API: {mvc_url}")

    try:
        response_stream = download_file(url_to_scan)
        logging.info(f"Successfully fetched {file_name}")

        mvc_client = requests.Session()
        mvc_client.headers.update({
            "x-access-token": conn.mvc_authinfo.access_token,
            "x-refresh-token": conn.mvc_authinfo.refresh_token
        })

        form_data = {
            "file": (file_name, response_stream, "application/octet-stream"),
            "numOfTimes": (None, "1"),
            "policy_ids": (None, policyid)
        }

        mvc_response = mvc_client.post(mvc_url, files=form_data)
        mvc_response_data = mvc_response.json()

        logging.info(f"Processed DLP Policy Evaluation: Filename={mvc_response_data['fileName']} Policy Name={mvc_response_data['policy_name']} Result={mvc_response_data['evaluation_result']}")

        return jsonify({"DLP Result": mvc_response_data})
    except Exception as e:
        logging.error(f"Exception in DLP API call: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
