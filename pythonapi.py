import base64
import hashlib
import hmac
import uuid
import datetime
import requests
import logging
import time
import json

def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)   

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

# first file logger
audit_logs = setup_logger('audit_logs', 'mimecast_audit_logs.log')
# second file logger
error_log = setup_logger('logging_log', 'mimecast_audit_log_errors.log', logging.ERROR)

# Setup required variables
base_url = "https://us-api.mimecast.com"
uri = "/api/audit/get-audit-events"
url = base_url + uri
access_key = 'YOUR_ACCESS_KEY'
secret_key = 'YOUR_SECRET_KEY'
app_id = 'YOUR_APP_ID'
app_key = 'YOUR_APP_KEY'
 
# Generate request header values
request_id = str(uuid.uuid4())
hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
 
# DataToSign is used in hmac_sha1
dataToSign = ':'.join([hdr_date, request_id, uri, app_key])
 
# Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
hmac_sha1 = hmac.new(base64.b64decode(secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
 
# Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
sig = base64.b64encode(hmac_sha1).rstrip()
 
# Create request headers
headers = {
    'Authorization': 'MC ' + access_key + ':' + sig.decode(),
    'x-mc-app-id': app_id,
    'x-mc-date': hdr_date,
    'x-mc-req-id': request_id,
    'Content-Type': 'application/json',
}

def CreatePayload():
    now = datetime.datetime.now()
    dates = list(map(lambda x: x.astimezone().replace(microsecond=0).isoformat(), [now - datetime.timedelta(minutes=15), now]))
    return {
        'meta':{},
        'data': [
            {
                'startDateTime': dates[0],
                'endDateTime': dates[1]
            }
        ]
    }

def MapJsonObjToECS(obj):
    '''
    Coming from Mimecast:
      "id": 
      "auditType": 
      "user": 
      "eventTime":
      "eventInfo": 
      "category": 
    '''
    ecs = {}
    ecs['event.id'] = obj['id']
    ecs['event.action']= obj['auditType']
    ecs['user.email']= obj['user']
    ecs['@timestamp']= obj['eventTime']
    ecs['message']= obj['eventInfo']
    return ecs


def FormatListNDJson(l):
    return ('\n'.join([str(x) for x in l])).rsplit('\n', 1)[0]
    

class SafeMimecastAuditLogQuery:
    def __init__(self):
        self.payload = CreatePayload()
        self.headers = headers

    def DoRateLimitedQuery(self):
        response = requests.post(url=url, headers=self.headers, data=str(self.payload), timeout=10)
        if response.status_code != 200:
            error_log.error("Error When calling mimecast api: " + response.status_code, response.json())
            if response.status_code == 429:
                error_log.error("Rate limit exceeded, waiting for X-RateLimit-Reset: " + response.headers['X-RateLimit-Reset'])
                time.sleep(response.headers['X-RateLimit-Reset'] / 1000)
                return self.DoRateLimitedQuery()
            return None
        
        data = response.json()
        if len(data['data']) > 0:
            fmt = FormatListNDJson(list(map(MapJsonObjToECS, data['data'])))
            audit_logs.info(fmt)
        
        if 'pagination' in data['meta']:
            if 'next' in data['meta']['pagination']:
                if 'pagination' not in self.payload['meta']:
                    self.payload['meta']['pagination'] = {}
                self.payload['meta']['pagination']['pageToken'] = data['meta']['pagination']['next']
                return self.DoRateLimitedQuery()
                
if __name__ == "__main__":
    s = SafeMimecastAuditLogQuery()
    s.DoRateLimitedQuery()