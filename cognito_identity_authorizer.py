import os
import json
import urllib.request
import logging
import jwt
import time
from functools import lru_cache
from jwt.api_jwk import PyJWK
import cryptography

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = "eu-west-1" 

@lru_cache(maxsize=32)
def get_jwks(issuer, expiry):
    
    if expiry < time.time():
        logger.info(f"Cache expired, fetching new JWKS")
    
    try:
        logger.info(f"Fetching JWKS from {issuer}")
        keys_url = f"{issuer}/.well-known/jwks.json"
        logger.info(f"JWKS URL: {keys_url}")
        
        req = urllib.request.Request(keys_url, headers={'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                logger.info(f"JWKS request status code: {status_code}")
                jwks = json.load(response)
                logger.info(f"JWKS response: {jwks}")
                
            cache_expiry = int(time.time()) + 86400  
            return jwks, cache_expiry
        except urllib.error.HTTPError as http_err:
            logger.error(f"HTTP error fetching JWKS: {http_err.code} - {http_err.reason}")
            logger.error(f"Error response body: {http_err.read().decode('utf-8')}")
            raise
        except urllib.error.URLError as url_err:
            logger.error(f"URL error fetching JWKS: {url_err.reason}")
            raise
    except Exception as e:
        logger.error(f"Error fetching JWKS: {str(e)}")
        return {}, int(time.time()) + 60

def get_token_from_header(auth_header):
    if not auth_header:
        raise ValueError("Authorization header is missing")
    
    if auth_header.lower().startswith('bearer '):
        return auth_header.split()[1]
    
    return auth_header

def extract_token_info(token):
    try:
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified_payload.get('iss')
        
        audience = unverified_payload.get('aud')
        if not audience:
            audience = unverified_payload.get('clientid')
            if not audience:
                audience = unverified_payload.get('client_id')
        
        if not issuer:
            raise ValueError("Token missing 'iss' claim")
        if not audience:
            raise ValueError("Token missing audience claim (checked 'aud', 'clientid', and 'client_id')")
            
        cognito_pool_id = issuer.split('/')[-1]
        
        app_client_id = audience[0] if isinstance(audience, list) else audience
        
        return {
            'issuer': issuer,
            'cognito_pool_id': cognito_pool_id,
            'app_client_id': app_client_id
        }
    except jwt.exceptions.PyJWTError as e:
        logger.warning(f"Invalid token format: {str(e)}")
        raise ValueError("Invalid token format")
def validate_token(token):
    token_info = extract_token_info(token)
    issuer = token_info['issuer']
    cognito_pool_id = token_info['cognito_pool_id']
    app_client_id = token_info['app_client_id']
    
    jwks_data, _ = get_jwks(issuer, int(time.time()))
    
    try:
        headers = jwt.get_unverified_header(token)
    except jwt.JWTError as e:
        logger.warning(f"Invalid token header: {str(e)}")
        raise ValueError("Invalid token format")
    
    if 'kid' not in headers:
        raise ValueError("Token header missing 'kid' field")
    
    matching_keys = [k for k in jwks_data.get('keys', []) if k.get('kid') == headers['kid']]
    if not matching_keys:
        jwks_data, _ = get_jwks(issuer, 0)
        matching_keys = [k for k in jwks_data.get('keys', []) if k.get('kid') == headers['kid']]
        if not matching_keys:
            raise ValueError("Matching key not found in JWKS")
    
    jwk_dict = matching_keys[0]
    public_key = PyJWK.from_dict(jwk_dict).key
    
    unverified_payload = jwt.decode(
        token,
        public_key,
        algorithms=['RS256'],
        options={
            'verify_signature': True,
            'verify_exp': True,
            'verify_nbf': True,
            'verify_iat': True,
            'verify_aud': True, 
            'verify_iss': True,
            'require_exp': True,
            'require_iat': True,
            'require_nbf': False
        },
        issuer=issuer
    )
    
    audience = unverified_payload.get('aud') or unverified_payload.get('clientid') or unverified_payload.get('client_id')
    if not audience:
        logger.warning("Token is missing audience claim (checked 'aud', 'clientid', and 'client_id')")
        raise ValueError("Token is missing audience claim")
        
    if isinstance(audience, list):
        if app_client_id not in audience:
            raise ValueError("Token audience does not match app client ID")
    else:
        if audience != app_client_id:
            raise ValueError("Token audience does not match app client ID")
    
    return unverified_payload

def generate_policy(principal_id, effect, resource, context):
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }
    
    if context:
        policy['context'] = context
    
    return policy

def lambda_handler(event, context):
    try:
        print(f"This is event {event}")
        if 'authorizationtoken' not in event["headers"]:
            logger.error("Authorization token not found in event")
            raise Exception("Unauthorized")
        
        token = get_token_from_header(event['headers']['authorizationtoken'])
        print(f"This is token {token}")
        payload = validate_token(token)
        
        context_data = {
            'userId': payload.get('sub', ''),
            'email': payload.get('email')[0] if isinstance(payload.get('email', ''), list) else payload.get('email', ''), 
            'name': payload.get('name', ''),
            'scope': payload.get('scope', ''),
            'groups': ','.join(payload.get('cognito:groups', [])) if 'cognito:groups' in payload else ''
        }
        
        logger.info(f"Successfully authenticated user: {context_data['userId']}")
        print(f"This is methodArn {event.get('methodArn','')}")
        print(f"This is generate policy {generate_policy( principal_id=payload['sub'],
            effect='Allow',
            resource=event.get('methodArn',''),
            context=context_data)}")
            
        return generate_policy(
            principal_id=payload['sub'],
            effect='Allow',
            resource=event.get('methodArn',''),
            context=context_data
        )
    
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        return generate_policy(
            principal_id="unauthorized",
            effect='Deny',
            resource=event.get('methodArn',''),
            context={"errorMessage": str(e)}
        )
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        return generate_policy(
            principal_id="unauthorized",
            effect='Deny',
            resource=event.get('methodArn',''),
            context={"errorMessage": f"Authentication failed: {str(e)}"}
        )

