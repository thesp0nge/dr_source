import random
from lxml import etree

def reset_password(user):
    # VULNERABLE: INSECURE_TOKEN_GENERATION
    token = str(random.random())
    send_email(user.email, token)

def parse_xml(xml_data):
    # VULNERABLE: XXE (DTD resolve_entities enabled)
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_data, parser=parser)
    return root

def send_email(email, token):
    pass
