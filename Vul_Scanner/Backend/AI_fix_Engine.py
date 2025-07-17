from dotenv import  load_dotenv
import os
from openai import OpenAI

load_dotenv()

API_KEY = os.getenv("OPEN_API_KEY")

def suggest_fix_engine(vulnerabilities):
    pass