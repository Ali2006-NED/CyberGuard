from dotenv import load_dotenv
import os
from mistralai import Mistral

from Vul_Scanner.Backend.scanner import run_static_analysis

load_dotenv()

API_KEY = os.getenv("OPEN_API_KEY")

client = Mistral(api_key=API_KEY)


def suggest_fix_engine(vulnerabilities, model='mistral-large-latest'):
    if len(vulnerabilities) == 0:
        return None

    suggestions = []
    for vuln in vulnerabilities:
        prompt = f"""
        
        For the following vulnerability in the code file:
        
        File : {vuln['file']}
        Line : {vuln['start_line']}
        RuleId : {vuln['ruleId']}
        Message : {vuln['message']}
        
        Your task is to :
        
        1. Explain the detected vulnerability in detail.
        2. Suggest a secure code fix.
        3. Show correct code.
        
"""
        try:
            response = client.chat.complete(model=model,
                                            messages=[{"role": "system",
                                                       "content": "You are a secure coding assistant"},
                                                      {"role": "user", "content": prompt}],
                                            temperature=0.5)

            ai_reply = response.choices[0].message.content.strip()
            suggestions.append({
                'file': vuln['file'],
                'line': vuln['start_line'],
                'ruleId': vuln['ruleId'],
                'message': vuln['message'],
                'suggestion': ai_reply
            })
        except Exception as e:
            suggestions.append({
                'file': vuln['file'],
                'error': str(e)
            })

    return suggestions


if __name__ == '__main__':
    file = 'test.py'
    scan_res = run_static_analysis(file)
    ai_fixes = suggest_fix_engine(scan_res)
    for res in ai_fixes:
        print(res)
