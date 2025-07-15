from fastapi import FastAPI, UploadFile, File
from scanner import run_static_analysis
from AI_fix_Engine import suggest_fix_engine

app = FastAPI()
'''
An endpoint "/scan/" is created to accept the source code. The @scan_code funcion reads the file and saves it locally to
the scans directory. The file is then scanned through the static analyzer extract vulnerabilities followed by AI powered
suggestion for fixes.

The function returns JSON response containing scan_results and AI fixes.

'''


@app.post("/scan/")
async def scan_code(file: UploadFile = File(...)):
    contents = await file.read()
    filepath = f"scans/{file.filename}"

    with open(filepath, 'wb') as f:
        f.write(contents)
        scan_results = run_static_analysis(filepath)
        ai_suggestions = suggest_fix_engine(scan_results)

        return {'vulnerabilities': scan_results, "ai_fixes": ai_suggestions}
