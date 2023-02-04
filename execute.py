import os
import argparse
import shutil
import time
import subprocess
from pathlib import Path
import sys
import json


def contract_in_file(file):
    cmd = ["solc", "--standard-json", "--allow-paths", ".,/"]
    settings = {
        "optimizer": {"enabled": False},
        "outputSelection": {
            "*": {
                "*": ["evm.deployedBytecode"],
            }
        },
    }

    input_json = json.dumps(
        {
            "language": "Solidity",
            "sources": {file: {"urls": [file]}},
            "settings": settings,
        }
    )
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(bytes(input_json, "utf8"))
    out = stdout.decode("UTF-8")
    result = json.loads(out)
    for error in result.get("errors", []):
        if error["severity"] == "error":
            print(error["formattedMessage"])
            sys.exit(1)
    contracts = result["contracts"][file]
    contract_list = []
    for contract in contracts.keys():
        if len(contracts[contract]["evm"]["deployedBytecode"]["object"]):
            contract_list.append(contract)
    return contract_list


parser = argparse.ArgumentParser(description="Run Testing tools")
parser.add_argument("indir", type=str, help="input directory", default=".")
parser.add_argument("outdir", type=str, help="output directory", default=".")
parser.add_argument("-timeout", type=int, default=180,
                    help="set timeout for tools")


parsed = parser.parse_args()

indir = os.path.abspath(parsed.indir)
outdir = os.path.abspath(parsed.outdir)
timeout = parsed.timeout
if os.path.isdir(outdir):
    shutil.rmtree(outdir)


timeout_cmd = ["timeout", "-k", "0.1", str(timeout)]
slither_command = ["slither"]
mythrill_command = ["myth", "analyze"]
conkas_command = ["python3", "conkas", "-s"]
#manticore_command = ["manticore"]

analyzed = []
#contracts = [f for f in os.listdir(indir) if (os.isfile(os.join(indir, f)) and f.endswith('.sol'))]
# new_dir = outdir + '/outputs' + str(len(os.listdir(outdir)))
Path(outdir).mkdir(parents=True, exist_ok=True)

for file in os.listdir(indir):
    if not (os.path.isfile(os.path.join(indir, file)) and file.endswith('.sol')):
        continue
    input_file = os.path.join(indir, file)
    # slither
    try:
        output_file = 'slither_' + file[:-4]
        #slither_cmd = "slither  {0} --json {1}".format(file, os.path.join(new_dir, output_file+'.json'))
        slither_cmd = ['slither', input_file, '--json',
                       os.path.join(outdir, output_file+'.json')]
        start = time.time()

        proc = subprocess.Popen(timeout_cmd + slither_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(subprocess.list2cmdline(proc.args))
        output = proc.communicate()
        proc.wait()

        with open(os.path.join(outdir, output_file+".out"), 'wb+') as f:
            for line in output[0].split(b'\n'):
                f.write(line+b'\n')

        with open(os.path.join(outdir, output_file+".err"), 'wb+') as f:
            for line in output[1].split(b'\n'):
                f.write(line+b'\n')

        elapsed = round(time.time() - start, 2)
        with open(os.path.join(outdir, output_file+".time"), 'wb+') as f:
            f.write(bytes(str(elapsed), 'utf-8'))

    except subprocess.CalledProcessError as e:
        print("slither failed to run ", file)
    # mythril
    try:
        output_file = 'mythril_' + file[:-4]
        #slither_cmd = "myth analyze  {0} -o json > {1}".format(file, os.path.join(new_dir, output_file+'.json'))
        mythril_cmd = ['myth', 'analyze', '-t',
                       '1', '--parallel-solving', input_file]
        output_cmd = ['-o', 'json']
        #              ,os.path.join(outdir, output_file+'.json')]
        start = time.time()

        proc = subprocess.Popen(timeout_cmd + mythril_cmd + output_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(subprocess.list2cmdline(proc.args))
        output = proc.communicate()
        proc.wait()

        with open(os.path.join(outdir, output_file+".json"), 'wb+') as f:
            for line in output[0].split(b'\n'):
                f.write(line+b'\n')

        with open(os.path.join(outdir, output_file+".err"), 'wb+') as f:
            for line in output[1].split(b'\n'):
                f.write(line+b'\n')

        elapsed = round(time.time() - start, 2)
        with open(os.path.join(outdir, output_file+".time"), 'wb+') as f:
            f.write(bytes(str(elapsed), 'utf-8'))

    except subprocess.CalledProcessError as e:
        print("mythril failed to run ", file)
    # conkas
    try:
        output_file = 'conkas_' + file[:-4]
        #slither_cmd = "python3 conkas.py -s {1}".format(   file, os.path.join(new_dir, output_file+'.json'))
        conkas_cmd = ['python3', './conkas/conkas.py', '-s', input_file]
        start = time.time()
        activate_this = './conk/bin/activate_this.py'
        exec(open(activate_this).read(), dict(__file__=activate_this))
        proc = subprocess.Popen(timeout_cmd + conkas_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(subprocess.list2cmdline(proc.args))
        output = proc.communicate()
        proc.wait()

        with open(os.path.join(outdir, output_file+".out"), 'wb+') as f:
            for line in output[0].split(b'\n'):
                f.write(line+b'\n')

        with open(os.path.join(outdir, output_file+".err"), 'wb+') as f:
            for line in output[1].split(b'\n'):
                f.write(line+b'\n')

        elapsed = round(time.time() - start, 2)
        with open(os.path.join(outdir, output_file+".time"), 'wb+') as f:
            f.write(bytes(str(elapsed), 'utf-8'))

    except subprocess.CalledProcessError as e:
        print("conkas failed to run ", file)
    # manticore
    try:
        output_file = 'manticore_' + file[:-4]
        # slither_cmd = "docker run -it -v /home/ali/w/SmartBugsC/dataset/access_control:/share trailofbits/manticore bash -c "manticore share/FibonacciBalance.sol --contract FibonacciBalance --workspace /share/mcore_res".format(file, os.path.join(new_dir, output_file+'.json'))
        manticore_cmd = ['docker', 'run', '-it', '-v', indir+':/share', 'smartbugs/manticore',
                         'bash', '-c', 'manticore share/{} --workspace /share/mcore_res'.format(file)]
        dir_path = os.path.join(outdir, output_file)
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        cp_cmd = ['mv', indir+'/mcore_res', dir_path]
        start = time.time()
        proc = subprocess.Popen(timeout_cmd + manticore_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(subprocess.list2cmdline(proc.args))
        output = proc.communicate()
        proc.wait()
        subprocess.run(cp_cmd)
        with open(os.path.join(outdir, output_file+".out"), 'wb+') as f:
            for line in output[0].split(b'\n'):
                f.write(line+b'\n')

        with open(os.path.join(outdir, output_file+".err"), 'wb+') as f:
            for line in output[1].split(b'\n'):
                f.write(line+b'\n')

        elapsed = round(time.time() - start, 2)
        with open(os.path.join(outdir, output_file+".time"), 'wb+') as f:
            f.write(bytes(str(elapsed), 'utf-8'))

    except subprocess.CalledProcessError as e:
        print("manticore failed to run ", file)
    # ConFuzzius
    try:
        output_file = 'confuzzius_' + file[:-4]
        # slither_cmd = "docker run -it -v /home/ali/w/SmartBugsC/dataset/access_control:/share trailofbits/manticore bash -c "manticore share/FibonacciBalance.sol --contract FibonacciBalance --workspace /share/mcore_res".format(file, os.path.join(new_dir, output_file+'.json'))
        #active_env = ['source', 'fuzz/bin/activate']
        confuzzius_cmd = ['python3', './ConFuzzius/fuzzer/main.py', '-s', input_file, '--solc', 'v0.4.26',
                          '--evm', 'byzantium', '-g', '20', '-r', os.path.join(outdir, output_file+'.json')]
        deactive_env = ['deactivate']
        start = time.time()
        # subprocess.run(active_env)
        activate_this = './fuzz/bin/activate_this.py'
        exec(open(activate_this).read(), dict(__file__=activate_this))
        venv_cmd = ["bash", "-c", "source fuzz/bin/activate", '&&']
        proc = subprocess.Popen(timeout_cmd + confuzzius_cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(subprocess.list2cmdline(proc.args))
        output = proc.communicate()
        proc.wait()
        with open(os.path.join(outdir, output_file+".out"), 'wb+') as f:
            for line in output[0].split(b'\n'):
                f.write(line+b'\n')

        with open(os.path.join(outdir, output_file+".err"), 'wb+') as f:
            for line in output[1].split(b'\n'):
                f.write(line+b'\n')

        elapsed = round(time.time() - start, 2)
        with open(os.path.join(outdir, output_file+".time"), 'wb+') as f:
            f.write(bytes(str(elapsed), 'utf-8'))

    except subprocess.CalledProcessError as e:
        print("confuzzius failed to run ", file)
