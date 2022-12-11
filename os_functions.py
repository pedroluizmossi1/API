import os
from pydantic import BaseModel
import time
from starlette.responses import FileResponse
import shutil

def bytestohuman(n):
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB"  % n

def dateformathuman(date):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(date))

def listalldirectoryfiles(directory):
    files = []
    print(directory)
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        file_size = os.path.getsize(file_path)
        file_size_human = bytestohuman(file_size)
        file_date = os.path.getmtime(file_path)
        file_date_human = dateformathuman(file_date)
        file_type = os.path.splitext(file_path)[1]
        if os.path.isfile(file_path):
            files.append({'file_name': file, 'file_path': file_path, 'file_size': file_size,'file_size_human':file_size_human,  'file_date': file_date,'file_date_human':file_date_human, 'file_type': file_type})
    return files

def downloadfile_from_path(file_path):

    return FileResponse(file_path, media_type='application/octet-stream', filename=os.path.basename(file_path))

def get_os_disk_space():
    total, used, free = shutil.disk_usage("/")
    total = bytestohuman(total)
    used = bytestohuman(used)
    free = bytestohuman(free)
    return total, used, free

def get_os_folder_size(folder):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return bytestohuman(total_size)