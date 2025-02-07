import time

filename = './time.log'
f = open(filename, 'r')
line = f.readline()
result = []
while line:
    line = line.split(': ')
    start_time = line[1].split(';')[0]
    end_time = line[2].strip()
    start = int(time.mktime(time.strptime(start_time, "%Y-%m-%d %H:%M:%S")))
    end = int(time.mktime(time.strptime(end_time, "%Y-%m-%d %H:%M:%S")))
    diff = round((end - start) / 60.0, 2)
    result.append(diff)
    line = f.readline()

print(result)


